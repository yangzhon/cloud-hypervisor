// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::vec::Vec;

use crate::VirtioInterrupt;
use net_util::{MacAddr, MAC_ADDR_LEN};

use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use super::handler::VhostUserEpollHandler;
use super::{Error, Result};
use super::{VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN};
use vhost_rs::vhost_user::{Listener, Master, VhostUserMaster};
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use virtio_bindings::virtio_net;

const VIRTIO_F_EVENT_IDX: ::std::os::raw::c_uint = 29;
const VIRTIO_F_NOTIFY_ON_EMPTY: ::std::os::raw::c_uint = 24;
const VIRTIO_F_VERSION_1: ::std::os::raw::c_uint = 32;
const VHOST_USER_F_PROTOCOL_FEATURES: ::std::os::raw::c_uint = 30;

const CONFIG_SPACE_MAC: usize = MAC_ADDR_LEN;
const CONFIG_SPACE_STATUS: usize = 2;
const CONFIG_SPACE_QUEUE_PAIRS: usize = 2;
const CONFIG_SPACE_VUNET: usize = CONFIG_SPACE_MAC + CONFIG_SPACE_STATUS + CONFIG_SPACE_QUEUE_PAIRS;

pub struct CtlVirtqueue {
    pub queue_evt: EventFd,
    pub queue: Queue,
}

impl CtlVirtqueue {
    fn new(queue: Queue, queue_evt: EventFd) -> Self {
        CtlVirtqueue { queue_evt, queue }
    }
}

pub struct Net {
    vhost_user_net: Master,
    kill_evt: EventFd,
    avail_features: u64,
    acked_features: u64,
    backend_features: u64,
    config_space: Vec<u8>,
    queue_sizes: Vec<u16>,
}

impl Net {
    /// Create a new vhost-user-net device
    pub fn new(
        mac_addr: MacAddr,
        path: &str,
        num_queue_pairs: usize,
        queue_size: u16,
        server: u8,
    ) -> Result<Net> {
        let num_queues = 2 * num_queue_pairs;

        let mut vhost_user_net = if server == 0 {
            Master::connect(path, num_queues as u64).map_err(Error::VhostUserCreateMaster)?
        } else {
            let listener = Listener::new(path, true).unwrap();
            let sock = listener.accept().map_err(Error::VhostUserSocket)?.unwrap();
            Master::from_stream(sock, num_queues as u64)
        };

        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO6
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_ECN
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO6
            | 1 << virtio_net::VIRTIO_NET_F_HOST_ECN
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_EVENT_IDX;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = vhost_user_net.get_features().unwrap();
        avail_features &= backend_features;
        // To set features back is decided by the vhost crate mechanism, since the
        // later vhost call requires backend_features filled in master,
        // which is setup by the call here. Will check if the corresponding logic
        // in vhost is sensible in the future.
        vhost_user_net
            .set_features(backend_features)
            .map_err(Error::VhostUserSetFeatures)?;

        // Enable the following features here which are not need to be negotiated with
        // vhost-user backends.
        avail_features |= 1 << virtio_net::VIRTIO_NET_F_MAC
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | 1 << virtio_net::VIRTIO_NET_F_MQ;

        // Fill config space which has mac_addr, status and MQ info currently.
        let mut config_space = mac_addr.get_bytes().to_vec();
        if num_queue_pairs as u16 >= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN
            && num_queue_pairs as u16 <= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX
        {
            config_space.resize(CONFIG_SPACE_VUNET, 0);
            let max_queue_pairs = (num_queue_pairs as u16).to_le_bytes();
            config_space[CONFIG_SPACE_MAC + CONFIG_SPACE_STATUS..CONFIG_SPACE_VUNET]
                .copy_from_slice(&max_queue_pairs);
        }

        let mut acked_features = 0;
        let max_queue_number = if backend_features & (1 << VHOST_USER_F_PROTOCOL_FEATURES) != 0 {
            acked_features |= 1 << VHOST_USER_F_PROTOCOL_FEATURES;
            let protocol_features = vhost_user_net.get_protocol_features().unwrap();
            vhost_user_net
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
            match vhost_user_net.get_queue_num() {
                Ok(qn) => qn,
                Err(_) => num_queues as u64,
            }
        } else {
            num_queues as u64
        };
        if num_queues > max_queue_number as usize {
            error!("vhost-user-net has queue number: {} larger than the max queue number: {} backend allowed\n",
                num_queues, max_queue_number);
            return Err(Error::BadQueueNum);
        }

        vhost_user_net
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        // Send set_vring_base here, since it could tell backends, like OVS + DPDK,
        // how many virt queues to be handled, which backend required to know at early stage.
        for i in 0..num_queues {
            vhost_user_net
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        let queue_num = if (avail_features & (1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) != 0)
            && (avail_features & (1 << virtio_net::VIRTIO_NET_F_MQ) != 0)
        {
            1 + num_queues
        } else {
            num_queues
        };

        Ok(Net {
            vhost_user_net,
            kill_evt,
            avail_features,
            acked_features,
            backend_features,
            config_space,
            queue_sizes: vec![queue_size; queue_num],
        })
    }

    pub fn setup_vunet(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[Queue],
        queue_evts: Vec<EventFd>,
    ) -> Result<Vec<EventFd>> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        mem.with_regions_mut(|_, region| {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => return Err(MmapError::NoMemoryRegion),
            };

            let vhost_user_net_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len() as u64,
                userspace_addr: region.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };

            regions.push(vhost_user_net_reg);

            Ok(())
        })
        .map_err(Error::VhostUserMemoryRegion)?;

        self.vhost_user_net
            .set_mem_table(regions.as_slice())
            .map_err(Error::VhostUserSetMemTable)?;

        self.vhost_user_net
            .set_features(self.acked_features & self.backend_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let mut vu_interrupt_list = Vec::new();

        for (queue_index, ref queue) in queues.iter().enumerate() {
            self.vhost_user_net
                .set_vring_num(queue_index, queue.get_max_size())
                .map_err(Error::VhostUserSetVringNum)?;

            let config_data = VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table)
                    .ok_or_else(|| Error::DescriptorTableAddress)?
                    as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring)
                    .ok_or_else(|| Error::UsedAddress)? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring)
                    .ok_or_else(|| Error::AvailAddress)? as u64,
                log_addr: None,
            };

            self.vhost_user_net
                .set_vring_addr(queue_index, &config_data)
                .map_err(Error::VhostUserSetVringAddr)?;
            self.vhost_user_net
                .set_vring_base(queue_index, 0)
                .map_err(Error::VhostUserSetVringBase)?;

            let vhost_user_interrupt = EventFd::new(EFD_NONBLOCK).map_err(Error::VhostIrqCreate)?;
            self.vhost_user_net
                .set_vring_call(queue_index, &vhost_user_interrupt)
                .map_err(Error::VhostUserSetVringCall)?;
            vu_interrupt_list.push(vhost_user_interrupt);

            self.vhost_user_net
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostUserSetVringKick)?;
        }

        Ok(vu_interrupt_list)
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Err(_e) = self.kill_evt.write(1) {
            error!("failed to kill vhost-user-net with error {}", _e);
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_NET as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt_cb: Arc<VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        let handler_kill_evt = self
            .kill_evt
            .try_clone()
            .map_err(|_| ActivateError::CloneKillEventFd)?;

        let cvq = if (self.acked_features & 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) != 0
            && (self.acked_features & 1 << virtio_net::VIRTIO_NET_F_MQ) != 0
        {
            let cvq_index = queues.len() - 1;
            let cvq_queue = queues.remove(cvq_index);
            let cvq_queue_evt = queue_evts.remove(cvq_index);
            Some(CtlVirtqueue::new(cvq_queue, cvq_queue_evt))
        } else {
            None
        };

        for i in 0..queues.len() {
            self.vhost_user_net
                .set_vring_enable(i, true)
                .map_err(ActivateError::VhostUserSetVringEnable)?;
        }

        let vu_interrupt_list = self
            .setup_vunet(&mem, &queues, queue_evts)
            .map_err(ActivateError::VhostUserNetSetup)?;

        let _handler_result = thread::Builder::new()
            .name("vhost_user_net".to_string())
            .spawn(move || {
                let mut handler = VhostUserEpollHandler::new(
                    interrupt_cb,
                    handler_kill_evt,
                    queues,
                    vu_interrupt_list,
                    cvq,
                    mem,
                );
                let result = handler.run();
                if let Err(_e) = result {
                    println!("net worker thread exited with error {:?}!", _e);
                }
            });
        if let Err(_e) = _handler_result {
            println!("vhost-user net thread create failed with error {:?}", _e);
        }
        Ok(())
    }
}
