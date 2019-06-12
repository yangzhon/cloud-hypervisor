// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread;
use std::vec::Vec;

use crate::VirtioInterrupt;
use net_util::{MacAddr, MAC_ADDR_LEN};

use vm_memory::address::Address;
use vm_memory::guest_memory::{GuestMemory, GuestMemoryRegion};
use vm_memory::mmap::{GuestMemoryMmap, MmapError};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use super::handler::VhostUserEpollHandler;
use super::{Error, Result};
use vhost_rs::vhost_user::Master;
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use virtio_bindings::virtio_net;

pub const VIRTIO_RING_F_INDIRECT_DESC: ::std::os::raw::c_uint = 28;
pub const VIRTIO_RING_F_EVENT_IDX: ::std::os::raw::c_uint = 29;
pub const VIRTIO_F_NOTIFY_ON_EMPTY: ::std::os::raw::c_uint = 24;
pub const VIRTIO_F_VERSION_1: ::std::os::raw::c_uint = 32;

pub struct Net {
    vhost_user_net: Master,
    kill_evt: EventFd,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    queue_sizes: Vec<u16>,
}

impl Net {
    /// Create a new vhost-user-net device
    pub fn new(mac_addr: MacAddr, path: &str, num_queues: usize, queue_size: u16) -> Result<Net> {
        let vhost_user_net =
            Master::connect(path, num_queues as u64).map_err(Error::VhostUserCreateMaster)?;

        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?;

        let mut avail_features = 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space = Vec::with_capacity(MAC_ADDR_LEN);
        unsafe { config_space.set_len(MAC_ADDR_LEN) }
        config_space[..].copy_from_slice(mac_addr.get_bytes());
        avail_features |= 1 << virtio_net::VIRTIO_NET_F_MAC;

        Ok(Net {
            vhost_user_net: vhost_user_net,
            kill_evt,
            avail_features,
            acked_features: 0u64,
            config_space,
            queue_sizes: vec![queue_size; num_queues],
        })
    }

    pub fn setup_vunet(
        &mut self,
        mem: GuestMemoryMmap,
        queues: &Vec<Queue>,
        queue_evts: Vec<EventFd>,
        vhost_user_interrupt: &EventFd,
    ) -> Result<()> {
        // Preliminary setup for vhost net.
        self.vhost_user_net
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        self.vhost_user_net
            .set_features(self.acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();

        mem.with_regions_mut(|_, region| {
            let mmap_offset = match region.fd_offset() {
                Some(offset) => offset as u64,
                None => 0u64,
            };

            let mmap_handle = match region.fd() {
                Some(fd) => fd,
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

        for (queue_index, ref queue) in queues.iter().enumerate() {
            self.vhost_user_net
                .set_vring_num(queue_index, queue.get_max_size())
                .map_err(Error::VhostUserSetVringNum)?;

            let config_data = VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                flags: 0u32,
                desc_table_addr: queue.desc_table.raw_value() as u64,
                used_ring_addr: queue.used_ring.raw_value() as u64,
                avail_ring_addr: queue.avail_ring.raw_value() as u64,
                log_addr: None,
            };

            self.vhost_user_net
                .set_vring_addr(queue_index, &config_data)
                .map_err(Error::VhostUserSetVringAddr)?;
            self.vhost_user_net
                .set_vring_base(queue_index, 0)
                .map_err(Error::VhostUserSetVringBase)?;
            self.vhost_user_net
                .set_vring_call(queue_index, &vhost_user_interrupt)
                .map_err(Error::VhostUserSetVringCall)?;
            self.vhost_user_net
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostUserSetVringKick)?;
        }

        Ok(())
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.kill_evt.write(1);
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
        interrupt_status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_sizes.len(),
                queues.len()
            );
            return Err(ActivateError::BadQueueNum);
        }

        let vhost_user_interrupt =
            EventFd::new(EFD_NONBLOCK).map_err(|_| ActivateError::VhostIrqCreate)?;
        self.setup_vunet(mem, &queues, queue_evts, & vhost_user_interrupt);

        let handler_kill_evt = self
            .kill_evt
            .try_clone()
            .map_err(|_| ActivateError::CloneKillEventFd)?;

        let _handler_result = thread::Builder::new()
            .name("vhost_user_net".to_string())
            .spawn(move || {
                let mut handler = VhostUserEpollHandler::new(
                    vhost_user_interrupt,
                    interrupt_status,
                    interrupt_cb,
                    handler_kill_evt,
                    queues,
                );
                let result = handler.run();
                if let Err(_e) = result {
                    println!("net worker thread exited with error {:?}!", _e);
                }
            });
        if let Err(_e) = _handler_result {
            println!("vhost-user net thread create failed with error {:?}", _e);
        }
        return Ok(());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use net_util::fakes::FakeTap;
    use std::result;
    use sys_util::{GuestAddress, GuestMemory, GuestMemoryError};
    use vhost::net::fakes::FakeNet;

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x100);
        GuestMemory::new(&vec![(start_addr1, 0x100), (start_addr2, 0x400)])
    }

    fn create_net_common() -> Net<FakeTap, FakeNet<FakeTap>> {
        let guest_memory = create_guest_memory().unwrap();
        Net::<FakeTap, FakeNet<FakeTap>>::new(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "de:21:e8:47:6b:6a".parse().unwrap(),
            &guest_memory,
        )
        .unwrap()
    }

    #[test]
    fn create_net() {
        create_net_common();
    }

    #[test]
    fn keep_fds() {
        let net = create_net_common();
        let fds = net.keep_fds();
        assert!(fds.len() >= 1, "We should have gotten at least one fd");
    }

    #[test]
    fn features() {
        let net = create_net_common();
        assert_eq!(net.features(), 5117103235);
    }

    #[test]
    fn ack_features() {
        let mut net = create_net_common();
        // Just testing that we don't panic, for now
        net.ack_features(1);
        net.ack_features(1 << 32);
    }

    #[test]
    fn activate() {
        let mut net = create_net_common();
        let guest_memory = create_guest_memory().unwrap();
        // Just testing that we don't panic, for now
        net.activate(
            guest_memory,
            EventFd::new().unwrap(),
            EventFd::new().unwrap(),
            Arc::new(AtomicUsize::new(0)),
            vec![Queue::new(1)],
            vec![EventFd::new().unwrap()],
        );
    }
}
