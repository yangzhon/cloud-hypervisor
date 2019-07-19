// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread;
use std::vec::Vec;

use crate::VirtioInterrupt;

use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use super::handler::VhostUserEpollHandler;
use super::{Error, Result};
use vhost_rs::vhost_user::Master;
use vhost_rs::vhost_user::VhostUserMaster;
use vhost_rs::vhost_user::message::VhostUserConfigFlags;
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use virtio_bindings::virtio_blk;
use std::mem;

pub const VIRTIO_F_VERSION_1_BITMASK: u64 = 1 << VIRTIO_F_VERSION_1;
pub const VIRTIO_F_VERSION_1: ::std::os::raw::c_uint = 32;

macro_rules! offset_of {
    ($ty:ty, $field:ident) => {
        unsafe { &(*(0 as *const $ty)).$field as *const _ as usize }
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct virtio_blk_config {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    cylinders: u16,
    heads: u8,
    sectors: u8,
    blk_size: u32,
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
    wce: u8,
    unused0: [u8; 1],
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    unused1: [u8; 3],
}

pub struct Blk {
    vhost_user_blk: Master,
    kill_evt: EventFd,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    queue_sizes: Vec<u16>,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(path: &str, num_queues: usize, queue_size: u16, config_wce: u8) -> Result<Blk> {
        // Connect to the vhost-user socket.
        let mut vhost_user_blk =
            Master::connect(path, num_queues as u64).map_err(Error::VhostUserCreateMaster)?;

        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?;
        // Retrieve available features only when connecting the first time.
        let mut avail_features = vhost_user_blk.get_features().map_err(Error::VhostUserGetFeatures)?;
        // Let only ack features we expect, that is VIRTIO_F_VERSION_1.
        if (avail_features & VIRTIO_F_VERSION_1_BITMASK) != VIRTIO_F_VERSION_1_BITMASK {
            return Err(Error::InvalidFeatures);
        }
        avail_features =
            VIRTIO_F_VERSION_1_BITMASK | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        vhost_user_blk
            .set_features(avail_features)
            .map_err(Error::VhostUserSetFeatures)?;
        // Identify if protocol features are supported by the slave.
        if (avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits())
            == VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        {
            let mut protocol_features = vhost_user_blk
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            protocol_features |= VhostUserProtocolFeatures::MQ;
            vhost_user_blk
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
        }

        vhost_user_blk
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        let config_len = mem::size_of::<virtio_blk_config>();
        let mut config_space = Vec::with_capacity(config_len as usize);
        config_space.resize(config_len as usize, 0);

        let offset = offset_of!(virtio_blk_config, wce);
        // only set wce value.
        config_space[offset] = config_wce;

        let queue_num_offset = offset_of!(virtio_blk_config, num_queues);
        // only setnum_queues value.
        config_space[queue_num_offset] = num_queues as u8;

        Ok(Blk {
            vhost_user_blk: vhost_user_blk,
            kill_evt,
            avail_features,
            acked_features: 0u64,
            config_space,
            queue_sizes: vec![queue_size; num_queues],
        })
    }

    pub fn setup_vub(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[Queue],
        queue_evts: Vec<EventFd>,
    ) -> Result<Vec<EventFd>> {
         // Set backend features.
        self.vhost_user_blk
            .set_features(self.acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        mem.with_regions_mut(|_, region| {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => return Err(MmapError::NoMemoryRegion),
            };

            let vhost_user_blk_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len() as u64,
                userspace_addr: region.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };

            regions.push(vhost_user_blk_reg);

            Ok(())
        })
        .map_err(Error::VhostUserMemoryRegion)?;

        self.vhost_user_blk
            .set_mem_table(regions.as_slice())
            .map_err(Error::VhostUserSetMemTable)?;

        let mut vub_interrupt_list = Vec::new();

        for (queue_index, ref queue) in queues.iter().enumerate() {
            self.vhost_user_blk
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

            self.vhost_user_blk
                .set_vring_base(queue_index, 0)
                .map_err(Error::VhostUserSetVringBase)?;
            self.vhost_user_blk
                .set_vring_addr(queue_index, &config_data)
                .map_err(Error::VhostUserSetVringAddr)?;

            self.vhost_user_blk
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostUserSetVringKick)?;

            let vhost_user_interrupt = EventFd::new(EFD_NONBLOCK).map_err(Error::VhostIrqCreate)?;
            self.vhost_user_blk
                .set_vring_call(queue_index, &vhost_user_interrupt)
                .map_err(Error::VhostUserSetVringCall)?;
            vub_interrupt_list.push(vhost_user_interrupt);

        }
        Ok(vub_interrupt_list)
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        if let Err(_e) = self.kill_evt.write(1) {
            error!("failed to kill vhost-user-blk with error {}", _e);
        }
    }
}

impl VirtioDevice for Blk {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_BLOCK as u32
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

    fn read_config(&mut self, offset: u64, mut data: &mut [u8]) {
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
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        println!("Entering vhost-user blk activate ......!");
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_sizes.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let vub_interrupt_list = self
            .setup_vub(&mem, &queues, queue_evts)
            .map_err(ActivateError::VhostUserBlkSetup)?;

        let handler_kill_evt = self
            .kill_evt
            .try_clone()
            .map_err(|_| ActivateError::CloneKillEventFd)?;

        let _handler_result = thread::Builder::new()
            .name("vhost_user_blk".to_string())
            .spawn(move || {
                let mut handler = VhostUserEpollHandler::new(
                    interrupt_cb,
                    handler_kill_evt,
                    queues,
                    vub_interrupt_list,
                    None,
                    mem,
                );
                let result = handler.run();
                if let Err(_e) = result {
                    println!("blk worker thread exited with error {:?}!", _e);
                }
            });
        if let Err(_e) = _handler_result {
            println!("vhost-user blk thread create failed with error {:?}", _e);
        }
        Ok(())
    }
}
