// Copyright (C) 2019 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use super::block::*;
use super::*;
use crate::backend::StorageBackend;
use libc::{self, EFD_NONBLOCK};
use log::error;
use nix::sys::uio;
use std::mem;
use std::slice;
//use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use vhost_rs::vhost_user::message::*;
use vhost_rs::vhost_user::{Error as VhostUserError, Result as VhostUserResult};
use vhost_user_backend::{VhostUserBackend, Vring, VringWorker};
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = 0;
// The device has been dropped.
pub const KILL_EVENT: u16 = 1;

pub fn build_device_id(image: &File) -> Result<String> {
    let blk_metadata = image.metadata()?;
    // This is how kvmtool does it.
    let device_id = format!(
        "{}{}{}",
        blk_metadata.st_dev(),
        blk_metadata.st_rdev(),
        blk_metadata.st_ino()
    )
    .to_owned();
    Ok(device_id)
}

pub struct StorageBackendRaw {
    image: File,
    image_id: Vec<u8>,
    mem: Option<GuestMemoryMmap>,
    position: u64,
    config: virtio_blk_config,
    vring_worker: Option<Arc<VringWorker>>,
    num_queues: u16,
    poll_ns: u128,
    kill_evt: EventFd,
}

impl StorageBackendRaw {
    pub fn new(
        image_path: &str,
        rdonly: bool,
        num_queues: u16,
        poll_ns: u128,
        flags: i32,
    ) -> Result<StorageBackendRaw> {
        let mut options = OpenOptions::new();
        options.read(true);
        if !rdonly {
            options.write(true);
        }
        if flags != 0 {
            options.custom_flags(flags);
        }
        let mut image = options.open(image_path)?;

        let mut config = virtio_blk_config::default();
        config.capacity = (image.seek(SeekFrom::End(0)).unwrap() as u64) / SECTOR_SIZE;
        config.blk_size = BLK_SIZE;
        config.size_max = 65535;
        config.seg_max = 128 - 2;
        config.min_io_size = 1;
        config.opt_io_size = 1;
        config.num_queues = 1;

        let image_id_str = build_device_id(&image)?;
        let image_id_bytes = image_id_str.as_bytes();
        let mut image_id_len = image_id_bytes.len();
        if image_id_len > VIRTIO_BLK_ID_BYTES as usize {
            image_id_len = VIRTIO_BLK_ID_BYTES as usize;
        }
        let mut image_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        image_id[..image_id_len].copy_from_slice(&image_id_bytes[..image_id_len]);

        Ok(StorageBackendRaw {
            image,
            image_id,
            mem: None,
            position: 0u64,
            config,
            vring_worker: None,
            num_queues,
            poll_ns,
            kill_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
        })
    }
}

impl Read for StorageBackendRaw {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        uio::pread(self.image.as_raw_fd(), buf, self.position as i64)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }
}

impl Seek for StorageBackendRaw {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Start(offset) => self.position = offset as u64,
            SeekFrom::Current(offset) => self.position += offset as u64,
            SeekFrom::End(offset) => {
                self.position = (self.config.capacity << SECTOR_SHIFT) + (offset as u64)
            }
        }
        Ok(self.position)
    }
}

impl Write for StorageBackendRaw {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        uio::pwrite(self.image.as_raw_fd(), buf, self.position as i64)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    fn flush(&mut self) -> Result<()> {
        self.image.flush()
    }
}

impl Clone for StorageBackendRaw {
    fn clone(&self) -> Self {
        StorageBackendRaw {
            image: self.image.try_clone().unwrap(),
            image_id: self.image_id.clone(),
            mem: self.mem.clone(),
            position: self.position,
            config: self.config.clone(),
            vring_worker: self.vring_worker.clone(),
            num_queues: self.num_queues.clone(),
            poll_ns: self.poll_ns.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
        }
    }
}

impl StorageBackend for StorageBackendRaw {
    fn get_sectors(&self) -> u64 {
        self.config.capacity
    }

    fn get_image_id(&self) -> &Vec<u8> {
        &self.image_id
    }

    fn is_async(&self) -> bool {
        false
    }

    fn submit_requests(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_completion(&mut self, _wait: bool) -> Result<Option<usize>> {
        Ok(None)
    }

    fn check_sector_offset(&self, sector: u64, len: u64) -> Result<()> {
        let mut top = len / SECTOR_SIZE;
        if len % SECTOR_SIZE != 0 {
            top += 1;
        }

        top = top.checked_add(sector).unwrap();
        if top > self.config.capacity {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "offset beyond image end",
            ))
        } else {
            Ok(())
        }
    }

    fn seek_sector(&mut self, sector: u64) -> Result<u64> {
        if sector >= self.config.capacity {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "sector beyond image end",
            ));
        }

        self.seek(SeekFrom::Start(sector << SECTOR_SHIFT))
    }

    fn poll_queues(&mut self, vring: &mut Vring) {
        //disable_notifications(self, vring);
        let mut start_time = Instant::now();
        let poll_ns = self.poll_ns;
        loop {
            if process_queue(self, vring).unwrap() {
                start_time = Instant::now();
            }

            if poll_ns == 0 || Instant::now().duration_since(start_time).as_nanos() > poll_ns {
                //enable_notifications(self, vring);
                process_queue(self, vring).unwrap();
                break;
            }
        }
    }

    fn get_mem(&self) -> Option<GuestMemoryMmap> {
        self.mem.clone()
    }
}

impl VhostUserBackend for StorageBackendRaw {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE as usize
    }

    fn features(&self) -> u64 {
        let avail_features = 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_SIZE_MAX
            | 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        avail_features
    }

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            println!("Invalid events operation!\n");
            return Ok(false);
        }
        match device_event {
            QUEUE_AVAIL_EVENT => {
                let mut vring = vrings[0].write().unwrap();
                self.poll_queues(&mut vring);
                if let Err(e) = vring.signal_used_queue() {
                    error!("Failed to signal used queue: {:?}", e);
                }
            }
            KILL_EVENT => {
                self.kill_evt.read().unwrap();
                println!("KILL_EVENT received, stopping epoll loop");
                return Ok(true);
            }
            _ => {
                println!("Unknown event for vhost-user-blk-backend");
            }
        }
        Ok(false)
    }
    fn get_config(&self, _offset: u32, size: u32) -> VhostUserResult<Vec<u8>> {
        if size != mem::size_of::<virtio_blk_config>() as u32 {
            return Err(VhostUserError::InvalidParam);
        }

        let config: virtio_blk_config = self.config;

        let buf = unsafe {
            slice::from_raw_parts(
                &config as *const virtio_blk_config as *const _,
                mem::size_of::<virtio_blk_config>(),
            )
        };

        Ok(buf.to_vec())
    }

    fn set_config(&mut self, offset: u32, data: &[u8]) -> VhostUserResult<()> {
        let data_len = data.len() as u32;
        let config_len = mem::size_of::<virtio_blk_config>() as u32;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return Err(VhostUserError::InvalidParam);
        }
        self.config.wce = data[0];
        Ok(())
    }
}
