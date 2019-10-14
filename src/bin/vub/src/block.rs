// Copyright (C) 2019 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::mem;
use std::os::unix::io::{FromRawFd, RawFd};
use std::result;
use std::slice;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use super::backend::StorageBackend;
use super::message::*;
use bitflags::bitflags;
use log::{debug, error};
use virtio_bindings::bindings::virtio_blk::*;
//use virtio_bindings::bindings::virtio_ring::VRING_USED_F_NO_NOTIFY;
use vm_memory::{
    Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MmapRegion,
};

use vhost_rs::message::*;
use vhost_rs::{Error, Result, VhostUserSlave};

bitflags! {
    pub struct VhostUserBlkFeatures: u64 {
        const MQ = 0x1000;
        const EVENT_IDX = 0x20000000;
        const PROTOCOL_FEATURES = 0x40000000;
    }
}

#[derive(Debug)]
enum ExecuteError {
    BadRequest(Error),
    Flush(io::Error),
    Read(GuestMemoryError),
    Seek(io::Error),
    Write(GuestMemoryError),
    Unsupported(u32),
}

impl ExecuteError {
    fn status(&self) -> u32 {
        match *self {
            ExecuteError::BadRequest(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}

fn request_type(
    mem: &GuestMemoryMmap,
    desc_addr: GuestAddress,
) -> result::Result<RequestType, Error> {
    let (region, addr) = mem.to_region_addr(desc_addr).unwrap();
    let type_ = region.read_obj(addr).unwrap();
    match type_ {
        VIRTIO_BLK_T_IN => {
            debug!("VIRTIO_BLK_T_IN");
            Ok(RequestType::In)
        }
        VIRTIO_BLK_T_OUT => {
            debug!("VIRTIO_BLK_T_OUT");
            Ok(RequestType::Out)
        }
        VIRTIO_BLK_T_FLUSH => {
            debug!("VIRTIO_BLK_T_FLUSH");
            Ok(RequestType::Flush)
        }
        VIRTIO_BLK_T_GET_ID => {
            debug!("VIRTIO_BLK_T_GET_ID");
            Ok(RequestType::GetDeviceID)
        }
        t => {
            debug!("unsupported request: {}", t);
            Ok(RequestType::Unsupported(t))
        }
    }
}

fn sector(mem: &GuestMemoryMmap, desc_addr: GuestAddress) -> result::Result<u64, Error> {
    const SECTOR_OFFSET: usize = 8;
    let (region, addr) = mem.to_region_addr(desc_addr).unwrap();
    let addr = region.checked_offset(addr, SECTOR_OFFSET).unwrap();
    Ok(region.read_obj(addr).unwrap())
}

enum ExecuteType {
    Sync(usize),
    Async(usize),
}

struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
    desc_index: u16,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        if avail_desc.is_write_only() {
            error!("unexpected write only descriptor");
            return Err(Error::OperationFailedInSlave);
        }

        let mut req = Request {
            request_type: request_type(&mem, avail_desc.addr)?,
            sector: sector(&mem, avail_desc.addr)?,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
            desc_index: avail_desc.index,
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc.next_descriptor().unwrap();

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                error!("request without data descriptor!");
                return Err(Error::OperationFailedInSlave);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc.next_descriptor().unwrap();

            if data_desc.is_write_only() && req.request_type == RequestType::Out {
                error!("unexpected write only descriptor");
                return Err(Error::OperationFailedInSlave);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::In {
                error!("unexpected read only descriptor");
                return Err(Error::OperationFailedInSlave);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                error!("unexpected read only descriptor");
                return Err(Error::OperationFailedInSlave);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            error!("unexpected read only descriptor");
            return Err(Error::OperationFailedInSlave);
        }

        if status_desc.len < 1 {
            error!("descriptor length is too small");
            return Err(Error::OperationFailedInSlave);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    #[allow(clippy::ptr_arg)]
    fn execute<T: StorageBackend>(
        &self,
        disk: &mut T,
        mem: &GuestMemoryMmap,
    ) -> result::Result<ExecuteType, ExecuteError> {
        disk.check_sector_offset(self.sector, self.data_len.into())
            .map_err(|err| {
                debug!("check_sector_offset {:?}", err);
                ExecuteError::BadRequest(Error::InvalidParam)
            })?;
        disk.seek_sector(self.sector).map_err(|err| {
            debug!("seek_sector {:?}", err);
            ExecuteError::Seek(err)
        })?;

        let (region, addr) = mem.to_region_addr(self.data_addr).unwrap();

        match self.request_type {
            RequestType::In => {
                debug!(
                    "reading {} bytes starting at sector {}",
                    self.data_len, self.sector
                );
                match region.read_from(addr, disk, self.data_len as usize) {
                    Ok(l) => {
                        if disk.is_async() {
                            Ok(ExecuteType::Async(l))
                        } else {
                            Ok(ExecuteType::Sync(l))
                        }
                    }
                    Err(err) => {
                        error!("error reading from disk: {:?}", err);
                        Err(ExecuteError::Read(err))
                    }
                }
            }
            RequestType::Out => {
                debug!(
                    "writing out {} bytes starting on sector {}",
                    self.data_len, self.sector
                );
                match region.write_to(addr, disk, self.data_len as usize) {
                    Ok(l) => {
                        if disk.is_async() {
                            Ok(ExecuteType::Async(l))
                        } else {
                            Ok(ExecuteType::Sync(l))
                        }
                    }
                    Err(err) => {
                        error!("error writing to disk: {:?}", err);
                        Err(ExecuteError::Write(err))
                    }
                }
            }
            RequestType::Flush => {
                debug!("requesting backend to flush out disk buffers");
                match disk.flush() {
                    Ok(_) => Ok(ExecuteType::Sync(0)),
                    Err(err) => {
                        error!("error flushing out buffers: {:?}", err);
                        Err(ExecuteError::Flush(err))
                    }
                }
            }
            RequestType::GetDeviceID => {
                debug!("providing device ID data");
                let image_id = disk.get_image_id();
                if (self.data_len as usize) < image_id.len() {
                    error!("data len smaller than disk_id");
                    return Err(ExecuteError::BadRequest(Error::InvalidParam));
                }
                match region.write_slice(image_id, addr) {
                    Ok(_) => Ok(ExecuteType::Sync(image_id.len())),
                    Err(err) => {
                        error!("error writing device ID to vring address: {:?}", err);
                        Err(ExecuteError::Write(err))
                    }
                }
            }
            RequestType::Unsupported(t) => {
                error!("unsupported request");
                Err(ExecuteError::Unsupported(t))
            }
        }
    }
}

pub struct VhostUserBlk<S: StorageBackend> {
    backend: S,
    mem: Option<GuestMemoryMmap>,
    memory_regions: Vec<VhostUserMemoryRegion>,
    num_queues: u16,
    vrings: HashMap<usize, Arc<Mutex<Vring>>>,
    vring_default_enabled: bool,
    owned: bool,
    queue: Queue,
    async_requests: HashMap<usize, Request>,
}

impl<S: StorageBackend> VhostUserBlk<S> {
    pub fn new(
        backend: S,
        num_queues: u16,
    ) -> Self {
        VhostUserBlk {
            backend,
            mem: None,
            memory_regions: vec![],
            num_queues,
            vrings: HashMap::new(),
            vring_default_enabled: false,
            owned: false,
        }
    }

    pub fn process_completions<S>(&mut self, backend: &mut S) -> Result<bool>
    where
        S: StorageBackend,
    {
        let mut count = 0;

        while !self.async_requests.is_empty() {
            if let Some(cookie) = backend
                .get_completion(false)
                .map_err(|_err| Error::OperationFailedInSlave)?
            {
                let request = self.async_requests.remove(&cookie).unwrap();

                debug!(
                    "got completion with cookie: {}, desc={}",
                    cookie, request.desc_index
                );

                let (region, addr) = self.mem.to_region_addr(request.status_addr).unwrap();
                region.write_obj(VIRTIO_BLK_S_OK, addr).unwrap();

                let used_idx = self
                    .queue
                    .add_used(&self.mem, request.desc_index, request.data_len);

                count += 1;
            } else {
                // No completions avaiable, don't waste more time looking for them.
                break;
            }
        }

        Ok(count != 0)
    }

    pub fn process_queue<S: StorageBackend>(&mut self, backend: &mut S) -> Result<bool> {
        let mut used_desc_heads = [(0, 0); 1024 as usize];
        let mut used_count = 0;
        for avail_desc in self.queue.iter(&self.mem) {
            debug!("got an element in the queue");
            match Request::parse(&avail_desc, &self.mem) {
                Ok(request) => {
                    debug!("element is a valid request");
                    let mut len = 0;
                    match request.execute(backend, &self.mem) {
                        Ok(type_) => match type_ {
                            ExecuteType::Sync(l) => {
                                debug!("executing synchronously: desc={}", request.desc_index);
                                len = l;
                                let (region, addr) =
                                    self.mem.to_region_addr(request.status_addr).unwrap();
                                region.write_obj(VIRTIO_BLK_S_OK, addr).unwrap();
                            }
                            ExecuteType::Async(cookie) => {
                                debug!("executing asynchronously: desc={}", request.desc_index);
                                self.async_requests.insert(cookie, request);
                            }
                        },
                        Err(err) => {
                            error!("failed to execute request: {:?}", err);
                            len = 1; // We need at least 1 byte for the status.
                            let (region, addr) =
                                self.mem.to_region_addr(request.status_addr).unwrap();
                            region.write_obj(err.status(), addr).unwrap();
                        }
                    };
                    if len != 0 {
                        used_desc_heads[used_count] = (avail_desc.index, len);
                        used_count += 1;
                    }
                }
                Err(err) => {
                    error!("failed to parse available descriptor chain: {:?}", err);
                    used_desc_heads[used_count] = (avail_desc.index, 0);
                    used_count += 1;
                }
            }
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            let used_idx = self.queue.add_used(&self.mem, desc_index, len as u32);
            if self.should_signal_guest(used_idx) {
                self.signal_guest().unwrap();
            } else {
                debug!("omitting guest signal");
            }
        }

        if backend.is_async() {
            backend.submit_requests().unwrap();
        }

        Ok(used_count > 0)
    }

    pub fn disable_notifications(&self) {
        if self.features & VhostUserBlkFeatures::EVENT_IDX.bits() != 0 {
            self.queue
                .set_avail_event(&self.mem, self.queue.get_last_avail());
        } else {
            // TODO
            //self.queue.set_used_flags_bit(VRING_USED_F_NO_NOTIFY);
        }
    }

    pub fn enable_notifications(&self) {
        if self.features & VhostUserBlkFeatures::EVENT_IDX.bits() != 0 {
            self.queue
                .set_avail_event(&self.mem, self.queue.get_last_avail());
        } else {
            // TODO
            //self.queue.unset_used_flags_bit(VRING_USED_F_NO_NOTIFY);
        }
    }

}
