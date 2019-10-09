// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
#[macro_use(crate_version, crate_authors)]
extern crate clap;

use epoll;
use std::cmp;
use std::fs::File;
//use std::fs::OpenOptions;
use clap::{App, Arg};
use libc::{self, EFD_NONBLOCK};
use log::{error, warn};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process;
use std::result;
use std::slice;
use std::sync::{Arc, RwLock};

use vhost_rs::vhost_user::message::*;
use vhost_rs::vhost_user::Error as VhostUserError;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};

use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};
use vm_virtio::DescriptorChain;
use vmm_sys_util::eventfd::EventFd;

const SECTOR_SHIFT: u8 = 9;
const BLK_SIZE: u32 = 512;
pub const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = 0;
// The device has been dropped.
pub const KILL_EVENT: u16 = 1;
// Number of DeviceEventT events supported by this implementation.
pub const BLOCK_EVENTS_COUNT: usize = 2;

pub type VhostUserResult<T> = std::result::Result<T, VhostUserError>;
pub type Result<T> = std::result::Result<T, Error>;
pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Failed to parse socket param.
    ParseSockParam,
    /// Failed to parse block file param.
    ParseBlkParam,
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

struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let mut req = Request {
            request_type: Self::get_request_type(&mem, avail_desc.addr)?,
            sector: Self::get_sector(&mem, avail_desc.addr)?,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                return Err(Error::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.request_type == RequestType::Out {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::In {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(Error::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    fn get_request_type(
        mem: &GuestMemoryMmap,
        desc_addr: GuestAddress,
    ) -> result::Result<RequestType, Error> {
        let type_ = mem.read_obj(desc_addr).map_err(Error::GuestMemory)?;
        match type_ {
            VIRTIO_BLK_T_IN => Ok(RequestType::In),
            VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
            VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
            VIRTIO_BLK_T_GET_ID => Ok(RequestType::GetDeviceID),
            t => Ok(RequestType::Unsupported(t)),
        }
    }

    fn get_sector(mem: &GuestMemoryMmap, desc_addr: GuestAddress) -> result::Result<u64, Error> {
        const SECTOR_OFFSET: usize = 8;
        let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
            Some(v) => v,
            None => return Err(Error::CheckedOffset(desc_addr, SECTOR_OFFSET)),
        };

        mem.read_obj(addr).map_err(Error::GuestMemory)
    }

    #[allow(clippy::ptr_arg)]
    fn execute<T: Seek + Read + Write>(
        &self,
        disk: &mut T,
        disk_nsectors: u64,
        mem: &GuestMemoryMmap,
        disk_id: &Vec<u8>,
    ) -> result::Result<u32, ExecuteError> {
        let mut top: u64 = u64::from(self.data_len) / SECTOR_SIZE;
        if u64::from(self.data_len) % SECTOR_SIZE != 0 {
            top += 1;
        }
        top = top
            .checked_add(self.sector)
            .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
        if top > disk_nsectors {
            return Err(ExecuteError::BadRequest(Error::InvalidOffset));
        }

        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;

        match self.request_type {
            RequestType::In => {
                mem.read_exact_from(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Read)?;
                return Ok(self.data_len);
            }
            RequestType::Out => {
                mem.write_all_to(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Flush => match disk.flush() {
                Ok(_) => {
                    return Ok(0);
                }
                Err(e) => return Err(ExecuteError::Flush(e)),
            },
            RequestType::GetDeviceID => {
                if (self.data_len as usize) < disk_id.len() {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }
                mem.write_slice(&disk_id.as_slice(), self.data_addr)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

pub struct VhostUserBlkBackend {
    vring_worker: Option<Arc<VringWorker>>,
    mem: Option<GuestMemoryMmap>,
    kill_evt: EventFd,
    disk_image: File,
    disk_image_id: Vec<u8>,
    disk_path: PathBuf,
    disk_nsectors: u64,
    config_space: Vec<u8>,
    disk_read_only: bool,
}

impl VhostUserBlkBackend {
    /// Create a new virtio block device that operates on the given file.
    /// The given file must be seekable and sizable.
    pub fn new(disk_path: PathBuf, is_disk_read_only: bool) -> io::Result<VhostUserBlkBackend> {
        //let image = OpenOptions::new().open(disk_path).unwrap();
        let mut image = File::open(&disk_path)?;
        let disk_size = image.seek(SeekFrom::End(0))? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(VhostUserBlkBackend {
            vring_worker: None,
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            disk_image: image,
            disk_image_id: Self::build_disk_image_id(&disk_path),
            disk_path,
            disk_nsectors: disk_size / SECTOR_SIZE,
            config_space: Self::build_config_space(disk_size),
            disk_read_only: is_disk_read_only,
        })
    }

    fn build_device_id(disk_path: &PathBuf) -> result::Result<String, Error> {
        let blk_metadata = match disk_path.metadata() {
            Err(_) => return Err(Error::GetFileMetadata),
            Ok(m) => m,
        };
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

    fn build_disk_image_id(disk_path: &PathBuf) -> Vec<u8> {
        let mut default_disk_image_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_path) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_disk_image_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_disk_image_id
    }

    fn build_config_space(disk_size: u64) -> Vec<u8> {
        let mut blk_config = virtio_blk_config::default();
        blk_config.capacity = disk_size / SECTOR_SIZE;
        blk_config.blk_size = BLK_SIZE;
        blk_config.size_max = 65535;
        blk_config.seg_max = 128 - 2;
        blk_config.min_io_size = 1;
        blk_config.opt_io_size = 1;
        blk_config.num_queues = 1;

        // In order to convert struct virtio_blk_config to Vec<u8>
        let buf = unsafe {
            slice::from_raw_parts(
                &blk_config as *const virtio_blk_config as *const _,
                mem::size_of::<virtio_blk_config>(),
            )
        };

        buf.to_vec()
    }

    fn process_queue(&mut self, vring: &mut Vring) -> bool {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        if let Some(mem) = &self.mem {
            while let Some(avail_desc) = vring.mut_queue().iter(&mem).next() {
                let len;
                match Request::parse(&avail_desc, &mem) {
                    Ok(request) => {
                        let status = match request.execute(
                            &mut self.disk_image,
                            self.disk_nsectors,
                            &mem,
                            &self.disk_image_id,
                        ) {
                            Ok(l) => {
                                len = l;
                                VIRTIO_BLK_S_OK
                            }
                            Err(e) => {
                                error!("Failed to execute request: {:?}", e);
                                len = 1; // We need at least 1 byte for the status.
                                e.status()
                            }
                        };
                        // We use unwrap because the request parsing process already checked that the
                        // status_addr was valid.
                        mem.write_obj(status, request.status_addr).unwrap();
                    }
                    Err(e) => {
                        error!("Failed to parse available descriptor chain: {:?}", e);
                        len = 0;
                    }
                }
                used_desc_heads[used_count] = (avail_desc.index, len);
                used_count += 1;
            }

            for &(desc_index, len) in &used_desc_heads[..used_count] {
                vring.mut_queue().add_used(&mem, desc_index, len);
            }
            used_count > 0
        } else {
            error!("No memory for queue handling!\n");
            false
        }
    }
}

impl Clone for VhostUserBlkBackend {
    fn clone(&self) -> Self {
        VhostUserBlkBackend {
            vring_worker: self.vring_worker.clone(),
            mem: self.mem.clone(),
            disk_nsectors: self.disk_nsectors.clone(),
            disk_image_id: self.disk_image_id.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            disk_image: self.disk_image.try_clone().unwrap(),
            disk_path: self.disk_path.clone(),
            config_space: self.config_space.clone(),
            disk_read_only: self.disk_read_only,
        }
    }
}

impl VhostUserBackend for VhostUserBlkBackend {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE as usize
    }

    fn features(&self) -> u64 {
        let mut avail_features = 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_SIZE_MAX
            | 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if self.disk_read_only {
            avail_features |= 1 << VIRTIO_BLK_F_RO;
        }
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
                if self.process_queue(&mut vring) {
                    if let Err(e) = vring.signal_used_queue() {
                        error!("Failed to signal used queue: {:?}", e);
                    }
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

    fn get_config(&self, offset: u32, size: u32) -> VhostUserResult<Vec<u8>> {
        let config_len = self.config_space.len() as u32;
        if offset >= config_len {
            error!("Failed to read config space");
            return Err(VhostUserError::InvalidParam);
        }
        let mut data = vec![0u8, size as u8];
        if let Some(end) = offset.checked_add(size) {
            // This write can't fail, offset and end are checked against config_len.
            &data
                .write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
        Ok(data)
    }

    fn set_config(&mut self, offset: u32, data: &[u8]) -> result::Result<(), io::Error> {
        Ok(())
    }
}

pub struct VhostUserBlkBackendConfig {
    pub blk: String,
    pub sock: String,
}

impl<'a> VhostUserBlkBackendConfig {
    pub fn parse(backend: String) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut blk: &str = "";
        let mut sock: &str = "";

        for param in params_list.iter() {
            if param.starts_with("blk=") {
                blk = &param[4..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            }
        }

        if !blk.is_empty() {
            return Err(Error::ParseBlkParam)?;
        }

        if sock.is_empty() {
            return Err(Error::ParseSockParam)?;
        }

        Ok(VhostUserBlkBackendConfig {
            blk: blk.to_string(),
            sock: sock.to_string(),
        })
    }
}

fn main() {
    let cmd_arguments = App::new("vhost-user-blk backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-blk backend.")
        .arg(
            Arg::with_name("backend")
                .long("backend")
                .help(
                    "Backend parameters \"blk=<blk_path>,\
                     sock=<socket_path>\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let vhost_user_blk_backend = cmd_arguments.value_of("backend").unwrap();

    let backend_config = match VhostUserBlkBackendConfig::parse(vhost_user_blk_backend.to_string())
    {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let blk_backend = Arc::new(RwLock::new(
        VhostUserBlkBackend::new(PathBuf::from(backend_config.blk), false).unwrap(),
    ));
    println!("blk_backend is created!\n");

    let name = "vhost-user-blk-backend";
    let mut blk_daemon = VhostUserDaemon::new(
        name.to_string(),
        backend_config.sock.to_string(),
        blk_backend.clone(),
    )
    .unwrap();
    println!("blk_daemon is created!\n");

    let vring_worker = blk_daemon.get_vring_worker();

    if vring_worker
        .register_listener(
            blk_backend.read().unwrap().kill_evt.as_raw_fd(),
            epoll::Events::EPOLLIN,
            u64::from(KILL_EVENT),
        )
        .is_err()
    {
        println!("failed to register listener for kill event\n");
    }

    blk_backend.write().unwrap().vring_worker = Some(vring_worker);

    if let Err(e) = blk_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-blk with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    blk_daemon.wait().unwrap();
}
