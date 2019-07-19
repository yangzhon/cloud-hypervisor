extern crate epoll;
extern crate net_util;
extern crate vhost_rs;
extern crate virtio_bindings;
extern crate vm_memory;

use std;
use std::io;
use vhost_rs::Error as VhostError;
use vm_memory::Error as MmapError;

mod handler;
pub mod net;
pub mod blk;

pub use self::net::Net;
pub use self::blk::Blk;

#[derive(Debug)]
pub enum Error {
    /// Invalid available address.
    AvailAddress,
    /// Queue number  is not correct
    BadQueueNum,
    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Create Epoll eventfd failed
    EpollCreateFd(io::Error),
    /// Epoll ctl error
    EpollCtl(io::Error),
    /// Epoll wait error
    EpollWait(io::Error),
    /// Signal used queue failed.
    FailedSignalingUsedQueue(io::Error),
    /// Read queue failed.
    FailedReadingQueue(io::Error),
    /// Failed to read vhost eventfd.
    MemoryRegions(MmapError),
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Set owner failed.
    VhostUserSetOwner(VhostError),
    /// Get features failed.
    VhostUserGetFeatures(VhostError),
    /// Get protocol features failed.
    VhostUserGetProtocolFeatures(VhostError),
    /// Set features failed.
    VhostUserSetFeatures(VhostError),
    /// Set protocol features failed.
    VhostUserSetProtocolFeatures(VhostError),
    /// Set mem table failed.
    VhostUserSetMemTable(VhostError),
    /// Set vring num failed.
    VhostUserSetVringNum(VhostError),
    /// Set vring addr failed.
    VhostUserSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostUserSetVringBase(VhostError),
    /// Set vring call failed.
    VhostUserSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostUserSetVringKick(VhostError),
    /// Set vring enable failed.
    VhostUserSetVringEnable(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),
    /// Failed to read vhost eventfd.
    VhostUserMemoryRegion(MmapError),
    /// Invalid used address.
    UsedAddress,

    /// Invalid features provided from vhost-user backend
    InvalidFeatures,
}
type Result<T> = std::result::Result<T, Error>;
const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
