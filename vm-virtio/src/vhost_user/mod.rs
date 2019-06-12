extern crate epoll;
extern crate vhost_rs;
extern crate virtio_bindings;
extern crate vm_memory;
extern crate net_util;

use std;
use std::io;
use vm_memory::MmapError;
use vhost_rs::Error as VhostError;

pub mod net;
mod handler;

pub use self::net::Net;

#[derive(Debug)]
pub enum Error {
    /// Queue number  is not correct
    BadQueueNum,
    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    ///
    EpollCreateFd(io::Error),
    ///
    EpollCtl(io::Error),
    ///
    EpollWait(io::Error),
    ///
    FailedSignalingUsedQueue(io::Error),
    ///
    FailedReadingQueue(io::Error),
    /// Error while polling for events.
    PollError(io::Error),
    /// Enabling tap interface failed.
    UnknownEvent(io::Error),
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Set owner failed.
    VhostUserSetOwner(VhostError),
    /// Get features failed.
    VhostUserGetFeatures(VhostError),
    /// Set features failed.
    VhostUserSetFeatures(VhostError),
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
    /// Failed to create vhost eventfd.
    VhostIrqCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),
    /// Failed to read vhost eventfd.
    VhostUserMemoryRegion(MmapError),
    /// Failed to read vhost eventfd.
    MemoryRegions(MmapError),
}
type Result<T> = std::result::Result<T, Error>;
const INTERRUPT_STATUS_USED_RING: u32 = 0x1;



