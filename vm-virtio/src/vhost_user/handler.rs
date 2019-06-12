// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::INTERRUPT_STATUS_USED_RING;

use super::super::{DeviceEventT, Queue};
use super::Error;
use epoll;
use vmm_sys_util::EventFd;

use crate::VirtioInterrupt;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Event for injecting IRQ into guest.
pub const VHOST_IRQ_AVAILABLE: DeviceEventT = 0;
/// Event for stopping the vhost device.
pub const KILL_EVENT: DeviceEventT = 1;

pub type Result<T> = result::Result<T, Error>;

pub struct VhostUserEpollHandler {
    pub vhost_user_interrupt: EventFd,
    pub interrupt_status: Arc<AtomicUsize>,
    pub interrupt_cb: Arc<VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub queues: Vec<Queue>,
}

impl VhostUserEpollHandler {
    /// Construct a new, empty event handler for vhost-based devices.
    ///
    /// # Arguments
    /// * `vhost_user_interrupt` - EventFd to notify queue event
    /// * `interrupt_status` - semaphore before triggering interrupt event
    /// * `interrupt_cdb` EventFd for signaling an interrupt that the guest
    ///                   driver is listening to
    /// * `kill_evt` - EventFd used to kill the vhost-user-net device
    /// * `queues` - queues as sharing memory between master and slave
    pub fn new(
        vhost_user_interrupt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_cb: Arc<VirtioInterrupt>,
        kill_evt: EventFd,
        queues: Vec<Queue>,
    ) -> VhostUserEpollHandler {
        VhostUserEpollHandler {
            vhost_user_interrupt,
            interrupt_status,
            interrupt_cb,
            kill_evt,
            queues,
        }
    }

    fn signal_used_queue(&self, queue_index: usize) -> Result<()> {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        for (queue_index, ref queue) in self.queues.iter().enumerate() {
            (self.interrupt_cb)(&queue).map_err(Error::FailedSignalingUsedQueue)?;
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let epoll_fd = epoll::create(true).map_err(Error::EpollCreateFd)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.vhost_user_interrupt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(VHOST_IRQ_AVAILABLE)),
        )
        .map_err(Error::EpollCtl)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(Error::EpollCtl)?;

        //return Ok(());
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); self.queues.len()];

        'epoll: loop {
            let num_events =
                epoll::wait(epoll_fd, -1, &mut events[..]).map_err(Error::EpollWait)?;

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;
                match ev_type {
                    VHOST_IRQ_AVAILABLE => {
                        self.vhost_user_interrupt
                            .read()
                            .map_err(Error::FailedReadingQueue)?;
                        let result = self.signal_used_queue(0);
                        if let Err(_e) = result {
                            error!("failed to signal used queue");
                        }
                    }
                    KILL_EVENT => {
                        //TODO: call API for device removal here
                        info!("vhost device removed");
                        return Ok(());
                    }
                    _ => {
                        error!("Unknow event for vhost-net");
                    }
                }
            }
        }
    }
}
