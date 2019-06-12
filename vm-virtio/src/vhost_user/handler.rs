// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::super::{Queue, VirtioInterruptType};
use super::Error;
use epoll;
use vmm_sys_util::eventfd::EventFd;

use crate::VirtioInterrupt;
use std::io::{self};
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;

pub type Result<T> = result::Result<T, Error>;

pub struct VhostUserEpollHandler {
    pub interrupt_cb: Arc<VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub queues: Vec<Queue>,
    pub vu_interrupt_list: Vec<EventFd>,
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
        interrupt_cb: Arc<VirtioInterrupt>,
        kill_evt: EventFd,
        queues: Vec<Queue>,
        vu_interrupt_list: Vec<EventFd>,
    ) -> VhostUserEpollHandler {
        VhostUserEpollHandler {
            interrupt_cb,
            kill_evt,
            queues,
            vu_interrupt_list,
        }
    }

    fn signal_used_queue(&self, _queue_index: usize) -> Result<()> {
        (self.interrupt_cb)(&VirtioInterruptType::Queue, Some(&self.queues[_queue_index])).map_err(Error::FailedSignalingUsedQueue)?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let epoll_fd = epoll::create(true).map_err(Error::EpollCreateFd)?;

        for (index, vhost_user_interrupt) in self.vu_interrupt_list.iter().enumerate() {
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                vhost_user_interrupt.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, index as u64),
            )
            .map_err(Error::EpollCtl)?;
        }

        let _kill_event = self.vu_interrupt_list.len();
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, _kill_event as u64),
        )
        .map_err(Error::EpollCtl)?;

        //return Ok(());
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); self.queues.len()];

        'poll: loop {
            let num_events =
                match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::EpollWait(e));
                },
            };

            for event in events.iter().take(num_events) {
                let index = event.data as usize;
                if index < _kill_event {
                    let vhost_user_interrupt = &self.vu_interrupt_list[index];
                    vhost_user_interrupt
                        .read()
                        .map_err(Error::FailedReadingQueue)?;
                    let result = self.signal_used_queue(index);
                    if let Err(_e) = result {
                        error!("failed to signal used queue");
                    }
                } else if index == _kill_event {
                    break 'poll;
                } else {
                    error!("Unknown event for vhost-user-net");
                }
            }
        }
        Ok(())
    }
}
