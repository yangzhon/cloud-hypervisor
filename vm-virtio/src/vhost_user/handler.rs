// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::super::{DescriptorChain, Queue, VirtioInterruptType};
use super::Error;
use epoll;
use vmm_sys_util::eventfd::EventFd;

use super::net::CtlVirtqueue;
use super::{VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN};
use crate::VirtioInterrupt;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;
use vm_memory::{Bytes, GuestMemoryMmap};

const VIRTIO_NET_CTRL_MQ: u8 = 4;
const QUEUE_SIZE: usize = 256;

pub type Result<T> = result::Result<T, Error>;

pub struct VhostUserEpollHandler {
    pub interrupt_cb: Arc<VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub queues: Vec<Queue>,
    pub vu_interrupt_list: Vec<EventFd>,
    pub cvq: Option<CtlVirtqueue>,
    pub mem: GuestMemoryMmap,
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
        cvq: Option<CtlVirtqueue>,
        mem: GuestMemoryMmap,
    ) -> VhostUserEpollHandler {
        VhostUserEpollHandler {
            interrupt_cb,
            kill_evt,
            queues,
            vu_interrupt_list,
            cvq,
            mem,
        }
    }

    fn signal_used_queue(&self, queue: &Queue) -> Result<()> {
        (self.interrupt_cb)(&VirtioInterruptType::Queue, Some(queue))
            .map_err(Error::FailedSignalingUsedQueue)?;
        Ok(())
    }

    fn process_mq(&self, avail_desc: DescriptorChain) -> Result<()> {
        let next_desc = if avail_desc.has_next() {
            avail_desc.next_descriptor().unwrap()
        } else {
            return Err(Error::NoQueuePairsNum);
        };
        let _queue_pairs = self
            .mem
            .read_obj::<u16>(next_desc.addr)
            .map_err(Error::GuestMemory)?;
        println!("ctrl virtqueue has queue_pairs: {}\n", _queue_pairs);
        if (_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN)
            || (_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
        {
            return Err(Error::InvalidQueuePairsNum);
        }

        Ok(())
    }

    fn process_cvq(&mut self, mut cvq: CtlVirtqueue) -> Result<()> {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE];
        let mut used_count = 0;
        for avail_desc in cvq.queue.iter(&self.mem) {
            used_desc_heads[used_count] = (avail_desc.index, avail_desc.len);
            used_count += 1;
            let _class = self
                .mem
                .read_obj::<u8>(avail_desc.addr)
                .map_err(Error::GuestMemory)?;
            match _class {
                VIRTIO_NET_CTRL_MQ => {
                    if let Err(_e) = self.process_mq(avail_desc) {
                        return Err(Error::FailedProcessMQ);
                    }
                }
                _ => return Err(Error::InvalidCtlCmd),
            }
        }
        for &(desc_index, len) in &used_desc_heads[..used_count] {
            cvq.queue.add_used(&self.mem, desc_index, len);
        }

        let result = self.signal_used_queue(&cvq.queue);
        if let Err(_e) = result {
            error!("failed to signal used queue");
        }

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

        let _cvq_event = self.vu_interrupt_list.len();
        match &self.cvq {
            Some(cvq) => {
                epoll::ctl(
                    epoll_fd,
                    epoll::ControlOptions::EPOLL_CTL_ADD,
                    cvq.queue_evt.as_raw_fd(),
                    epoll::Event::new(epoll::Events::EPOLLIN, _cvq_event as u64),
                )
                .map_err(Error::EpollCtl)?;
            }
            None => println!("no ctrl queue event to handle!\n"),
        }

        let _kill_event = _cvq_event + 1;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, _kill_event as u64),
        )
        .map_err(Error::EpollCtl)?;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); _kill_event];

        'poll: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
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
                }
            };

            for event in events.iter().take(num_events) {
                let index = event.data as usize;
                if index < _cvq_event {
                    let vhost_user_interrupt = &self.vu_interrupt_list[index];
                    vhost_user_interrupt
                        .read()
                        .map_err(Error::FailedReadingQueue)?;
                    let result = self.signal_used_queue(&self.queues[index]);
                    if let Err(_e) = result {
                        error!("failed to signal used queue");
                    }
                } else if index == _cvq_event {
                    println!("control queue event received!\n");
                    if let Some(cvq) = self.cvq.take() {
                        if let Err(_e) = cvq.queue_evt.read() {
                            error!("failed to get ctl queue event: {:?}", _e);
                        }
                        if let Err(_e) = self.process_cvq(cvq) {
                            error!("failed to process ctl queue: {:?}", _e);
                        }
                    } else {
                        error!("No control queue info !\n");
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
