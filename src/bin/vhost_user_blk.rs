// Copyright (C) 2019 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate vhost_user_backend;
extern crate vub;

use std::collections::HashMap;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use clap::{crate_authors, crate_version, App, Arg};
use log::{debug, error, info};
use vhost_rs::SlaveListener;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};
use vub::backend::StorageBackend;
use vub::backend_raw::StorageBackendRaw;
use vub::backend_raw_async::StorageBackendRawAsync;
use vub::block::VhostUserBlk;

fn main() {
    env_logger::init();

    let cmd_args = App::new("vhost-user-blk")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Serve a vhost-user-blk device for Cloud-hypervisor.")
        .arg(
            Arg::with_name("socket")
                .long("socket")
                .short("s")
                .takes_value(true)
                .required(true)
                .help("Listen in this UNIX socket"),
        )
        .arg(
            Arg::with_name("backend")
                .long("backend")
                .short("b")
                .takes_value(true)
                .required(true)
                .help("Use this raw image or block device as backend"),
        )
        .arg(
            Arg::with_name("async_backend")
                .long("async_backend")
                .short("a")
                .help("Use an asynchronous backend storage (requires io_uring support)"),
        )
        .arg(
            Arg::with_name("poll_ns")
                .long("poll_ns")
                .short("p")
                .takes_value(true)
                .help("Keep polling the queue for this amount of time (default: 32000)"),
        )
        .arg(
            Arg::with_name("queue_num")
                .long("queue_num")
                .short("q")
                .takes_value(true)
                .help("Number of queues (default: 1)"),
        )
        .arg(
            Arg::with_name("readonly")
                .long("readonly")
                .short("r")
                .help("Open the storage backend in read-only mode"),
        )
        .get_matches();

    let socket_path = cmd_args
        .value_of("socket")
        .expect("Can't parse socket path");
    let disk_image_path = cmd_args
        .value_of("backend")
        .expect("Can't parse backend path");

    let readonly;
    if cmd_args.is_present("readonly") {
        readonly = true;
    } else {
        readonly = false;
    }

    let async_backend;
    if cmd_args.is_present("async_backend") {
        async_backend = true;
    } else {
        async_backend = false;
    }

    let poll_ns;
    if cmd_args.is_present("poll_ns") {
        let poll_ns_str = cmd_args.value_of("poll_ns").expect("Invalid poll_ns value");
        poll_ns = poll_ns_str.parse::<u128>().expect("Invalid poll_ns value");
    } else {
        poll_ns = 32000u128;
    }

    let queue_num: u16;
    if cmd_args.is_present("queue_num") {
        let queue_num_str = cmd_args
            .value_of("queue_num")
            .expect("Invalid queue_num value");
        queue_num = queue_num_str
            .parse::<u16>()
            .expect("Invalid queue_num value");
    } else {
        queue_num = 1;
    }

    if async_backend {
        let uring_efd = EventFd::new().expect("Can't create uring efd");
        let storage_backend = match StorageBackendRawAsync::new(
            disk_image_path,
            uring_efd.as_raw_fd(),
            readonly,
            queue_num,
            poll_ns,
            libc::O_DIRECT,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Can't open disk image {}: {}", disk_image_path, e);
                exit(-1);
            }
        };
    } else {
        let storage_backend = match StorageBackendRaw::new(
            disk_image_path,
            readonly,
            queue_num,
            poll_ns,
            libc::O_DIRECT,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Can't open disk image {}: {}", disk_image_path, e);
                exit(-1);
            }
        };
    }

    let blk_backend = Arc::new(RwLock::new(storage_backend));
    println!("blk_backend is created!\n");

    let name = "vhost-user-blk-backend";
    let mut blk_daemon = VhostUserDaemon::new(
        name.to_string(),
        socket_path.to_string(),
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
