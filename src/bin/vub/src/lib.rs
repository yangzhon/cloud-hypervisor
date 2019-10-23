// Copyright (C) 2019 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate vhost_user_backend;

pub mod backend;
pub mod backend_raw;
//pub mod backend_raw_async;
pub mod block;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;

const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
const BLK_SIZE: u32 = 512;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
