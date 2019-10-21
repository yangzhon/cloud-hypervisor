// Copyright (C) 2019 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result, Seek, Write};

use vhost_user_backend::VhostUserBackend;

pub trait StorageBackend: Read + Seek + Write + VhostUserBackend {
    fn get_sectors(&self) -> u64;

    fn get_image_id(&self) -> &Vec<u8>;

    fn is_async(&self) -> bool;

    fn submit_requests(&mut self) -> Result<()>;

    fn get_completion(&mut self, wait: bool) -> Result<Option<usize>>;

    fn check_sector_offset(&self, sector: u64, len: u64) -> Result<()>;

    fn seek_sector(&mut self, sector: u64) -> Result<u64>;
}
