// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use core::fmt;
use std::borrow::Cow;
use std::num::Wrapping;

use super::cipher::SealingKey;
use bytes::{Bytes, BytesMut};
use compression::Compress;
use log::debug;
use ssh_encoding::Writer;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use super::*;

/// The SSH client/server identification string.
#[derive(Debug)]
pub enum SshId {
    /// When sending the id, append RFC standard `\r\n`. Example: `SshId::Standard("SSH-2.0-acme")`
    Standard(Cow<'static, str>),
    /// When sending the id, use this buffer as it is and do not append additional line terminators.
    Raw(Cow<'static, str>),
}

impl SshId {
    pub(crate) fn as_kex_hash_bytes(&self) -> &[u8] {
        match self {
            Self::Standard(s) => s.as_bytes(),
            Self::Raw(s) => s.trim_end_matches(['\n', '\r']).as_bytes(),
        }
    }

    /// Write the SSH identification string to a buffer.
    /// Buffer is not sensitive - SSH identification strings are public protocol data.
    pub(crate) fn write(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::Standard(s) => buffer.extend_from_slice(format!("{s}\r\n").as_bytes()),
            Self::Raw(s) => buffer.extend_from_slice(s.as_bytes()),
        }
    }
}

/// SSH packet read/write buffer. Uses Vec<u8> (not CryptoVec/mlocked) because
/// packet data is not secret material.
#[derive(Debug, Default)]
pub struct SSHBuffer {
    pub buffer: Vec<u8>,
    pub len: usize,   // next packet length.
    pub bytes: usize, // total payload bytes read/written since the last rekey
    // Sequence numbers are on 32 bits and wrap.
    // https://tools.ietf.org/html/rfc4253#section-6.4
    pub seqn: Wrapping<u32>,
}

impl SSHBuffer {
    pub fn new() -> Self {
        SSHBuffer {
            buffer: Vec::new(),
            len: 0,
            bytes: 0,
            seqn: Wrapping(0),
        }
    }

    pub fn send_ssh_id(&mut self, id: &SshId) {
        id.write(&mut self.buffer);
    }
}

pub(crate) struct PacketBytesWriter {
    buffer: BytesMut,
}

impl Writer for PacketBytesWriter {
    fn write(&mut self, bytes: &[u8]) -> ssh_encoding::Result<()> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
}

impl PacketBytesWriter {
    #[allow(dead_code)]
    pub(crate) fn push(&mut self, byte: u8) {
        self.buffer.extend_from_slice(&[byte]);
    }

    #[allow(dead_code)]
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn freeze(self) -> Bytes {
        self.buffer.freeze()
    }
}

/// Incoming SSH packet after decryption and optional decompression.
/// Uses Vec<u8> (not CryptoVec/mlocked) because incoming network data is not secret.
#[derive(Debug)]
pub(crate) struct IncomingSshPacket {
    pub buffer: Vec<u8>,
    pub seqn: Wrapping<u32>,
}

/// Packet writer for constructing and encrypting outgoing SSH packets.
pub(crate) struct PacketWriter {
    cipher: Box<dyn SealingKey + Send>,
    compress: Compress,
    packet_buffer: Vec<u8>,
    write_buffer: SSHBuffer,
}

impl Debug for PacketWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWriter").finish()
    }
}

impl PacketWriter {
    // SSH packet prefix = packet_length (cipher::PACKET_LENGTH_LEN bytes)
    // + padding_length (1 byte).
    const PACKET_PREFIX_LEN: usize = cipher::PACKET_LENGTH_LEN + 1;

    pub fn clear() -> Self {
        Self::new(Box::new(cipher::clear::Key {}), Compress::None)
    }

    pub fn new(cipher: Box<dyn SealingKey + Send>, compress: Compress) -> Self {
        Self {
            cipher,
            compress,
            packet_buffer: Vec::new(),
            write_buffer: SSHBuffer::new(),
        }
    }

    fn prepare_packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = std::mem::take(&mut self.packet_buffer);
        buf.clear();
        match f(&mut buf) {
            Ok(()) => Ok(buf),
            Err(err) => {
                self.packet_buffer = buf;
                Err(err)
            }
        }
    }

    fn write_packet_in_place<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<(), Error> {
        self.write_payload_into_output(|buffer, payload_start| {
            f(buffer)?;
            Ok(buffer.len() - payload_start)
        })
    }

    fn write_payload_into_output<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>, usize) -> Result<usize, Error>,
    {
        let offset = self.write_buffer.buffer.len();
        let payload_start = offset + Self::PACKET_PREFIX_LEN;

        self.write_buffer.buffer.resize(payload_start, 0);
        match f(&mut self.write_buffer.buffer, payload_start) {
            Ok(payload_len) => {
                if payload_len == 0 {
                    self.write_buffer.buffer.truncate(offset);
                    return Ok(());
                }

                if let Some(message_type) = self.write_buffer.buffer.get(payload_start) {
                    debug!("> msg type {message_type:?}, len {payload_len}");
                }

                self.cipher
                    .finish_packet(offset, payload_len, &mut self.write_buffer);
                Ok(())
            }
            Err(err) => {
                if let Some(payload) = self.write_buffer.buffer.get_mut(offset..) {
                    payload.zeroize();
                }
                self.write_buffer.buffer.truncate(offset);
                Err(err)
            }
        }
    }

    fn write_compressed_payload_into_output(&mut self, buf: &[u8]) -> Result<(), Error> {
        let offset = self.write_buffer.buffer.len();
        let payload_start = offset + Self::PACKET_PREFIX_LEN;

        self.write_buffer.buffer.resize(payload_start, 0);
        match self
            .compress
            .compress_into(buf, &mut self.write_buffer.buffer, payload_start)
        {
            Ok(payload_len) => {
                if payload_len == 0 {
                    self.write_buffer.buffer.truncate(offset);
                    return Ok(());
                }

                self.cipher
                    .finish_packet(offset, payload_len, &mut self.write_buffer);
                Ok(())
            }
            Err(err) => {
                if let Some(payload) = self.write_buffer.buffer.get_mut(offset..) {
                    payload.zeroize();
                }
                self.write_buffer.buffer.truncate(offset);
                Err(err)
            }
        }
    }

    pub fn packet_raw(&mut self, buf: &[u8]) -> Result<(), Error> {
        if let Some(message_type) = buf.first() {
            debug!("> msg type {message_type:?}, len {}", buf.len());
            if matches!(&self.compress, Compress::None) {
                self.cipher.write(buf, &mut self.write_buffer);
            } else {
                self.write_compressed_payload_into_output(buf)?;
            }
        }
        Ok(())
    }

    /// Sends a packet using the reusable plaintext packet buffer.
    ///
    /// The closure must append only the packet payload bytes. It must not
    /// modify or truncate any existing contents in the provided buffer.
    /// When compression is disabled, the buffer may already contain queued
    /// packets and the reserved 5-byte packet header prefix for the packet
    /// being built, so callers must only write new payload bytes starting at
    /// the current end of the buffer.
    pub fn write_packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<(), Error> {
        if matches!(&self.compress, Compress::None) {
            return self.write_packet_in_place(f);
        }
        let buf = self.prepare_packet(f)?;
        let result = self.packet_raw(&buf);
        self.packet_buffer = buf;
        result
    }

    pub(crate) fn reserve_cleartext_packet_output(
        &mut self,
        payload_bytes: usize,
        packet_count: usize,
    ) {
        if !matches!(&self.compress, Compress::None) {
            return;
        }

        // Padding is cipher-dependent and rounded to the cipher block size.
        // Reserving a small fixed margin avoids repeated output-buffer growth
        // without coupling callers to individual cipher padding formulas.
        let per_packet_margin = Self::PACKET_PREFIX_LEN + self.cipher.tag_len() + 32;
        let additional =
            payload_bytes.saturating_add(packet_count.saturating_mul(per_packet_margin));
        self.write_buffer.buffer.reserve(additional);
    }

    /// Sends and returns the packet contents for callers that need to retain
    /// the plaintext packet after it has been queued for encryption.
    #[allow(dead_code)]
    pub fn packet<F: FnOnce(&mut Vec<u8>) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<Bytes, Error> {
        let buf = self.prepare_packet(f)?;
        if let Err(err) = self.packet_raw(&buf) {
            self.packet_buffer = buf;
            return Err(err);
        }
        Ok(Bytes::from(buf))
    }

    pub(crate) fn packet_bytes<F>(&mut self, f: F) -> Result<Bytes, Error>
    where
        F: FnOnce(&mut PacketBytesWriter) -> Result<(), Error>,
    {
        let mut buf = PacketBytesWriter {
            buffer: BytesMut::new(),
        };
        f(&mut buf)?;
        let packet = buf.freeze();
        self.packet_raw(packet.as_ref())?;
        Ok(packet)
    }

    pub fn buffer(&mut self) -> &mut SSHBuffer {
        &mut self.write_buffer
    }

    /// Payload bytes written since the current cipher was installed.
    pub fn bytes_written(&self) -> usize {
        self.write_buffer.bytes
    }

    pub fn compress(&mut self) -> &mut Compress {
        &mut self.compress
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn SealingKey + Send>) {
        self.cipher = cipher;
        // Every cipher installation starts a new key epoch. In particular,
        // discard the cleartext KEX packets counted before the initial keys
        // were installed as well as the previous encrypted epoch on rekey.
        self.write_buffer.bytes = 0;
    }

    pub fn reset_seqn(&mut self) {
        self.write_buffer.seqn = Wrapping(0);
    }

    pub async fn flush_into<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> std::io::Result<()> {
        if !self.write_buffer.buffer.is_empty() {
            w.write_all(&self.write_buffer.buffer).await?;
            w.flush().await?;
            self.write_buffer.buffer.clear();
        }
        Ok(())
    }
}
