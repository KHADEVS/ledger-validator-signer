//! The commands of the app, over the emulator's TCP port. A USB transport is still to write.

use std::io::{self, Read, Write};
use std::net::TcpStream;

pub const OK: u16 = 0x9000;
pub const SLASHABLE: u16 = 0xB101;
pub const NOT_ENABLED: u16 = 0xB102;
pub const SETTING: u16 = 0xB106;
pub const DENIED: u16 = 0x6985;

pub const PUBLIC_KEY: u8 = 0x06;
pub const ATTESTATION: u8 = 0x21;
pub const BLOCK: u8 = 0x22;
pub const AGGREGATION_SLOT: u8 = 0x27;
pub const RANDAO: u8 = 0x28;
pub const SYNC_MESSAGE: u8 = 0x29;
pub const SYNC_SELECTION: u8 = 0x2A;
pub const BEGIN: u8 = 0x2C;
pub const BITS: u8 = 0x2D;
pub const END: u8 = 0x2E;
pub const EXIT: u8 = 0x30;
pub const REGISTRATION: u8 = 0x32;

pub struct Device {
    stream: TcpStream,
}

impl Device {
    pub fn connect(address: &str) -> io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(address)?,
        })
    }

    /// Sends one command and returns the answer with its status word.
    pub fn send(&mut self, ins: u8, data: &[u8]) -> io::Result<(Vec<u8>, u16)> {
        let length = u8::try_from(data.len()).map_err(|_| io::Error::other("command too long"))?;
        let mut apdu = vec![0xE0, ins, 0, 0, length];
        apdu.extend_from_slice(data);
        self.stream.write_all(&(apdu.len() as u32).to_be_bytes())?;
        self.stream.write_all(&apdu)?;
        let mut size = [0u8; 4];
        self.stream.read_exact(&mut size)?;
        let mut body = vec![0u8; u32::from_be_bytes(size) as usize + 2];
        self.stream.read_exact(&mut body)?;
        let status = body.split_off(body.len() - 2);
        Ok((body, u16::from_be_bytes([status[0], status[1]])))
    }
}
