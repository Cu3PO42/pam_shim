use pam_shim_common::messages::*;
use std::io::{Read, Write};

pub struct Client<'a> {
    stdin: &'a std::io::Stdin,
    stdout: &'a mut std::fs::File,
}

impl<'a> Client<'a> {
    pub fn new(stdin: &'a std::io::Stdin, stdout: &'a mut std::fs::File) -> Self {
        Client { stdin, stdout }
    }

    pub fn send<'b, 'c>(&'b mut self, msg: &'c Response) -> Result<(), serde_brief::Error> {
        let buf = serde_brief::to_vec(msg)?;
        self.stdout.write_all(&buf.len().to_le_bytes()).expect("failed to write size");
        self.stdout.write_all(&buf).expect("failed to write size");
        self.stdout.flush().expect("Failed to flush child stdin");
        Ok(())
    }

    pub fn receive(&self) -> Result<Request<'static>, serde_brief::Error> {
        let mut buf = [0u8; 8];
        self.stdin.lock().read_exact(&mut buf)?;
        let len = usize::from_le_bytes(buf);
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        self.stdin.lock().read_exact(&mut buf)?;
        serde_brief::from_slice(&buf)
    }
}