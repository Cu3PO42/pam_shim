use pam_shim_common::messages::*;
use std::io::{Read, Write};


pub struct RemoteClient {
    child: std::process::Child,
}

impl RemoteClient {
    pub fn new() -> Self {
        let child = std::process::Command::new(env!("PAM_SHIM_SERVER_PATH"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .env("LD_LIBRARY_PATH", "")
            .spawn()
            .expect("Failed to start pam_shim_server process");

        RemoteClient { child }
    }

    pub fn send(&mut self, msg: Request) {
        let stdin = self.child.stdin.as_mut().expect("Child stdin not available");
        let msg = serde_brief::to_vec(&msg).expect("Failed to write message to child process");
        stdin.write_all(&msg.len().to_le_bytes()).expect("Failed to write message length to child process");
        stdin.write_all(&msg).expect("Failed to write message to child process");
        stdin.flush().expect("Failed to flush message to child process");
    }

    pub fn receive(&mut self) -> Response<'static> {
        let stdout = self.child.stdout.as_mut().expect("Child stdout not available");
        let mut buf = [0u8; 8];
        stdout.read_exact(&mut buf);
        let len = usize::from_le_bytes(buf);
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        stdout.read_exact(&mut buf);
        serde_brief::from_slice(&buf).expect("Failed to read message from child process")
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}