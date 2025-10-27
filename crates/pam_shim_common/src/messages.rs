use serde::{Deserialize, Serialize};

type Handle = usize;
type Str<'a> = std::borrow::Cow<'a, std::ffi::CStr>;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request<'a> {
    PamStart {
        service_name: Str<'a>,
        user: Str<'a>,
        confdir: Option<Str<'a>>,
    },
    PamEnd {
        handle: Handle,
        pam_status: libc::c_int,
    },
    PamAuthenticate {
        handle: Handle,
        flags: libc::c_int,
    },
    PamAuthenticateResponse {
        responses: Vec<Option<Str<'a>>>,
    },
    PamSetcred {
        handle: Handle,
        flags: libc::c_int,
    },
    PamAcctMgmt {
        handle: Handle,
        flags: libc::c_int,
    },
    PamOpenSession {
        handle: Handle,
        flags: libc::c_int,
    },
    PamCloseSession {
        handle: Handle,
        flags: libc::c_int,
    },
    PamChauthtok {
        handle: Handle,
        flags: libc::c_int,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamMessage<'a> {
    pub msg_style: libc::c_int,
    pub msg: Str<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response<'a> {
    Handle { handle: Handle, pam_status: libc::c_int },
    Result { pam_status: libc::c_int },
    Conversation {
        messages: Vec<PamMessage<'a>>,
    },
}