#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PamMessage {
    pub msg_style: libc::c_int,
    pub msg: *const libc::c_char,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut libc::c_char,
    pub resp_retcode: libc::c_int,
}

#[repr(C)]
pub struct PamConv {
    pub conv: extern "C" fn(num_msg: libc::c_int, pam_message: *const *const PamMessage, pam_response: *mut *mut PamResponse, appdata: *mut libc::c_void) -> libc::c_int,
    pub appdata_ptr: *mut libc::c_void,
}

pub const PAM_SUCCESS: libc::c_int = 0;
pub const PAM_SYSTEM_ERR: libc::c_int = 4;