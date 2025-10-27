pub use pam_shim_common::sys::*;

#[link(name = "pam")]
unsafe extern "C" {
    pub fn pam_start(service_name: *const libc::c_char, user: *const libc::c_char, pam_conversation: *const PamConv, pamh: *mut *mut libc::c_void) -> libc::c_int;
    pub fn pam_start_confdir(service_name: *const libc::c_char, user: *const libc::c_char, pam_conversation: *const PamConv, confdir: *const libc::c_char, pamh: *mut *mut libc::c_void) -> libc::c_int;
    pub fn pam_end(pamh: *mut libc::c_void, pam_status: libc::c_int) -> libc::c_int;
    pub fn pam_setcred(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    pub fn pam_authenticate(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    pub fn pam_acct_mgmt(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    pub fn pam_open_session(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    pub fn pam_close_session(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    pub fn pam_chauthtok(pamh: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
}