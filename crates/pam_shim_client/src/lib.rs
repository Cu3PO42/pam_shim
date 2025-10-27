//! This is a small shim that simulates the PAM API by forwarding requests to a separate process
//! that actually links against PAM. This is primarily intended for use with Nix-built applications
//! on non-NixOS systems to let the system native PAM libraries handle authentication without
//! breaking sandboxing or other isolation mechanisms.
//! 
//! # Safety
//! This library exposes the PAM C API, which is inherently unsafe. Almost all functions share some
//! common safety requirements:
//! - All pointers passed to functions must be valid for at least the duration of the call and be
//!   properly aligned.
//! - Any char pointers must point to null-terminated strings.
//! - Any `PamHandle` pointers must point to valid `PamHandle` instances created by `pam_start` or
//!   `pam_start_confdir` and not yet ended with `pam_end`. 
//! - The API is not fully thread-safe. Concurrent calls using the same `PamHandle` instance are
//!   not permitted.

mod client;

use std::ffi::CStr;
use std::borrow::Cow;

use pam_shim_common::messages::*;
use pam_shim_common::sys::*;
use pam_shim_common::sys;
use client::RemoteClient;

pub struct PamHandle {
    internal_handle: *mut libc::c_void,
    conv: *const PamConv,
    handler: RemoteClient,
}

/// Start a PAM transaction and spawn a child to handle it.
/// 
/// Creates a new `PamHandle` and initializes it. A pointer to it is stored in `pamh`.
/// 
/// # Safety
/// The caller must ensure that the pointer to `pam_conversation` remains valid until `pam_end` is
/// called with the returned `PamHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_start_impl(service_name: *const libc::c_char, user: *const libc::c_char, pam_conversation: *const PamConv, pamh: *mut *mut PamHandle) -> libc::c_int {
    // SAFETY: The saftey requirements for pam_start_confdir are the same as for pam_start.
    //         Null is a valid pointer for confdir.
    unsafe { pam_start_confdir_impl(service_name, user, pam_conversation, std::ptr::null(), pamh) }
}

/// Start a PAM transaction and spawn a child to handle it.
/// 
/// Creates a new `PamHandle` and initializes it. A pointer to it is stored in `pamh`.
/// 
/// # Safety
/// The caller must ensure that the pointer to `pam_conversation` remains valid until `pam_end` is
/// called with the returned `PamHandle`. `confdir` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_start_confdir_impl(service_name: *const libc::c_char, user: *const libc::c_char, pam_conversation: *const PamConv, confdir: *const libc::c_char, pamh: *mut *mut PamHandle) -> libc::c_int {
    let mut handle = Box::new(PamHandle {
        internal_handle: std::ptr::null_mut(),
        conv: pam_conversation,
        handler: RemoteClient::new() 
    });

    // SAFETY: The caller must ensure that the pointers are valid and point to null-terminated strings.
    let service_name = Cow::Borrowed(unsafe { CStr::from_ptr(service_name) });
    let user = Cow::Borrowed(unsafe { CStr::from_ptr(user) });
    let confdir = if confdir.is_null() {
        None
    } else {
        Some(Cow::Borrowed(unsafe { CStr::from_ptr(confdir) }))
    };

    handle.handler.send(Request::PamStart {
        service_name,
        user,
        confdir,
    });

    match handle.handler.receive() {
        Response::Handle { handle: internal_handle, pam_status } => {
            if pam_status == PAM_SUCCESS {
                handle.internal_handle = internal_handle as *mut libc::c_void;
                // SAFETY: The caller must ensure that `pamh` is a valid pointer.
                unsafe { *pamh = Box::into_raw(handle); }
            }
            pam_status
        },
        // Other responses are unexpected here.
        _ => PAM_SYSTEM_ERR
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_end_impl(pamh: *mut PamHandle, pam_status: libc::c_int) -> libc::c_int {
    // N.B.: We take ownership of the handle here to ensure it is dropped.
    //       This is intentionally different from other functions where we only borrow.
    let mut handle = unsafe { Box::from_raw(pamh) };
    handle.handler.send(Request::PamEnd {
        handle: pamh as usize,
        pam_status,
    });

    match handle.handler.receive() {
        Response::Result { pam_status } => pam_status,
        // Other responses are unexpected here.
        _ => PAM_SYSTEM_ERR
    }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_authenticate_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    // SAFETY: The caller must ensure that `pamh` is a valid pointer. Also, the
    //         API is not thread-safe and must not be called concurrently.
    //         Therefore, we have the exclusive access to the handle here.
    let handle = unsafe { &mut *pamh };
    handle.handler.send(Request::PamAuthenticate {
        handle: pamh as usize,
        flags,
    });
    // We cannot wait for a single response here, because we may need to handle an arbitrary number
    // of conversation requests.
    loop {
        break match handle.handler.receive() {
            Response::Conversation { messages } => {
                // SAFETY: As part of the contract of pam_start, the caller must
                // ensure that the conversation pointer remains valid until
                // pam_end is called.
                let conv = unsafe { &*handle.conv };

                // Prepare the parameters for the conversation function
                let num_msg = messages.len() as libc::c_int;
                let sys_messages = messages.iter().map(|msg| sys::PamMessage {
                    msg_style: msg.msg_style,
                    msg: msg.msg.as_ptr(),
                }).collect::<Vec<_>>();
                let pam_messages: Vec<*const sys::PamMessage> = sys_messages.iter().map(|msg| {
                    msg as *const _
                }).collect();

                let mut pam_responses_out: *mut sys::PamResponse = std::ptr::null_mut();

                // Call the conversation function
                let ret = (conv.conv)(
                    num_msg,
                    pam_messages.as_ptr(),
                    &mut pam_responses_out,
                    conv.appdata_ptr,
                );

                if ret != PAM_SUCCESS {
                    // If the conversation function fails, the callee is
                    // responsible for cleaning up any allocated resources.
                    return ret;
                }

                // SAFETY: As part of the contract of the conversation function, the response pointer
                //         must point to an array of `num_msg` responses.
                let pam_responses = unsafe { std::slice::from_raw_parts(pam_responses_out, num_msg as usize) };
                let msg_responses = pam_responses.iter().map(|resp| {
                    if resp.resp.is_null() {
                        return None;
                    }
                    // SAFETY: The response string must be a valid null-terminated C string.
                    Some(Cow::Borrowed(unsafe { CStr::from_ptr(resp.resp) }))
                }).collect::<Vec<_>>();

                // Send back the responses
                handle.handler.send(Request::PamAuthenticateResponse {
                    responses: msg_responses,
                });

                // Now, we must clean up resources allocated for responses by the callee.
                for resp in pam_responses {
                    // SAFETY: msg_responses is moved here and no longer valid, we have no refernce to
                    //         the deallocated memory after this.
                    unsafe { libc::free(resp.resp as *mut libc::c_void); }
                }
                // Drop the reference to pam_responses to avoid use-after-free explicitly.
                _ = pam_responses;
                // SAFETY: We have dropped our reference. The array itself was allocated by the callee.
                unsafe { libc::free(pam_responses_out as *mut libc::c_void); }

                continue;
            },
            Response::Result { pam_status } => pam_status,
            // Other responses are unexpected here.
            _ => PAM_SYSTEM_ERR
        }
    }
}

fn pam_default_impl(pamh: *mut PamHandle, flags: libc::c_int, func: fn(*mut PamHandle, libc::c_int) -> Request<'static>) -> libc::c_int {
    let handle = unsafe { &mut *pamh };
    handle.handler.send(func(pamh, flags));
    match handle.handler.receive() {
        Response::Result { pam_status } => pam_status,
        // Other responses are unexpected here.
        _ => PAM_SYSTEM_ERR
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_setcred_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    pam_default_impl(pamh, flags, |pamh, flags| {
        Request::PamSetcred {
            handle: pamh as usize,
            flags,
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_acct_mgmt_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    pam_default_impl(pamh, flags, |pamh, flags| {
        Request::PamAcctMgmt {
            handle: pamh as usize,
            flags,
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_open_session_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    pam_default_impl(pamh, flags, |pamh, flags| {
        Request::PamOpenSession {
            handle: pamh as usize,
            flags,
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_close_session_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    pam_default_impl(pamh, flags, |pamh, flags| {
        Request::PamCloseSession {
            handle: pamh as usize,
            flags,
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_chauthtok_impl(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    pam_default_impl(pamh, flags, |pamh, flags| {
        Request::PamChauthtok {
            handle: pamh as usize,
            flags,
        }
    })
}
