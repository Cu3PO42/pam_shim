mod client;
mod sys;

use std::os::unix::io::FromRawFd;
use std::rc::Rc;
use std::cell::RefCell;

use pam_shim_common::messages::*;

struct Conversation<'a> {
    handle: *mut libc::c_void,
    conv: sys::PamConv,
    client: Rc<RefCell<client::Client<'a>>>,
}

fn main() {
    // Save original stdout file descriptor since we will overwrite it in the next step.
    // SAFETY: 1 is always stdout and a valid file descriptor.
    let ipc_out = unsafe { libc::dup(1) };
    if ipc_out == -1 {
        panic!("Failed to duplicate stdout file descriptor");
    }

    // SAFETY: We have just created the file descriptor and checked for its validity.
    let mut stdout = unsafe { std::fs::File::from_raw_fd(ipc_out) };
    
    // Redirect stdout to stderr so we can use stdout for IPC.
    // SAFETY: 2 and 1 are always valid file descriptors.
    unsafe { libc::dup2(2, 1); }

    let stdin = std::io::stdin();

    let client = Rc::new(RefCell::new(client::Client::new(&stdin, &mut stdout)));

    loop {
        let req: Request = client.borrow_mut().receive().expect("Failed to read message from stdin");
        let response: Response = match req {
            Request::PamStart { service_name, user, confdir } => {
                let mut conv = Conversation {
                    handle: std::ptr::null_mut(),
                    conv: sys::PamConv {
                        conv: conv_fn,
                        appdata_ptr: std::ptr::null_mut(),
                    },
                    client: Rc::clone(&client),
                };

                let addr = &mut conv as *mut _;
                conv.conv.appdata_ptr = addr as *mut libc::c_void;

                let mut handle_out = std::ptr::null_mut();
                let res = unsafe { 
                    match confdir {
                        Some(confdir) => sys::pam_start_confdir(service_name.as_ptr(), user.as_ptr(), &conv.conv, confdir.as_ptr(), &mut handle_out),
                        Option::None => sys::pam_start(service_name.as_ptr(), user.as_ptr(), &conv.conv, &mut handle_out),
                    }
                };
                if res == sys::PAM_SUCCESS {
                    conv.handle = handle_out;
                    let ref_handle = &conv as *const _ as usize;
                    client.borrow_mut().send(&Response::Handle { handle: ref_handle, pam_status: res }).expect("Failed to write message to stdout");

                    handle_session(&mut conv, ref_handle)
                } else {
                    Response::Result { pam_status: res }
                }
            },
            // If no session is active, we can only handle start requests.
            _ => Response::Result { pam_status: sys::PAM_SYSTEM_ERR }
        };
        client.borrow_mut().send(&response).expect("Failed to write message to stdout");
    }
}

fn handle_session(conv: &mut Conversation, ref_handle: usize) -> Response<'static> {
    loop {
        let req = conv.client.borrow_mut().receive().expect("Failed to read message from stdin");
        let res = match req {
            Request::PamStart { .. } => {
                // This is unexpected, as we are already in a session.
                Response::Result { pam_status: sys::PAM_SYSTEM_ERR }
            }
            Request::PamEnd { handle, pam_status } => {
                // SAFETY: The handle comes from our conversation struct, which we only
                //         initialize in pam_start on success.
                let res = unsafe { sys::pam_end(conv.handle, pam_status) };
                if res == sys::PAM_SUCCESS {
                    return Response::Result { pam_status: res }
                }
                Response::Result { pam_status: res }
            }
            Request::PamAuthenticate { handle, flags } => {
                let res = unsafe { sys::pam_authenticate(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            Request::PamAcctMgmt { handle, flags } => {
                let res = unsafe { sys::pam_acct_mgmt(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            Request::PamOpenSession { handle, flags } => {
                let res = unsafe { sys::pam_open_session(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            Request::PamCloseSession { handle, flags } => {
                let res = unsafe { sys::pam_close_session(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            Request::PamChauthtok { handle, flags } => {
                let res = unsafe { sys::pam_chauthtok(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            Request::PamAuthenticateResponse { .. } => {
                // This is unexpected here, as we only expect this message as part of a conversation.
                Response::Result { pam_status: sys::PAM_SYSTEM_ERR }
            }
            Request::PamSetcred { handle, flags } => {
                let res = unsafe { sys::pam_setcred(conv.handle, flags) };
                Response::Result { pam_status: res }
            }
            _ => Response::Result { pam_status: sys::PAM_SYSTEM_ERR }
        };
        conv.client.borrow_mut().send(&res).expect("Failed to write message to stdout");
    }
}

extern "C" fn conv_fn(num_msg: libc::c_int, pam_message: *const *const sys::PamMessage, pam_response: *mut *mut sys::PamResponse, appdata: *mut libc::c_void) -> libc::c_int {
    match conv_impl(num_msg, pam_message, pam_response, appdata) {
        Ok(code) => code,
        Err(_) => sys::PAM_SYSTEM_ERR,
    }
}

fn conv_impl(num_msg: libc::c_int, pam_message: *const *const sys::PamMessage, pam_response: *mut *mut sys::PamResponse, appdata: *mut libc::c_void) -> Result<libc::c_int, ConvError> {
    // SAFETY: According to the PAM documentation, pam_message is a valid pointer to an array of
    //         of num_msg pointers. References have the same layout as pointers.
    let messages = unsafe {
        std::slice::from_raw_parts(pam_message as *const &sys::PamMessage, num_msg as usize)
    };
    // SAFETY: appdata was set to point to a Conversation struct in pam_start.
    //         Additionally, the API is blocking, therefore we have exclusive access to it.
    let conv = unsafe { &mut *(appdata as *mut Conversation) };

    conv.client.borrow_mut().send(&Response::Conversation {
        messages: messages.iter().map(|msg| PamMessage {
            msg_style: msg.msg_style,
            // SAFETY: According to the PAM documentation, the string pointer is valid.
            msg: std::borrow::Cow::Borrowed(unsafe { std::ffi::CStr::from_ptr(msg.msg) }),
        }).collect(),
    })?;

    let resp: Request = conv.client.borrow_mut().receive()?;
    match resp {
        Request::PamAuthenticateResponse { responses } => {
            let resp_vec = responses.into_iter().map(|resp| {
                let str = resp.map(|r| Box::leak(r.into_owned().into_boxed_c_str()).as_ptr()).unwrap_or(std::ptr::null());
                sys::PamResponse {
                    resp: str as *mut _,
                    resp_retcode: 0,
                }
            }).collect::<Vec<_>>();
            let responses = Box::leak(resp_vec.into_boxed_slice()).as_mut_ptr();
            // SAFETY: The caller guarantees pam_response is a valid pointer to write to.
            unsafe {
                std::ptr::write(pam_response, responses);
            }
            return Ok(sys::PAM_SUCCESS);
        }
        // All other responses are invalid.
        _ => Err(ConvError)
    }
}

struct ConvError;
impl<T: std::error::Error> From<T> for ConvError {
    fn from(_: T) -> ConvError {
        ConvError
    }
}