use std::ffi::{c_void, OsStr};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::sync::mpsc;
use std::{ffi, ptr};
use std::{thread, time};

use widestring::WideCString;
use windows::core::{PCWSTR, PWSTR};
use windows::imp::{FormatMessageW, GetLastError, FORMAT_MESSAGE_FROM_SYSTEM};
use windows::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, MAX_PATH};
use windows::Win32::Security::SC_HANDLE;
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, ENUM_SERVICE_TYPE,
    SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR, SERVICE_ERROR_NORMAL, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_START_TYPE, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_LOGON, WTS_SESSION_UNLOCK,
};

use crate::controller::{ControllerInterface, ServiceMainFn};
use crate::session;
use crate::Error;
use crate::ServiceEvent;

// Default to an invalid Handle
static mut SERVICE_CONTROL_HANDLE: SERVICE_STATUS_HANDLE = SERVICE_STATUS_HANDLE(-1);

type WindowsServiceMainWrapperFn = extern "system" fn(argc: u32, argv: *mut PWSTR);
pub type Session = session::Session_<u32>;

struct Service {
    pub handle: SC_HANDLE,
}

impl Drop for Service {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe { CloseServiceHandle(self.handle) };
        }
    }
}

struct ServiceControlManager {
    pub handle: SC_HANDLE,
}

impl ServiceControlManager {
    fn open(desired_access: u32) -> Result<ServiceControlManager, Error> {
        let handle = unsafe { OpenSCManagerW(None, None, desired_access)? };

        if handle.is_invalid() {
            Err(Error::new(&format!(
                "OpenSCManager: {}",
                get_last_error_text()
            )))
        } else {
            Ok(ServiceControlManager { handle })
        }
    }

    fn open_service(&self, service_name: &str, desired_access: u32) -> Result<Service, Error> {
        let handle = unsafe {
            OpenServiceW(
                self.handle,
                PCWSTR(get_utf16(service_name).as_ptr()),
                desired_access,
            )?
        };

        if handle.is_invalid() {
            Err(Error::new(&format!(
                "OpenServiceW: {}",
                get_last_error_text()
            )))
        } else {
            Ok(Service { handle })
        }
    }
}

impl Drop for ServiceControlManager {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe { CloseServiceHandle(self.handle) };
        }
    }
}

/// Manages the service on the system.
pub struct WindowsController {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub desired_access: u32,
    pub service_type: ENUM_SERVICE_TYPE,
    pub start_type: SERVICE_START_TYPE,
    pub error_control: SERVICE_ERROR,
    pub tag_id: u32,
    pub load_order_group: String,
    pub dependencies: String,
    pub account_name: String,
    pub password: String,
    pub service_status: SERVICE_STATUS,
    pub status_handle: SERVICE_STATUS_HANDLE,
    pub controls_accepted: u32,
}

impl ControllerInterface for WindowsController {
    fn create(&mut self) -> Result<(), Error> {
        unsafe {
            let service_manager = ServiceControlManager::open(SC_MANAGER_ALL_ACCESS)?;

            let filename = get_filename();
            let tag_id = 0;

            let service = CreateServiceW(
                service_manager.handle,
                PCWSTR(get_utf16(self.service_name.as_str()).as_ptr()),
                PCWSTR(get_utf16(self.display_name.as_str()).as_ptr()),
                self.desired_access,
                self.service_type,
                self.start_type,
                self.error_control,
                PCWSTR(get_utf16(filename.as_str()).as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )?;

            if service.is_invalid() {
                return Err(Error::new(&format!(
                    "CreateService: {}",
                    get_last_error_text()
                )));
            }

            self.tag_id = tag_id;

            let mut description = get_utf16(self.description.as_str());

            let mut sd = SERVICE_DESCRIPTIONW {
                lpDescription: PWSTR(description.as_mut_ptr()),
            };

            let p_sd = &mut sd as *mut _ as *mut c_void;
            ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, Some(p_sd));
            CloseServiceHandle(service);

            Ok(())
        }
    }

    fn delete(&mut self) -> Result<(), Error> {
        unsafe {
            let service_manager = ServiceControlManager::open(SC_MANAGER_ALL_ACCESS)?;
            let service = service_manager.open_service(&self.service_name, SERVICE_ALL_ACCESS)?;

            if ControlService(
                service.handle,
                SERVICE_CONTROL_STOP,
                &mut self.service_status,
            )
            .as_bool()
            {
                while QueryServiceStatus(service.handle, &mut self.service_status).as_bool() {
                    if self.service_status.dwCurrentState != SERVICE_STOP_PENDING {
                        break;
                    }
                    thread::sleep(time::Duration::from_millis(250));
                }
            }

            if !DeleteService(service.handle).as_bool() {
                return Err(Error::new(&format!(
                    "DeleteService: {}",
                    get_last_error_text()
                )));
            }

            Ok(())
        }
    }

    fn start(&mut self) -> Result<(), Error> {
        unsafe {
            let service_manager = ServiceControlManager::open(SC_MANAGER_ALL_ACCESS)?;
            let service = service_manager.open_service(&self.service_name, SERVICE_ALL_ACCESS)?;

            if StartServiceW(service.handle, None).as_bool() {
                while QueryServiceStatus(service.handle, &mut self.service_status).as_bool() {
                    if self.service_status.dwCurrentState != SERVICE_START_PENDING {
                        break;
                    }
                    thread::sleep(time::Duration::from_millis(250));
                }
            }

            if self.service_status.dwCurrentState != SERVICE_RUNNING {
                return Err(Error::new("Failed to start service"));
            }

            Ok(())
        }
    }

    fn stop(&mut self) -> Result<(), Error> {
        unsafe {
            let service_manager = ServiceControlManager::open(SC_MANAGER_ALL_ACCESS)?;
            let service = service_manager.open_service(&self.service_name, SERVICE_ALL_ACCESS)?;

            if !ControlService(
                service.handle,
                SERVICE_CONTROL_STOP,
                &mut self.service_status,
            )
            .as_bool()
            {
                return Err(Error::new("ControlService: failed to stop service"));
            }

            while QueryServiceStatus(service.handle, &mut self.service_status).as_bool() {
                if self.service_status.dwCurrentState != SERVICE_STOP_PENDING {
                    break;
                }
                thread::sleep(time::Duration::from_millis(250));
            }

            if self.service_status.dwCurrentState != SERVICE_STOPPED {
                return Err(Error::new("Failed to stop service"));
            }

            Ok(())
        }
    }
}

impl WindowsController {
    pub fn new(service_name: &str, display_name: &str, description: &str) -> WindowsController {
        WindowsController {
            service_name: service_name.to_string(),
            display_name: display_name.to_string(),
            description: description.to_string(),
            desired_access: SERVICE_ALL_ACCESS,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            start_type: SERVICE_AUTO_START,
            error_control: SERVICE_ERROR_NORMAL,
            tag_id: 0,
            load_order_group: "".to_string(),
            dependencies: "".to_string(),
            account_name: "".to_string(),
            password: "".to_string(),
            service_status: SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: SERVICE_STOPPED,
                dwControlsAccepted: 0,
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            },
            status_handle: SERVICE_STATUS_HANDLE::default(),
            controls_accepted: SERVICE_ACCEPT_STOP,
        }
    }

    /// Register the `service_main_wrapper` function, this function is generated by the `Service!` macro.
    pub fn register(
        &mut self,
        service_main_wrapper: WindowsServiceMainWrapperFn,
    ) -> Result<(), Error> {
        unsafe {
            let mut service_name = get_utf16(self.service_name.as_str());

            let service_table: &[*const SERVICE_TABLE_ENTRYW] = &[
                &SERVICE_TABLE_ENTRYW {
                    lpServiceName: PWSTR(service_name.as_mut_ptr()),
                    lpServiceProc: Some(service_main_wrapper),
                },
                ptr::null(),
            ];

            match StartServiceCtrlDispatcherW(*service_table.as_ptr()).0 {
                0 => Err(Error::new("StartServiceCtrlDispatcher")),
                _ => Ok(()),
            }
        }
    }
}

fn set_service_status(
    status_handle: SERVICE_STATUS_HANDLE,
    current_state: SERVICE_STATUS_CURRENT_STATE,
    wait_hint: u32,
) {
    let service_status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: SERVICE_ACCEPT_STOP
            | SERVICE_ACCEPT_SHUTDOWN
            | SERVICE_ACCEPT_SESSIONCHANGE,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    unsafe {
        SetServiceStatus(status_handle, &service_status);
    }
}

unsafe extern "system" fn service_handler<T>(
    control: u32,
    event_type: u32,
    event_data: *mut ffi::c_void,
    context: *mut ffi::c_void,
) -> u32 {
    let tx = context as *mut mpsc::Sender<ServiceEvent<T>>;

    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_service_status(SERVICE_CONTROL_HANDLE, SERVICE_STOP_PENDING, 10);
            let _ = (*tx).send(ServiceEvent::Stop);
            0
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            let session_notification = event_data as *const WTSSESSION_NOTIFICATION;
            let session_id = (*session_notification).dwSessionId;
            let session = Session::new(session_id);

            if event_type == WTS_CONSOLE_CONNECT {
                let _ = (*tx).send(ServiceEvent::SessionConnect(session));
                0
            } else if event_type == WTS_CONSOLE_DISCONNECT {
                let _ = (*tx).send(ServiceEvent::SessionDisconnect(session));
                0
            } else if event_type == WTS_REMOTE_CONNECT {
                let _ = (*tx).send(ServiceEvent::SessionRemoteConnect(session));
                0
            } else if event_type == WTS_REMOTE_DISCONNECT {
                let _ = (*tx).send(ServiceEvent::SessionRemoteDisconnect(session));
                0
            } else if event_type == WTS_SESSION_LOGON {
                let _ = (*tx).send(ServiceEvent::SessionLogon(session));
                0
            } else if event_type == WTS_SESSION_LOGOFF {
                let _ = (*tx).send(ServiceEvent::SessionLogoff(session));
                0
            } else if event_type == WTS_SESSION_LOCK {
                let _ = (*tx).send(ServiceEvent::SessionLock(session));
                0
            } else if event_type == WTS_SESSION_UNLOCK {
                let _ = (*tx).send(ServiceEvent::SessionUnlock(session));
                0
            } else {
                0
            }
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

fn get_args(argc: u32, argv: *mut PWSTR) -> Vec<String> {
    let mut args = Vec::new();
    for i in 0..argc {
        unsafe {
            let s = *argv.add(i as usize);
            let widestr = WideCString::from_ptr_str(s.as_ptr());
            args.push(widestr.to_string_lossy());
        }
    }
    args
}

pub fn get_utf16(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

pub fn get_filename() -> String {
    unsafe {
        let mut filename = [0u16; MAX_PATH as usize];
        let _size = GetModuleFileNameW(None, filename.as_mut());
        String::from_utf16(&filename).unwrap_or_else(|_| String::from(""))
    }
}

pub fn get_last_error_text() -> String {
    unsafe {
        let mut message = [0u16; 512];
        let length = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            ptr::null(),
            GetLastError(),
            0,
            PWSTR(message.as_mut_ptr()),
            message.len() as u32,
            ptr::null_mut(),
        );
        String::from_utf16(&message[0..length as usize]).unwrap_or_else(|_| String::from(""))
    }
}

/// Generates a `service_main_wrapper` that wraps the provided service main function.
#[macro_export]
macro_rules! Service {
    ($name:expr, $function:ident) => {
        use $crate::windows::core::PWSTR;

        extern "system" fn service_main_wrapper(argc: u32, argv: *mut PWSTR) {
            if let Err(error) = dispatch($function, $name, argc, argv) {
                // The service will properly abort if an error is raised
                panic!("{error}")
            };
        }
    };
}

#[doc(hidden)]
pub fn dispatch<T>(
    service_main: ServiceMainFn<T>,
    name: &str,
    argc: u32,
    argv: *mut PWSTR,
) -> Result<(), Error> {
    let args = get_args(argc, argv);
    let service_name = get_utf16(name);
    let (tx, rx) = mpsc::channel();
    let _tx = tx.clone();
    let ctrl_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            Some(&PCWSTR(service_name.as_ptr())),
            Some(service_handler::<T>),
            Some(&tx as *const _ as *const ffi::c_void),
        )?
    };
    unsafe { SERVICE_CONTROL_HANDLE = ctrl_handle };
    set_service_status(ctrl_handle, SERVICE_START_PENDING, 0);
    set_service_status(ctrl_handle, SERVICE_RUNNING, 0);
    service_main(rx, _tx, args, false);
    set_service_status(ctrl_handle, SERVICE_STOPPED, 0);
    Ok(())
}
