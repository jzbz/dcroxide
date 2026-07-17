// SPDX-License-Identifier: ISC
//! dcrd's Windows service wrapper (`service_windows.go`): running the
//! daemon under the service control manager, and the `--service`
//! command-line controls that install, remove, start, and stop the
//! registered service.
//!
//! The SCM integration rides the `windows-service` crate: the
//! dispatcher detects whether the process was launched by the service
//! control manager (dcrd `svc.IsWindowsService` folded into the
//! failed-connect error), the registered control handler translates
//! stop and shutdown requests into the daemon's graceful shutdown
//! (dcrd `dcrdService.Execute` sending on `shutdownRequestChannel`),
//! and the status transitions mirror dcrd's start-pending → running →
//! stop-pending → stopped sequence.  The Windows event log half of
//! dcrd's wrapper (`eventlog.InstallAsEventCreate` and the
//! start-of-day message) is not ported: the daemon's log lines go to
//! standard output under the SCM exactly as they do interactively.
//!
//! On other platforms every entry point is a stub: dcrd's
//! `runServiceCommand` hook is nil off Windows, so the `--service`
//! flag parses but does nothing, and the service detection reports
//! interactive mode.

/// The name of the dcrd service (dcrd `svcName`), the "real" name used
/// to control the service.
pub const SVC_NAME: &str = "dcrdsvc";

/// The service name shown in the Windows services list (dcrd
/// `svcDisplayName`); only for display purposes.
pub const SVC_DISPLAY_NAME: &str = "Dcrd Service";

/// The description of the service (dcrd `svcDesc`).
pub const SVC_DESC: &str = "Downloads and stays synchronized with the Decred block \
chain and provides chain services to applications.";

/// The daemon body the service runs (the whole of `dcrdMain`).
pub type ServiceRun = Box<dyn FnOnce() + Send>;

/// The graceful-shutdown request the service control handler fires on
/// an SCM stop or shutdown control (dcrd's `shutdownRequestChannel`
/// send).
pub type RequestShutdown = Box<dyn Fn() + Send + Sync>;

/// Run one of the supported service commands (dcrd
/// `performServiceCommand`): `install`, `remove`, `start`, or `stop`,
/// with dcrd's error text for anything else.
pub fn run_service_command(command: &str) -> Result<(), String> {
    match command {
        "install" => imp::install_service(),
        "remove" => imp::remove_service(),
        "start" => imp::start_service(),
        "stop" => imp::stop_service(),
        other => Err(format!("invalid service command [{other}]")),
    }
}

/// Check whether the process is being invoked as a service, and if so
/// run the daemon under the service control manager (dcrd
/// `serviceMain`).  `Ok(true)` means the process ran as a service and
/// should exit; `Ok(false)` means interactive mode should proceed.
pub fn service_main(run: ServiceRun, request_shutdown: RequestShutdown) -> Result<bool, String> {
    imp::service_main(run, request_shutdown)
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::{RequestShutdown, SVC_DESC, SVC_DISPLAY_NAME, SVC_NAME, ServiceRun};

    /// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: the dispatcher's way of
    /// saying the process was started interactively rather than by the
    /// service control manager.
    const NOT_A_SERVICE: i32 = 1063;

    /// The hooks the FFI service entry consumes; the dispatcher offers
    /// no way to thread state through, so they ride a global exactly
    /// once (dcrd reaches its equivalents as package-level state).
    struct Hooks {
        run: Mutex<Option<ServiceRun>>,
        request_shutdown: RequestShutdown,
    }

    static HOOKS: OnceLock<Hooks> = OnceLock::new();

    define_windows_service!(ffi_service_main, dcrd_service_main);

    /// The service body (dcrd `dcrdService.Execute`): report the
    /// start-pending → running transitions, run the daemon, translate
    /// stop/shutdown controls into the graceful-shutdown request with
    /// a stop-pending report, and report stopped at the end.
    fn dcrd_service_main(_args: Vec<OsString>) {
        let Some(hooks) = HOOKS.get() else {
            return;
        };
        let Some(run) = hooks
            .run
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        else {
            return;
        };

        let status = |state: ServiceState, accepts: ServiceControlAccept| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepts,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };

        // The control handler runs on SCM threads; a stop or shutdown
        // reports stop-pending and requests the daemon's graceful
        // shutdown (dcrd's `shutdownRequestChannel <- struct{}{}`).
        let handle_holder: std::sync::Arc<
            Mutex<Option<service_control_handler::ServiceStatusHandle>>,
        > = std::sync::Arc::default();
        let control_holder = std::sync::Arc::clone(&handle_holder);
        let handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(handle) = control_holder
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                {
                    let _ = handle.set_service_status(status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                    ));
                }
                if let Some(hooks) = HOOKS.get() {
                    (hooks.request_shutdown)();
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status_handle) = service_control_handler::register(SVC_NAME, handler) else {
            return;
        };
        *handle_holder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(status_handle);

        let _ = status_handle.set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
        ));
        let _ = status_handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ));

        run();

        let _ = status_handle
            .set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
    }

    pub(super) fn service_main(
        run: ServiceRun,
        request_shutdown: RequestShutdown,
    ) -> Result<bool, String> {
        let _ = HOOKS.set(Hooks {
            run: Mutex::new(Some(run)),
            request_shutdown,
        });
        match service_dispatcher::start(SVC_NAME, ffi_service_main) {
            Ok(()) => Ok(true),
            // Running interactively (dcrd `svc.IsWindowsService()`
            // false): fall through to normal operation.
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
                Ok(false)
            }
            Err(e) => Err(format!("{e}")),
        }
    }

    /// Install the dcrd service (dcrd `installService`); typically the
    /// msi installer's job, provided for development.  The event log
    /// registration dcrd performs afterwards is not ported.
    pub(super) fn install_service() -> Result<(), String> {
        let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| e.to_string())?;

        // Ensure the service doesn't already exist.
        if manager
            .open_service(SVC_NAME, ServiceAccess::QUERY_STATUS)
            .is_ok()
        {
            return Err(format!("service {SVC_NAME} already exists"));
        }

        let info = ServiceInfo {
            name: OsString::from(SVC_NAME),
            display_name: OsString::from(SVC_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| e.to_string())?;
        service
            .set_description(SVC_DESC)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Uninstall the dcrd service (dcrd `removeService`).
    pub(super) fn remove_service() -> Result<(), String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| e.to_string())?;
        let service = manager
            .open_service(SVC_NAME, ServiceAccess::DELETE)
            .map_err(|_| format!("service {SVC_NAME} is not installed"))?;
        service.delete().map_err(|e| e.to_string())
    }

    /// Start the dcrd service (dcrd `startService`), passing the
    /// current process arguments through like dcrd's
    /// `service.Start(os.Args...)`.
    pub(super) fn start_service() -> Result<(), String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| e.to_string())?;
        let service = manager
            .open_service(SVC_NAME, ServiceAccess::START)
            .map_err(|e| format!("could not access service: {e}"))?;
        let args: Vec<OsString> = std::env::args_os().collect();
        service
            .start(&args)
            .map_err(|e| format!("could not start service: {e}"))
    }

    /// Stop the dcrd service and wait up to ten seconds for it to
    /// reach the stopped state (dcrd `controlService(svc.Stop,
    /// svc.Stopped)`).
    pub(super) fn stop_service() -> Result<(), String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| e.to_string())?;
        let service = manager
            .open_service(SVC_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
            .map_err(|e| format!("could not access service: {e}"))?;
        let mut status = service
            .stop()
            .map_err(|e| format!("could not send control=stop: {e}"))?;

        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .unwrap_or_else(Instant::now);
        while status.current_state != ServiceState::Stopped {
            if Instant::now() >= deadline {
                return Err("timeout waiting for service to go to state=stopped".to_string());
            }
            std::thread::sleep(Duration::from_millis(300));
            status = service
                .query_status()
                .map_err(|e| format!("could not retrieve service status: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{RequestShutdown, ServiceRun};

    /// Off Windows dcrd's `runServiceCommand` hook is nil and the flag
    /// is ignored; these stubs only exist for cross-platform callers
    /// that do not gate the call themselves.
    pub(super) fn install_service() -> Result<(), String> {
        Err("service commands are only supported on Windows".to_string())
    }

    pub(super) fn remove_service() -> Result<(), String> {
        install_service()
    }

    pub(super) fn start_service() -> Result<(), String> {
        install_service()
    }

    pub(super) fn stop_service() -> Result<(), String> {
        install_service()
    }

    pub(super) fn service_main(
        _run: ServiceRun,
        _request_shutdown: RequestShutdown,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command dispatch rejects anything but the four dcrd
    /// commands with dcrd's error text.
    #[test]
    fn invalid_commands_get_dcrds_error() {
        let err = run_service_command("bogus").expect_err("invalid command");
        assert_eq!(err, "invalid service command [bogus]");
    }

    /// The service identity constants match dcrd's.
    #[test]
    fn service_identity_matches_dcrd() {
        assert_eq!(SVC_NAME, "dcrdsvc");
        assert_eq!(SVC_DISPLAY_NAME, "Dcrd Service");
        assert!(SVC_DESC.starts_with("Downloads and stays synchronized"));
    }
}
