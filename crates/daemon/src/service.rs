//! The Windows service: started by the service manager as `omnitund
//! --service` (the installer registers it, as LocalSystem). A stop, or the
//! system shutting down, closes the sessions first, as a signal does on
//! Unix.

use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::{define_windows_service, service_dispatcher};

use crate::Args;

/// The arguments of the command line, for the service's thread.
static ARGS: OnceLock<std::sync::Mutex<Option<Args>>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hands this thread to the service manager until the service stops.
pub fn run(args: Args) -> anyhow::Result<()> {
    ARGS.get_or_init(|| std::sync::Mutex::new(Some(args)));
    service_dispatcher::start(vpn_core::brand::DAEMON, ffi_service_main)?;
    Ok(())
}

fn service_main(_: Vec<OsString>) {
    let args = ARGS.get().and_then(|a| a.lock().unwrap().take());
    let Some(args) = args else { return };
    // Without a log, the service manager still records the exit code.
    let _ = crate::winlog::init();
    if let Err(e) = serve(args) {
        tracing::error!("{e:#}");
    }
}

fn serve(args: Args) -> anyhow::Result<()> {
    let stop = CancellationToken::new();
    let handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::default();
    let handler = {
        let (stop, handle) = (stop.clone(), handle.clone());
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                if let Some(handle) = handle.get() {
                    let _ = handle.set_service_status(status(ServiceState::StopPending, crate::SHUTDOWN_TIMEOUT));
                }
                stop.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let registered = service_control_handler::register(vpn_core::brand::DAEMON, handler)?;
    let _ = handle.set(registered);
    registered.set_service_status(status(ServiceState::Running, Duration::ZERO))?;
    tracing::info!("started by the service manager");

    let result = tokio::runtime::Runtime::new()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(crate::daemon(args, stop.cancelled_owned())));
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("{e:#}");
            1
        }
    };
    let mut stopped = status(ServiceState::Stopped, Duration::ZERO);
    stopped.exit_code = ServiceExitCode::ServiceSpecific(code);
    registered.set_service_status(stopped)?;
    Ok(())
}

/// The service's status; `wait` is how long the next step may take.
fn status(state: ServiceState, wait: Duration) -> ServiceStatus {
    let controls = match state {
        // Preshutdown: the sessions close before the network goes.
        ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        _ => ServiceControlAccept::empty(),
    };
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: wait + Duration::from_secs(5),
        process_id: None,
    }
}
