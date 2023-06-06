#![deny(unsafe_code)]

mod interface;
mod monitor;
mod pty;

use std::{
    ffi::{c_int, CString, OsStr},
    io,
    mem::size_of,
    os::unix::{ffi::OsStrExt, process::ExitStatusExt},
    os::{fd::OwnedFd, unix::process::CommandExt},
    process::{Command, ExitStatus},
    sync::{atomic::AtomicBool, Arc},
};

pub use interface::RunOptions;
use signal_hook::consts::*;
use sudo_common::Environment;
use sudo_log::user_error;
use sudo_system::{fork, openpty, pipe, read, set_target_user, write};

/// We only handle the signals that ogsudo handles.
const SIGNALS: &[c_int] = &[
    SIGINT, SIGQUIT, SIGTSTP, SIGTERM, SIGHUP, SIGALRM, SIGPIPE, SIGUSR1, SIGUSR2, SIGCHLD,
    SIGCONT, SIGWINCH,
];

/// Based on `ogsudo`s `exec_pty` function.
pub fn run_command(
    options: impl RunOptions,
    env: Environment,
) -> io::Result<(ExitReason, EmulateDefaultHandler)> {
    // FIXME: should we pipe the stdio streams?
    let mut command = Command::new(options.command());
    // reset env and set filtered environment
    command.args(options.arguments()).env_clear().envs(env);
    // Decide if the pwd should be changed. `--chdir` takes precedence over `-i`.
    let path = options.chdir().cloned().or_else(|| {
        options.is_login().then(|| {
            // signal to the operating system that the command is a login shell by prefixing "-"
            let mut process_name = options
                .command()
                .file_name()
                .map(|osstr| osstr.as_bytes().to_vec())
                .unwrap_or_else(Vec::new);
            process_name.insert(0, b'-');
            command.arg0(OsStr::from_bytes(&process_name));

            options.user().home.clone()
        })
    });

    // change current directory if necessary.
    if let Some(path) = path {
        let is_chdir = options.chdir().is_some();

        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(move || {
                let bytes = path.as_os_str().as_bytes();

                let c_path =
                    CString::new(bytes).expect("nul byte found in provided directory path");

                if let Err(err) = sudo_system::chdir(&c_path) {
                    user_error!("unable to change directory to {}: {}", path.display(), err);
                    if is_chdir {
                        return Err(err);
                    }
                }

                Ok(())
            });
        }
    }

    // set target user and groups
    set_target_user(
        &mut command,
        options.user().clone(),
        options.group().clone(),
    );

    let (pty_leader, pty_follower) = openpty()?;
    let (rx, tx) = pipe()?;
    // SAFETY: we don't call any function that is not `async-signal-safe` inside this `fork` as all
    // the signal handling is done by `signal_hook` which protects us from it.
    #[allow(unsafe_code)]
    let monitor_pid = unsafe { fork() }?;
    // Monitor logic. Based on `exec_monitor`.
    if monitor_pid == 0 {
        match monitor::MonitorRelay::new(command, pty_follower, tx)?.run()? {}
    } else {
        pty::PtyRelay::new(monitor_pid, options.pid(), pty_leader, rx)?.run()
    }
}

/// Atomic type used to decide when to run the default signal handlers
pub type EmulateDefaultHandler = Arc<AtomicBool>;

/// Exit reason for the command executed by sudo.
pub enum ExitReason {
    Code(i32),
    Signal(i32),
}

impl ExitReason {
    fn send(self, tx: &OwnedFd) -> io::Result<()> {
        let mut bytes = [0u8; size_of::<u8>() + size_of::<i32>()];
        let (prefix_bytes, int_bytes) = bytes.split_at_mut(size_of::<u8>());
        match self {
            Self::Code(code) => {
                int_bytes.copy_from_slice(&code.to_ne_bytes());
            }
            Self::Signal(signal) => {
                prefix_bytes.copy_from_slice(&1u8.to_ne_bytes());
                int_bytes.copy_from_slice(&signal.to_ne_bytes());
            }
        }

        write(tx, &bytes)?;

        Ok(())
    }

    fn recv(rx: &OwnedFd) -> io::Result<Self> {
        let mut bytes = [0u8; size_of::<u8>() + size_of::<i32>()];

        read(rx, &mut bytes)?;

        let (prefix_bytes, int_bytes) = {
            let (hd, tl) = bytes.split_at(size_of::<u8>());
            (hd.try_into().unwrap(), tl.try_into().unwrap())
        };

        let prefix = u8::from_ne_bytes(prefix_bytes);
        let int = i32::from_ne_bytes(int_bytes);
        if prefix == 0 {
            Ok(Self::Code(int))
        } else {
            Ok(Self::Signal(int))
        }
    }

    fn from_status(status: ExitStatus) -> Self {
        if let Some(code) = status.code() {
            Self::Code(code)
        } else {
            Self::Signal(status.signal().unwrap())
        }
    }
}
