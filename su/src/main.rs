use std::{ffi::OsString, path::PathBuf, process, sync::atomic::Ordering};

use sudo_common::{error::Error, Environment};
use sudo_exec::{ExitReason, RunOptions};
use sudo_log::user_warn;
use sudo_pam::{CLIConverser, PamContext, PamError, PamErrorType};
use sudo_system::{Group, Process, User};

use crate::cli::{SuAction, SuOptions};

mod cli;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct SuContext {
    command: PathBuf,
    options: SuOptions,
    environment: Environment,
    user: User,
    group: Group,
    process: Process,
}

impl SuContext {
    fn from_env(options: SuOptions) -> Result<SuContext, Error> {
        let process = sudo_system::Process::new();

        let environment = Environment::default();
        let user = User::from_name(&options.user)?
            .ok_or_else(|| Error::UserNotFound(options.user.clone()))?;

        let group = match (&options.group, &options.supp_group) {
            (Some(group), _) | (_, Some(group)) => {
                Group::from_name(group)?.ok_or_else(|| Error::GroupNotFound(group.to_owned()))
            }
            _ => {
                Group::from_gid(user.gid)?.ok_or_else(|| Error::GroupNotFound(user.gid.to_string()))
            }
        }?;

        // the shell specified with --shell
        // the shell specified in the environment variable SHELL, if the --preserve-environment option is used
        // the shell listed in the passwd entry of the target user
        let command = options
            .shell
            .as_ref()
            .cloned()
            .or_else(|| environment.get(&OsString::from("SHELL")).map(|v| v.into()))
            .unwrap_or(user.home.clone());

        Ok(SuContext {
            command,
            options,
            environment,
            user,
            group,
            process,
        })
    }
}

impl RunOptions for SuContext {
    fn command(&self) -> &PathBuf {
        &self.command
    }

    fn arguments(&self) -> &Vec<String> {
        &self.options.arguments
    }

    fn chdir(&self) -> Option<&std::path::PathBuf> {
        None
    }

    fn is_login(&self) -> bool {
        self.options.login
    }

    fn user(&self) -> &sudo_system::User {
        &self.user
    }

    fn group(&self) -> &sudo_system::Group {
        &self.group
    }

    fn pid(&self) -> i32 {
        self.process.pid
    }
}

fn authenticate(user: &str) -> Result<PamContext<CLIConverser>, Error> {
    let mut pam = PamContext::builder_cli(false)
        .target_user(user)
        .service_name("su")
        .build()?;

    pam.mark_silent(true);
    pam.mark_allow_null_auth_token(false);

    pam.set_user(user)?;

    let mut max_tries = 3;
    let mut current_try = 0;

    loop {
        current_try += 1;
        match pam.authenticate() {
            // there was no error, so authentication succeeded
            Ok(_) => break,

            // maxtries was reached, pam does not allow any more tries
            Err(PamError::Pam(PamErrorType::MaxTries, _)) => {
                return Err(Error::MaxAuthAttempts(current_try));
            }

            // there was an authentication error, we can retry
            Err(PamError::Pam(PamErrorType::AuthError, _)) => {
                max_tries -= 1;
                if max_tries == 0 {
                    return Err(Error::MaxAuthAttempts(current_try));
                } else {
                    user_warn!("Authentication failed, try again.");
                }
            }

            // there was another pam error, return the error
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    pam.validate_account()?;
    pam.open_session()?;

    Ok(pam)
}

fn run(options: SuOptions) -> Result<(), Error> {
    let mut pam = authenticate(&options.user)?;

    let context = SuContext::from_env(options)?;

    // run command and return corresponding exit code
    let environment = context.environment.clone();
    let pid = context.process.pid;

    let (reason, emulate_default_handler) = sudo_exec::run_command(context, environment)?;

    // closing the pam session is best effort, if any error occurs we cannot
    // do anything with it
    let _ = pam.close_session();

    // Run any clean-up code before this line.
    emulate_default_handler.store(true, Ordering::SeqCst);

    match reason {
        ExitReason::Code(code) => process::exit(code),
        ExitReason::Signal(signal) => {
            sudo_system::kill(pid, signal)?;
        }
    }

    Ok(())
}

fn main() {
    let su_options = SuOptions::from_env().unwrap();

    match su_options.action {
        SuAction::Help => {
            println!("Usage: su [options] [-] [<user> [<argument>...]]");
            std::process::exit(0);
        }
        SuAction::Version => {
            eprintln!("sudo-rs {VERSION}");
            std::process::exit(0);
        }
        SuAction::Run => {
            if let Err(error) = run(su_options) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    };
}
