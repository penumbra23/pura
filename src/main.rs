mod core;
mod oci;

use std::{convert::TryFrom, io::Write, path::Path};

use crate::core::{common::{exit, exit_msg}, fork::{clone_child, signal}, hooks::exec_hook, ipc::IpcParent, state::{State, Status}, terminal::PtySocket};

use clap::{App, Arg, ArgMatches, SubCommand};
use log::{error, info};
use oci::{ops::Create, spec::Spec};

pub fn create(create: Create) {
    let container_id = create.id;
    let root = create.root;
    let bundle = create.bundle;
    let console_socket = create.console_socket;

    let spec = match Spec::try_from(Path::new(&bundle).join("config.json").as_path()) {
        Ok(spec) => spec,
        Err(err) => {
            error!("{}", err);
            exit(1);
        }
    };

    let has_terminal = if let Some(process) = &spec.process {
        if let Some(terminal) = process.terminal {
            terminal == true
        } else {
            false
        }
    } else {
        false
    };

    let mut pid_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(create.pid_file)
        .unwrap();

    let state = State::new(&container_id.to_string(), 0, &bundle.to_string());
    let container_path_str = format!("{}/{}", &root, container_id);
    let container_path = Path::new(&container_path_str);
    state.save(container_path).unwrap();

    let pty_console = if has_terminal {
        match PtySocket::new(&console_socket.expect("no console-socket arg")) {
            Ok(socket_fd) => Some(socket_fd),
            Err(err) => {
                exit_msg(1, format!("error setting up socket for console_fd {}", err));
            }
        }
    } else {
        None
    };

    let init_lock_path = format!("{}/init.sock", container_path_str);
    let init_lock = IpcParent::new(&init_lock_path).unwrap();

    let pid = clone_child(|| 0).expect("error forking child");

    // Wait until child prepares for command execution
    match init_lock.wait() {
        Ok(str) => {
            if str.eq("0") {
                info!("child process prepared successfully");
            } else {
                error!("child process error {}", str);
                exit(2);
            }
        }
        Err(err) => {
            error!("error with init_lock {}", err);
            exit(2);
        }
    }
    init_lock.close().unwrap();

    // Write process pid to pid_file
    pid_file.write_all(format!("{}", pid).as_bytes()).unwrap();

    // Update state
    let mut state = State::try_from(container_path).unwrap();
    state.status = Status::Created;
    state.pid = i32::from(pid) as u64;
    state.save(container_path).unwrap();

    // TODO: execute all hooks
    if let Some(hooks) = &spec.hooks {
        if let Some(prestart) = &hooks.prestart {
            for pre_hook in prestart {
                exec_hook(pre_hook, &state).expect("prestart hook failed");
                signal(pid, 9).unwrap();
            }
        }

        if let Some(create_runtime) = &hooks.create_runtime {
            for cr_hook in create_runtime {
                exec_hook(cr_hook, &state).expect("create_runtime hook failed");
                signal(pid, 9).unwrap();
            }
        }
    }

    // Parent cleanup
    if has_terminal {
        match pty_console.unwrap().close() {
            Ok(_) => (),
            Err(err) => error!("error closing console-socket: {}", err),
        }
    }
}

pub fn start(args: &ArgMatches) {}

pub fn delete(args: &ArgMatches) {}

pub fn kill(args: &ArgMatches) {}

pub fn state(args: &ArgMatches) {}

pub fn main() {
    let matches = App::new("pura")
        .version("0.1.0")
        .author("penumbra23 <glbranimir@gmail.com>")
        .about("Lightweight, Rust-based and OCI-compliant container runtime")
        .arg(
            Arg::with_name("root")
                .long("root")
                .takes_value(true)
                .help("runtime root for the container state"),
        )
        .arg(
            Arg::with_name("log")
                .long("log")
                .takes_value(true)
                .help("location of the log file"),
        )
        .arg(
            Arg::with_name("log-format")
                .long("log-format")
                .takes_value(true)
                .help("log format (e.q. json, txt)"),
        )
        // Subcommands
        .subcommand(
            SubCommand::with_name("create")
                .arg(
                    Arg::with_name("bundle")
                        .long("bundle")
                        .short("b")
                        .takes_value(true)
                        .required(true)
                        .help("bundle directory containing container configuration"),
                )
                .arg(
                    Arg::with_name("pid-file")
                        .long("pid-file")
                        .takes_value(true)
                        .help("file to write the container process PID"),
                )
                .arg(
                    Arg::with_name("console-socket")
                        .long("console-socket")
                        .takes_value(true)
                        .help("UNIX socket to send the pty master fd, if terminal: true"),
                )
                .arg(
                    Arg::with_name("id")
                        .required(true)
                        .help("ID of the container"),
                ),
        )
        .subcommand(
            SubCommand::with_name("start").arg(
                Arg::with_name("id")
                    .required(true)
                    .help("ID of the container")
                    .help("starts the container process"),
            ),
        )
        .subcommand(
            SubCommand::with_name("kill")
                .arg(
                    Arg::with_name("id")
                        .required(true)
                        .help("ID of the container"),
                )
                .arg(
                    Arg::with_name("signal")
                        .required(true)
                        .help("signal to send to the process (e.q. SIGTERM, SIGKILL, ...)"),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete").arg(
                Arg::with_name("id")
                    .required(true)
                    .help("ID of the container"),
            ),
        )
        .subcommand(
            SubCommand::with_name("state").arg(
                Arg::with_name("id")
                    .required(true)
                    .help("ID of the container"),
            ),
        )
        .get_matches();

    match matches.subcommand() {
        ("create", create_cmd) => {
            let args = create_cmd.unwrap();
            create(Create {
                id: args.value_of("id").expect("id is required").to_string(),
                bundle: args
                    .value_of("bundle")
                    .expect("bundle is required")
                    .to_string(),
                console_socket: args
                    .value_of("console-socket")
                    .map(|s| Some(s.to_string()))
                    .unwrap_or(None),
                root: args.value_of("root").unwrap_or("/tmp/pura").to_string(),
                pid_file: args
                    .value_of("pid-file")
                    .expect("pid-file is required")
                    .to_string(),
            })
        }
        ("start", start_cmd) => start(start_cmd.unwrap()),
        ("delete", delete_cmd) => delete(delete_cmd.unwrap()),
        ("kill", kill_cmd) => kill(kill_cmd.unwrap()),
        ("state", state_cmd) => state(state_cmd.unwrap()),
        (_, _) => exit_msg(1, "unknown container command"),
    }

    exit(0);
}
