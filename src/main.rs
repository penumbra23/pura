mod core;
mod oci;

use std::convert::TryInto;
use std::os::unix::prelude::AsRawFd;
use std::{convert::TryFrom, ffi::CString, io::Write, path::Path};

use crate::core::ipc::IpcChannel;
use crate::core::logger::ContainerLogger;
use crate::core::state::State as ContainerState;

use crate::core::{
    common::{exit, exit_msg},
    filesystem::{
        create_default_devices, create_devices, mount_devices, mount_rootfs, symlinks_defaults, pivot_rootfs
    },
    fork::{clone_child, signal},
    hooks::exec_hook,
    ipc::{IpcChild, IpcParent},
    state::Status,
    terminal::{Pty, PtySocket},
};

use clap::{App, Arg, SubCommand};
use log::{Level, error, warn};
use nix::fcntl::{OFlag, open};
use nix::sched::{CloneFlags, setns};
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::unistd::{Gid, Pid, Uid, chdir, execvp, setgid, sethostname, setuid};
use oci::{
    ops::{Create, Delete, Kill, Start, State},
    spec::Spec,
};

const PURA_ROOT_PATH: &str = "/tmp/pura";

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

    let state = ContainerState::new(&container_id.to_string(), 0, &bundle.to_string());
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

    // IPC lock that waits the setup of the container IPC channel
    let init_lock_path = format!("{}/init.sock", container_path_str);
    let init_lock = IpcParent::new(&init_lock_path).unwrap();

    let sock_path = format!("{}/container.sock", container_path.display());

    let pid = clone_child(|| {
        let init_lock_child = IpcChild::new(&init_lock_path).unwrap();

        let mut ipc_channel = match IpcChannel::new(&sock_path) {
            Ok(ch) => ch,
            Err(err) => {
                init_lock_child.notify(&format!("error:ipc:{}", err)).unwrap();
                init_lock_child.close().unwrap();
                exit_msg(1, format!("error:ipc:{}", err));
            }
        };

        init_lock_child.notify(&"ok".to_string()).unwrap();
        init_lock_child.close().unwrap();

        // Bind to namespaces paths
        if let Some(linux) = &spec.linux {
            if let Some(namespaces) = &linux.namespaces {
                for ns in namespaces {
                    if let Some(path) = &ns.path {
                        let fd = match open(path.as_str(), OFlag::empty(), Mode::empty()) {
                            Ok(fd) => fd,
                            Err(err) => {
                                ipc_channel
                                    .send(&format!("error:ns:{}", err))
                                    .unwrap();
                                exit_msg(1, format!("error:ns:{}", err));
                            }
                        };

                        if let Err(err) = setns(fd.as_raw_fd(), CloneFlags::empty()) {
                            ipc_channel
                                .send(&format!("error:ns:{}", err))
                                .unwrap();
                            exit_msg(1, format!("error:ns:{}", err));
                        }
                    }
                }
            }
        }

        // Accept the create process
        ipc_channel.accept().unwrap();

        let rootfs = Path::new(&spec.root.path);

        let pty: Option<Pty> = if has_terminal {
            match Pty::new() {
                Ok(pty) => {
                    pty.connect().unwrap();
                    pty_console.as_ref().unwrap().send_pty(&pty).unwrap();
                    Some(pty)
                }
                Err(err) => {
                    ipc_channel
                        .send(&format!("error:terminal:{}", err))
                        .unwrap();
                    exit_msg(1, format!("error:terminal:{}", err));
                }
            }
        } else {
            None
        };

        // Mounts the rootfs folder with bind option
        if let Err(err) = mount_rootfs(&rootfs) {
            ipc_channel
                .send(&format!("error:rootfs:{}", err))
                .unwrap();
            exit_msg(1, format!("error:rootfs:{}", err));
        }

        if let Some(mounts) = &spec.mounts {
            if let Err(err) = mount_devices(&mounts, rootfs) {
                ipc_channel
                    .send(&format!("error:devices:{}", err))
                    .unwrap();
                exit_msg(1, format!("error:devices:{}", err));
            }
        }

        if let Some(linux) = &spec.linux {
            if let Some(devices) = &linux.devices {
                if let Err(err) = create_devices(&devices, rootfs) {
                    ipc_channel
                        .send(&format!("error:devices:{}", err))
                        .unwrap();
                    exit_msg(1, format!("error:devices:{}", err));
                }
            }
        }
        // Create default devices and mounts
        create_default_devices(&rootfs);

        // Symlinks the file descriptors of the process
        symlinks_defaults(&rootfs);

        if let Some(hooks) = &spec.hooks {
            if let Some(create) = &hooks.create_container {
                for create_hook in create {
                    if let Err(err) = exec_hook(create_hook, &state) {
                        ipc_channel
                            .send(&format!("error:hook:createContainer:{}", err))
                            .unwrap();
                        exit_msg(1, format!("error:hook:createContainer:{}", err));
                    }
                }
            }
        }

        // Wait for the hook to finish and the parent to confirm
        ipc_channel.send("before_pivot").unwrap();
        if let Ok(msg) = ipc_channel.recv() {
            if !msg.eq("ok") {
                exit_msg(1, format!("error:hook:createRuntime:{}", msg));
            }
        }

        if let Err(err) = pivot_rootfs(&rootfs) {
            ipc_channel
                .send(&format!("error:pivot_root:{}", err))
                .unwrap();
            exit_msg(1, format!("error:pivot_root:{}", err));
        }

        ipc_channel.send("after_pivot").unwrap();

        if let Some(hostname) = &spec.hostname {
            sethostname(hostname).unwrap();
        }

        // Here gets the process executed
        if let Some(process) = &spec.process {
            let cmd = &process.args.as_ref().unwrap()[0];
            let args: Vec<CString> = spec
                .process
                .as_ref()
                .unwrap()
                .args
                .as_ref()
                .unwrap()
                .iter()
                .map(|a| CString::new(a.to_string()).unwrap_or_default())
                .collect();

            let exec = CString::new(cmd.as_bytes()).unwrap();

            if let Some(envs) = &process.env {
                for (key, _) in std::env::vars() {
                    std::env::remove_var(key);
                }

                for env in envs {
                    if let Some((key, value)) = env.split_once("=") {
                        std::env::set_var(key, value);
                    }
                }
            }

            // Finish the create command
            ipc_channel.send("ready").unwrap();

            // Wait for the start command to fire start
            ipc_channel.accept().unwrap();
            match ipc_channel.recv() {
                Ok(msg) => {
                    if !msg.eq("start") {
                        println!("[ERROR]: {}", msg);
                        exit(1);
                    }
                },
                Err(err) => {
                    println!("[ERROR]: {}", err);
                    exit(1);
                }
            }

            if let Some(user) = &process.user {
                setuid(Uid::from_raw(user.uid as u32)).unwrap();
                setgid(Gid::from_raw(user.gid as u32)).unwrap();
            }

            chdir(Path::new(&process.cwd)).unwrap();
            match execvp(&exec, &args) {
                Ok(_) => (),
                Err(err) => {
                    // We can't log this error because it doesn't see the log file
                    println!("[ERROR]: {}", err.to_string());
                    exit(1);
                }
            }
        }

        0
    })
    .expect("error forking child");

    // Wait until child sets up IPC channel
    match init_lock.wait() {
        Ok(str) => {
            if !str.eq("ok") {
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

    let ipc_channel = IpcChannel::connect(&sock_path).unwrap();

    loop {
        match ipc_channel.recv() {
            Ok(msg) => {
                if msg.starts_with("error") {
                    error!("{}", msg);
                    exit(1);
                } else if msg.eq("ready") {
                    break;
                } else if msg.eq("before_pivot") {
                    if let Some(hooks) = &spec.hooks {
                        if let Some(create_runtime) = &hooks.create_runtime {
                            for cr_hook in create_runtime {
                                if exec_hook(cr_hook, &state).is_err() {
                                    error!("createRuntime hook failed");
                                    signal(pid, 9).unwrap();
                                }
                            }
                        }
                    }
                    ipc_channel.send("ok").unwrap();
                }
            },
            Err(err) => {
                error!("{}", err);
                signal(pid, 9).unwrap();
            },
        }
    }

    if let Some(pid_file_path) = create.pid_file {
        let mut pid_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(pid_file_path)
            .unwrap();
        // Write process pid to pid_file
        pid_file.write_all(format!("{}", pid).as_bytes()).unwrap();
    }

    // Update state
    let mut state = ContainerState::try_from(container_path).unwrap();
    state.status = Status::Created;
    state.pid = i32::from(pid) as u64;
    state.save(container_path).unwrap();

    // Parent cleanup
    if has_terminal {
        match pty_console.unwrap().close() {
            Ok(_) => (),
            Err(err) => error!("error closing console-socket: {}", err),
        }
    }
}

pub fn start(start: Start) {
    let container_path = Path::new(&start.root).join(&start.id);

    let mut state = ContainerState::try_from(container_path.as_path()).unwrap();

    let bundle = &state.bundle;
    let spec = match Spec::try_from(Path::new(&bundle).join("config.json").as_path()) {
        Ok(spec) => spec,
        Err(err) => {
            error!("{}", err);
            exit(1);
        }
    };

    // TODO: check state
    let pid = Pid::from_raw(state.pid.try_into().unwrap());

    if let Some(hooks) = &spec.hooks {
        if let Some(prestart) = &hooks.prestart {
            for pre_hook in prestart {
                if exec_hook(pre_hook, &state).is_err() {
                    error!("prestart hook failed");
                    signal(pid, 9).unwrap();
                }
            }
        }

        if let Some(start_container) = &hooks.start_container {
            for hook in start_container {
                if exec_hook(hook, &state).is_err() {
                    error!("startContainer hook failed");
                    signal(pid, 9).unwrap();
                }
            }
        }
    }

    let sock_path = format!("{}/container.sock", container_path.display());
    let ipc_channel = IpcChannel::connect(&sock_path).unwrap();
    ipc_channel.send(&"start".to_string()).unwrap();
    ipc_channel.close().unwrap();

    state.status = Status::Running;
    state.save(container_path.as_path()).unwrap();

    if let Some(hooks) = &spec.hooks {
        if let Some(poststart) = &hooks.poststart {
            for hook in poststart {
                if let Err(err) = exec_hook(hook, &state) {
                    warn!("poststart hook error: {}", err);
                }
            }
        }
    }
}

pub fn delete(delete: Delete) {
    let state_path = Path::new(&delete.root).join(&delete.id);

    // TODO: check state if ready for deletion
    let state = ContainerState::try_from(state_path.as_path()).unwrap();

    let bundle = &state.bundle;
    let spec = match Spec::try_from(Path::new(&bundle).join("config.json").as_path()) {
        Ok(spec) => spec,
        Err(err) => {
            error!("{}", err);
            exit(1);
        }
    };

    if let Some(hooks) = &spec.hooks {
        if let Some(poststop) = &hooks.poststop {
            for hook in poststop {
                exec_hook(hook, &state).expect("error executing poststop hook");
            }
        }
    }

    // TODO: actually delete the container
    std::fs::remove_dir_all(Path::new(&delete.root).join(&delete.id)).unwrap();
}

fn to_signal(sig: i32) -> Signal {
    match sig {
        1 => Signal::SIGHUP,
        2 => Signal::SIGINT,
        6 => Signal::SIGABRT,
        9 => Signal::SIGKILL,
        15 => Signal::SIGTERM,
        17 => Signal::SIGCHLD,
        _ => panic!("unknown signal"),
    }
}

pub fn kill(kill: Kill) {
    let state_path = Path::new(&kill.root).join(&kill.id);
    let state = ContainerState::try_from(state_path.as_path()).unwrap();

    if state.status != Status::Created && state.status != Status::Running {
        exit(1);
    }

    match nix::sys::signal::kill(
        Pid::from_raw(state.pid as i32),
        to_signal(kill.signal),
    ) {
        Ok(_) => return,
        Err(_) => exit(1),
    }
}

pub fn state(state: State) {
    let state_path = Path::new(&state.root).join(&state.id);

    let state = ContainerState::try_from(state_path.as_path()).unwrap();

    std::io::stdout()
        .write_all(&serde_json::to_string(&state).unwrap().as_bytes())
        .unwrap();
    std::io::stdout().flush().unwrap();
}

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
            SubCommand::with_name("start")
                .arg(
                    Arg::with_name("id")
                        .required(true)
                        .help("ID of the container")
                        .help("starts the container process"))
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

    let mut log_path = matches.value_of("log").map(|s| s.to_string());

    if log_path.is_none() {
        if let Some(id) = matches.value_of("id") {
            log_path = Some(format!("/tmp/pura/{}.log", id));
        } else {
            // This isn't likely to happen since each OCI runtime command has the id arg
            log_path = Some(String::from("/tmp/pura/unknown.log"));
        }
    }

    let _ = ContainerLogger::init(&log_path.unwrap(), Level::Info).unwrap();

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
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
                pid_file: args
                    .value_of("pid-file")
                    .map(|p| p.to_string()),
            })
        }
        ("start", start_cmd) => {
            let args = start_cmd.unwrap();
            start(Start {
                id: args.value_of("id").expect("id is required").to_string(),
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
            })
        }
        ("delete", delete_cmd) => {
            let args = delete_cmd.unwrap();
            delete(Delete {
                id: args.value_of("id").expect("id is required").to_string(),
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
            })
        }
        ("kill", kill_cmd) => {
            let args = kill_cmd.unwrap();
            kill(Kill {
                id: args.value_of("id").expect("id is required").to_string(),
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
                signal: args
                    .value_of("signal")
                    .expect("signal is required")
                    .parse()
                    .expect("signal expected as integer"),
            })
        }
        ("state", state_cmd) => {
            let args = state_cmd.unwrap();
            state(State {
                id: args.value_of("id").expect("id is required").to_string(),
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
            })
        }
        (_, _) => exit_msg(1, "unknown container command"),
    }

    exit(0);
}
