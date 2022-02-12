mod core;
mod oci;

use std::convert::TryInto;
use std::{convert::TryFrom, io::Write, path::Path};

use crate::core::container::fork_container;
use crate::core::hooks::exec_hook;
use crate::core::ipc::IpcChannel;
use crate::core::logger::ContainerLogger;
use crate::core::state::State as ContainerState;

use crate::core::{
    common::{exit, exit_msg},
    fork::signal,
    ipc::IpcParent,
    state::Status,
    terminal::PtySocket,
};
use crate::oci::spec::Namespace;

use clap::{App, Arg, SubCommand};
use log::{error, warn, Level};
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use oci::{
    ops::{Create, Delete, Kill, Start, State},
    spec::Spec,
};

use anyhow::Result;
use nix;
use oci_spec::runtime::Mount;
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType,
    Spec as SpecConfigOci,
};
use serde_json::to_writer_pretty;
use std::fs::File;
use std::path::PathBuf;

const PURA_ROOT_PATH: &str = "/tmp/pura";

pub struct SpecConfig {
    rootless: bool
}

pub fn get_default() -> Result<SpecConfigOci> {
    Ok(SpecConfigOci::default())
}

pub fn get_rootless() -> Result<SpecConfigOci> {
    // Remove network and user namespace from the default spec
    let mut namespaces: Vec<LinuxNamespace> = oci_spec::runtime::get_default_namespaces()
        .into_iter()
        .filter(|ns| {
            ns.typ() != LinuxNamespaceType::Network && ns.typ() != LinuxNamespaceType::User
        })
        .collect();

    // Add user namespace
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()?,
    );

    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();

    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .uid_mappings(vec![LinuxIdMappingBuilder::default()
            .host_id(uid)
            .container_id(0_u32)
            .size(1_u32)
            .build()?])
        .gid_mappings(vec![LinuxIdMappingBuilder::default()
            .host_id(gid)
            .container_id(0_u32)
            .size(1_u32)
            .build()?])
        .build()?;

    // Prepare the mounts

    let mut mounts: Vec<Mount> = oci_spec::runtime::get_default_mounts();
    for mount in &mut mounts {
        if mount.destination().eq(Path::new("/sys")) {
            mount
                .set_source(Some(PathBuf::from("/sys")))
                .set_typ(Some(String::from("none")))
                .set_options(Some(vec![
                    "rbind".to_string(),
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ]));
        } else {
            let options: Vec<String> = mount
                .options()
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .filter(|&o| !o.starts_with("gid=") && !o.starts_with("uid="))
                .map(|o| o.to_string())
                .collect();
            mount.set_options(Some(options));
        }
    }

    let mut spec = get_default()?;
    spec.set_linux(Some(linux)).set_mounts(Some(mounts));
    Ok(spec)
}

pub fn spec(spec: SpecConfig) -> Result<()> {
    let spec = if spec.rootless {
        get_rootless()?
    } else {
        get_default()?
    };

    to_writer_pretty(&File::create("config.json")?, &spec)?;
    Ok(())
}

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

    let pty_socket = if has_terminal {
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

    let namespaces: Vec<Namespace> = match &spec.linux {
        Some(linux) => linux.namespaces.clone().unwrap_or(Vec::new()),
        None => Vec::new(),
    };

    let pid = fork_container(
        &spec,
        &state,
        &namespaces,
        &init_lock_path,
        &sock_path,
        &pty_socket,
    )
    .expect("error forking container");

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
            }
            Err(err) => {
                error!("{}", err);
                signal(pid, 9).unwrap();
            }
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
        match pty_socket.unwrap().close() {
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

    let pid = Pid::from_raw(state.pid.try_into().unwrap());

    if state.status != Status::Created {
        error!("container isn't created");
        signal(pid, 9).unwrap();
        exit(1);
    }

    if let Some(hooks) = &spec.hooks {
        if let Some(prestart) = &hooks.prestart {
            for pre_hook in prestart {
                if exec_hook(pre_hook, &state).is_err() {
                    error!("prestart hook failed");
                    signal(pid, 9).unwrap();
                    exit(1);
                }
            }
        }

        if let Some(start_container) = &hooks.start_container {
            for hook in start_container {
                if exec_hook(hook, &state).is_err() {
                    error!("startContainer hook failed");
                    signal(pid, 9).unwrap();
                    exit(1);
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

    let state = match ContainerState::try_from(state_path.as_path()) {
        Ok(state) => state,
        Err(err) => {
            error!("error reading state {}", err);
            exit(1);
        }
    };

    let bundle = &state.bundle;
    let spec = match Spec::try_from(Path::new(&bundle).join("config.json").as_path()) {
        Ok(spec) => spec,
        Err(err) => {
            error!("{}", err);
            exit(1);
        }
    };

    // Just log the error
    if state.status != Status::Stopped {
        error!("[DELETE] container isn't created in {:?} for {:?}", delete.root, delete.id);
    }

    if let Some(hooks) = &spec.hooks {
        if let Some(poststop) = &hooks.poststop {
            for hook in poststop {
                exec_hook(hook, &state).expect("error executing poststop hook");
            }
        }
    }

    if std::fs::remove_dir_all(Path::new(&delete.root).join(&delete.id)).is_err() {
        warn!("failed to delete container root");
    }
}

pub fn kill(kill: Kill) {
    let state_path = Path::new(&kill.root).join(&kill.id);
    let mut state = ContainerState::try_from(state_path.as_path()).unwrap();

    if state.status != Status::Created && state.status != Status::Running {
        error!(
            "[KILL] error can't kill container that isn't created or running: {:?}",
            &state
        );
    }

    if let Err(err) = signal(Pid::from_raw(state.pid as i32), kill.signal) {
        error!("error killing container: {}", err);
        exit(1);
    }

    match waitpid(Pid::from_raw(state.pid as i32), Some(WaitPidFlag::WNOHANG)) {
        Ok(res) => match res {
            WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                state.status = Status::Stopped;
                state.save(state_path.as_path()).unwrap();
            }
            _ => (),
        },
        Err(err) => {
            if err.as_errno() != Some(Errno::ECHILD) {
                error!("error polling pid status: {}", err);
                exit(1);
            }
        }
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
            SubCommand::with_name("spec")
                .arg(
                    Arg::with_name("rootless")
                        .long("rootless")
                        .required(false)
                        .takes_value(false)
                        .help("spec container as rootless mode")
                ),
        )
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
        ("spec", _spec_cmd) => {
            // spec(SpecConfig {
            //     rootless: matches.is_present("rootless")
            // }).map_err(|err| println!("{:?}", err));
            match spec(SpecConfig {
                rootless: matches.is_present("rootless")
            }) {
                Err(e) => println!("{:?}", e),
                _ => () 
            }
        }
        ("create", create_cmd) => {
            let args = create_cmd.unwrap();
            create(Create {
                id: args
                    .value_of("id")
                    .expect("id is required")
                    .to_string(),
                bundle: args
                    .value_of("bundle")
                    .expect("bundle is required")
                    .to_string(),
                console_socket: args
                    .value_of("console-socket")
                    .map(|s| Some(s.to_string()))
                    .unwrap_or(None),
                root: args.value_of("root").unwrap_or(PURA_ROOT_PATH).to_string(),
                pid_file: args.value_of("pid-file").map(|p| p.to_string()),
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
