use std::{ffi::CString, os::unix::prelude::AsRawFd, path::Path};

use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
    unistd::{chdir, execvp, setgid, sethostname, setuid, Gid, Pid, Uid},
};

use crate::{
    core::common::{exit, exit_msg, Result},
    oci::spec::{Namespace, Spec},
};

use super::{
    filesystem::{
        create_default_devices, create_devices, mount_devices, mount_rootfs, pivot_rootfs,
        symlinks_defaults,
    },
    fork::clone_child,
    hooks::exec_hook,
    ipc::{IpcChannel, IpcChild},
    state::State,
    terminal::{Pty, PtySocket},
};

/// Fork a child container process and initializes the container.
/// Waits for the start command to trigger the user-defined process
///
/// # Arguments
///
/// * `spec` - OCI specification instance
/// * `state` - Loaded state of the container
/// * `namespaces` - Vector of namespaces passed to `clone`
/// * `init_lock_path` - String path to the initial lock Unix domain socket (used to inform the parent when the child finishes container preparation)
/// * `sock_path` - Container's main Unix domain socket (used for the start command)
/// * `pty_socket` - Optional: if the user specified a terminal
///
/// # Returns
///
/// Pid of the running container process inside the root PID namespace
///
pub fn fork_container(
    spec: &Spec,
    state: &State,
    namespaces: &Vec<Namespace>,
    init_lock_path: &String,
    sock_path: &String,
    pty_socket: &Option<PtySocket>,
) -> Result<Pid> {
    let pid = clone_child(
        || {
            let init_lock_child = IpcChild::new(&init_lock_path).unwrap();

            let mut ipc_channel = match IpcChannel::new(&sock_path) {
                Ok(ch) => ch,
                Err(err) => {
                    init_lock_child
                        .notify(&format!("error:ipc:{}", err))
                        .unwrap();
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
                                    ipc_channel.send(&format!("error:ns:{}", err)).unwrap();
                                    exit_msg(1, format!("error:ns:{}", err));
                                }
                            };

                            if let Err(err) = setns(fd.as_raw_fd(), CloneFlags::empty()) {
                                ipc_channel.send(&format!("error:ns:{}", err)).unwrap();
                                exit_msg(1, format!("error:ns:{}", err));
                            }
                        }
                    }
                }
            }

            // Accept the create process
            ipc_channel.accept().unwrap();

            let rootfs = Path::new(&spec.root.path);

            let _: Option<Pty> = if let Some(pty_sock) = &pty_socket {
                match Pty::new() {
                    Ok(pty) => {
                        pty.connect().unwrap();
                        pty_sock.send_pty(&pty).unwrap();
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
                ipc_channel.send(&format!("error:rootfs:{}", err)).unwrap();
                exit_msg(1, format!("error:rootfs:{}", err));
            }

            if let Some(mounts) = &spec.mounts {
                if let Err(err) = mount_devices(&mounts, rootfs) {
                    ipc_channel.send(&format!("error:devices:{}", err)).unwrap();
                    exit_msg(1, format!("error:devices:{}", err));
                }
            }

            if let Some(linux) = &spec.linux {
                if let Some(devices) = &linux.devices {
                    if let Err(err) = create_devices(&devices, rootfs) {
                        ipc_channel.send(&format!("error:devices:{}", err)).unwrap();
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
                            println!("[ERROR]: {} on ipc channel msg", msg);
                            exit(1);
                        }
                    }
                    Err(err) => {
                        println!("[ERROR]: {} on ipc channel error", err);
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
                        println!("[ERROR]: {} execvp", err);
                        exit(1);
                    }
                }
            }

            0
        },
        &namespaces,
    );

    pid
}
