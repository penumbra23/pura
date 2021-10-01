use nix::{
    sched::{clone, CloneFlags},
    sys::signal::{kill, Signal},
    unistd::Pid,
};

use crate::{core::common::{Error, ErrorType, Result}, oci::spec::Namespace};

fn to_flags(namespace: &Namespace) -> CloneFlags {
    match namespace.namespace.as_str() {
        "pid" => CloneFlags::CLONE_NEWPID,
        "network" | "net" => CloneFlags::CLONE_NEWNET,
        "mount" | "mnt" => CloneFlags::CLONE_NEWNS,
        "ipc" => CloneFlags::CLONE_NEWIPC,
        "uts" => CloneFlags::CLONE_NEWUTS,
        "user" => CloneFlags::CLONE_NEWUSER,
        "cgroup" => CloneFlags::CLONE_NEWCGROUP,
        _ => panic!("unknown namespace {}", namespace.namespace),
    }
}

pub fn clone_child(child_fun: impl FnMut() -> isize, namespaces: &Vec<Namespace>) -> Result<nix::unistd::Pid> {
    const STACK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
    let ref mut stack: [u8; STACK_SIZE] = [0; STACK_SIZE];

    let spec_namespaces = namespaces.into_iter()
        .map(|ns| to_flags(ns))
        .reduce(|a, b| a | b);

    let clone_flags = match spec_namespaces {
        Some(flags) => flags,
        None => CloneFlags::empty(),
    };

    let child = clone(Box::new(child_fun), stack, clone_flags, None);

    return child.map_err(|err| Error {
        msg: format!("error clone(): {}", err.to_string()),
        err_type: ErrorType::Runtime,
    });
}

pub fn signal(pid: Pid, sig: i32) -> Result<()> {
    kill(pid, to_signal(sig)).map_err(|err| Error {
        msg: format!("error signal {}", err.to_string()),
        err_type: ErrorType::Runtime,
    })?;
    Ok(())
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
