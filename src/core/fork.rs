use nix::sched::{clone, CloneFlags};

use crate::core::common::{Error, ErrorType, Result};

pub fn clone_child(child_fun: impl FnMut() -> isize) -> Result<nix::unistd::Pid> {
    const STACK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
    let ref mut stack: [u8; STACK_SIZE] = [0; STACK_SIZE];

    let clone_flags = CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS;

    let child = clone(Box::new(child_fun), stack, clone_flags, None);

    return child.map_err(|err| Error {
        msg: format!("error clone(): {}", err.to_string()),
        err_type: ErrorType::Runtime,
    });
}
