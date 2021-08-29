use std::{io::Write, os::unix::prelude::CommandExt, process::Command};

use crate::core::{
    common::{Error, ErrorType, Result},
    state::State,
};

use crate::oci::spec::Hook;

pub fn exec_hook(hook: &Hook, state: &State) -> Result<i32> {
    let mut hook_command = Command::new(&hook.path);

    let arg0 = hook.args.as_ref().unwrap()[0].clone();
    let args = hook.args.as_ref().unwrap()[1..].to_vec();
    hook_command.arg0(&arg0).args(&args);

    let mut hook_process: std::process::Child = hook_command
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| Error { msg: err.to_string(), err_type: ErrorType::Runtime })?;

    // Provide container state to the hook
    // NOTE: the "pid" is the only important field for the libnetwork hook
    if let Some(mut stdin) = hook_process.stdin.as_ref() {
        let state_json = serde_json::to_string(state).unwrap();
        stdin.write(state_json.as_bytes()).map_err(|_| Error { msg: String::from("error writing to hook stdin"), err_type: ErrorType::Runtime })?;
    }

    let status = hook_process.wait().map_err(|_| Error { msg: String::from("error hook execution"), err_type: ErrorType::Runtime })?;
    match status.code() {
        Some(c) => Ok(c),
        None => Err(Error { msg: String::from("hook interrupted by signal"), err_type: ErrorType::Runtime }),
    }
}
