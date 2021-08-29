use std::{io::Write, os::unix::prelude::CommandExt, process::Command};

use crate::{core::state::State, oci::spec::Hook};

pub fn exec_hook(hook: &Hook, state: &State) {
    let hook_cmd = hook.path.clone();

    let mut hook_command = Command::new(hook_cmd);

    let arg0 = hook.args.as_ref().unwrap()[0].clone();
    let args = hook.args.as_ref().unwrap()[1..].to_vec();
    hook_command.arg0(&arg0).args(&args);

    let hook_process: std::process::Child = hook_command
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Provide container state to the hook
    // NOTE: the "pid" is the only important field for the libnetwork hook
    if let Some(mut stdin) = hook_process.stdin.as_ref() {
        let state_json = serde_json::to_string(state).unwrap();
        stdin.write(state_json.as_bytes()).unwrap();
    }

    let output = hook_process.wait_with_output().unwrap();
}
