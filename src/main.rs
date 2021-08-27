mod core;
mod oci;

use crate::core::common::exit_msg;

use clap::{App, Arg, ArgMatches, SubCommand};

use crate::core::common::exit;

pub fn create(args: &ArgMatches) {}
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
        ("create", create_cmd) => create(create_cmd.unwrap()),
        ("start", start_cmd) => start(start_cmd.unwrap()),
        ("delete", delete_cmd) => delete(delete_cmd.unwrap()),
        ("kill", kill_cmd) => kill(kill_cmd.unwrap()),
        ("state", state_cmd) => state(state_cmd.unwrap()),
        (_, _) => exit_msg(1, "unknown container command"),
    }

    exit(0);
}
