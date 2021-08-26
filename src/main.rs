use clap::{App, Arg, SubCommand};

pub fn main() {
    let matches = App::new("pura")
        .version("0.1.0")
        .author("penumbra23 <glbranimir@gmail.com>")
        .about("containe runtime")
        .arg(Arg::with_name("root").long("root").takes_value(true))
        .arg(Arg::with_name("log").long("log").takes_value(true))
        .arg(
            Arg::with_name("log-format")
                .long("log-format")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("create")
                .arg(
                    Arg::with_name("bundle")
                        .long("bundle")
                        .short("b")
                        .takes_value(true)
                        .required(true)
                        .help("A cool file"),
                )
                .arg(
                    Arg::with_name("pid-file")
                        .long("pid-file")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("console-socket")
                        .long("console-socket")
                        .takes_value(true),
                )
                .arg(Arg::with_name("id").required(true)),
        )
        .subcommand(SubCommand::with_name("start").arg(Arg::with_name("id").required(true)))
        .subcommand(
            SubCommand::with_name("kill")
                .arg(Arg::with_name("id").required(true))
                .arg(Arg::with_name("signal")),
        )
        .subcommand(SubCommand::with_name("delete").arg(Arg::with_name("id").required(true)))
        .subcommand(SubCommand::with_name("state").arg(Arg::with_name("id").required(true)))
        .get_matches();
}