use clap::Parser;
use std::{net::Ipv4Addr, str::FromStr};

#[derive(Parser)]
struct Cli
{
    #[clap(short, long)]
    resolver: Option<Ipv4Addr>,
    #[arg(required = true)]
    cname: String,
}

#[derive(Debug)]
enum DiggerError
{
    /* Could not find system default resolver */
    ResolverNotFound,
}

const RESOLV_CONF : &str = "/etc/resolv.conf";

fn dump_arguments(args: &Cli)
{
    println!("Configuration:");
    match args.resolver {
        Some(r) => println!("    Resolver: {}", r),
        None => println!("    Resolver: /etc/resolv.conf"),
    }
    println!("    CNAME: {}", args.cname);
}

fn get_system_resolver() -> Result<Ipv4Addr, DiggerError>
{
    /* https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/read_lines.html */
    let lines : Vec<String> = std::fs::read_to_string(RESOLV_CONF)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

    /* Find the first `nameserver` line */
    for line in lines {
        if line.starts_with("nameserver") {
            match line.split(' ').last() {
                Some(s) => { return Ok(Ipv4Addr::from_str(s).unwrap()) },
                None => { continue }
            };
        }
    }

    Err(DiggerError::ResolverNotFound)
}

/* Make sure our arguments are in a sane state */
fn sanitize_arguments(mut args: Cli) -> Cli {
    /* Resolver is optional. If it does not exist, we use the system's default one. */
    args.resolver = match args.resolver {
        Some(r) => Some(r),
        None => {
            Some(get_system_resolver().unwrap())
        }
    };
    args
}

fn banner()
{
    println!(r" _____                                                               _____");
    println!(r"( ___ )                                                             ( ___ )");
    println!(r" |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   |");
    println!(r" |   |     _____                                                     |   |");
    println!(r" |   |  __|__   |__    ____    ______    ______    ______    _____   |   |");
    println!(r" |   | |     \     |  |    |  |   ___|  |   ___|  |   ___|  |     |  |   |");
    println!(r" |   | |      \    |  |    |  |   |  |  |   |  |  |   ___|  |     \  |   |");
    println!(r" |   | |______/  __|  |____|  |______|  |______|  |______|  |__|\__\ |   |");
    println!(r" |   |    |_____|                                                    |   |");
    println!(r" |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___|");
    println!(r"(_____)                                                             (_____)");
    println!();
}

fn main() -> Result<(), DiggerError> {
    banner();

    let mut args = Cli::parse();
    args = sanitize_arguments(args);

    dump_arguments(&args);
    Ok(())
}
