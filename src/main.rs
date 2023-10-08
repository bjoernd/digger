use clap::Parser;
use std::{net::Ipv4Addr, str::FromStr};

/// A DNS client
#[derive(Parser)]
struct DiggerArguments
{
    /// IP address of the resolver to use
    #[clap(short, long)]
    resolver: Option<Ipv4Addr>,
    /// UDP port to use to send request
    #[clap(short, long, default_value_t = 53)]
    port: u16,
    /// CNAME to query
    #[arg(required = true)]
    cname: String,
}

struct DiggerSettings {
    resolver: Ipv4Addr,
    port: u16,
    cname: String,
}

impl DiggerSettings {
    fn dump(&self)
    {
        println!("Configuration:");
        println!("    Resolver: {}", self.resolver);
        println!("    Port    : {}", self.port);
        println!("    CNAME   : {}", self.cname);
    }
}

#[derive(Debug)]
enum DiggerError
{
    /* Could not find system default resolver */
    ResolverNotFound,
}

impl DiggerError {
    fn to_str(&self) -> &str {
        match self {
            DiggerError::ResolverNotFound => {
                "Could not determine system resolver."
            }
        }
    }
}

const RESOLV_CONF : &str = "/etc/resolv.conf";

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
fn sanitize_arguments(args: DiggerArguments) -> DiggerSettings {

    /* Resolver is optional. If it does not exist, we use the system's default one. */
    let resolver = match args.resolver {
        Some(r) => r,
        None => match get_system_resolver() {
            Ok(t) => t,
            Err(e) => {
                println!("{}", e.to_str());
                std::process::exit(e as i32);
            }
        }
    };

    DiggerSettings{ resolver, port: args.port, cname: args.cname }
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

    let args = DiggerArguments::parse();
    let parameters = sanitize_arguments(args);

    parameters.dump();
    Ok(())
}
