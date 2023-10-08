#![allow(unused)] // TODO

use clap::Parser;
use std::{net::Ipv4Addr, net::UdpSocket, str::FromStr};
use socket::{htons,htonl,ntohs,ntohl};

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

/* https://www.rfc-editor.org/rfc/rfc1035
*
*                                   1  1  1  1  1  1
*     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |                      ID                       |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |                    QDCOUNT                    |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |                    ANCOUNT                    |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |                    NSCOUNT                    |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*   |                    ARCOUNT                    |
*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct DnsHeader {
    id : u16,
    cfg : u16,
    qdcount : u16,
    ancount : u16,
    nscount : u16,
    arcount : u16,
}

enum DnsOperations {
    Query,
    IQuery,
    Status,
}

enum DnsType {
    Address,
    NameServer,
    MailDestination,
    MailForwarder,
    CName,
    StartOfAuthority,
    MailBox,
    MailGroup,
    MailRename,
    Null,
    WellKnownService,
    Pointer,
    HostInformation,
    MailboxInformation,
    MailExchange,
    Text,
    AXFR,
    MAILB,
    MAILA,
    All,
}

impl DnsType {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Address => 1,
            Self::NameServer => 2,
            Self::MailDestination => 3,
            Self::MailForwarder => 4,
            Self::CName => 5,
            Self::StartOfAuthority => 6,
            Self::MailBox => 7,
            Self::MailGroup => 8,
            Self::MailRename => 9,
            Self::Null => 10,
            Self::WellKnownService => 11,
            Self::Pointer => 12,
            Self::HostInformation => 13,
            Self::MailboxInformation => 14,
            Self::MailExchange => 15,
            Self::Text => 16,
            Self::AXFR => 252,
            Self::MAILA => 253,
            Self::MAILB => 254,
            Self::All => 255,
        }
    }

    fn from_u8(v: u8) -> DnsType {
        match v {
            1 => Self::Address,
            2 => Self::NameServer,
            3 => Self::MailDestination,
            4 => Self::MailForwarder,
            5 => Self::CName,
            6 => Self::StartOfAuthority,
            7 => Self::MailBox,
            8 => Self::MailGroup,
            9 => Self::MailRename,
            10 => Self::Null,
            11 => Self::WellKnownService,
            12 => Self::Pointer,
            13 => Self::HostInformation,
            14 => Self::MailboxInformation,
            15 => Self::MailExchange,
            16 => Self::Text,
            252 => Self::AXFR,
            253 => Self::MAILA,
            254 => Self::MAILB,
            255 => Self::All,
            _ => {
                println!("E: unknown DNS type: {}", v);
                std::process::exit(1);
            }
        }
    }
}

enum DnsClass {
    Internet,
    CSNET,
    CHAOS,
    Hesiod,
}

impl DnsClass {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Internet => 1,
            Self::CSNET => 2,
            Self::CHAOS => 3,
            Self::Hesiod => 4,
        }
    }

    fn from_u8(v: u8) -> DnsClass {
        match v {
            1 => Self::Internet,
            2 => Self::CSNET,
            3 => Self::CHAOS,
            4 => Self::Hesiod,
            _ => {
                println!("E: unknown DNS class {}", v);
                std::process::exit(1);
            }
        }
    }
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader { id: 0, cfg: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 }
    }

    fn qr(&self) -> bool {
        self.cfg & 0x1 != 0
    }

    fn set_qr(& mut self, set: bool) {
        match set {
            true => self.cfg |= 1,
            false => self.cfg &= !1,
        }
    }

    fn opcode(&self) -> DnsOperations {
        let op = ntohs((self.cfg & 0x001E) >> 1);
        match op {
            0 => DnsOperations::Query,
            1 => DnsOperations::IQuery,
            2 => DnsOperations::Status,
            _ => {
                println!("Unknown opcode: {:x}", op);
                std::process::exit(1);
            }
        }
    }

    fn set_opcode(& mut self, op: DnsOperations) {
        self.cfg &= !0x001E;
        let mut opcode : u16 = match op {
            DnsOperations::Query => htons(0),
            DnsOperations::IQuery => htons(1),
            DnsOperations::Status => htons(2),
        };
        opcode >>= 1;
        self.cfg |= opcode;
    }

    fn get_cfg_bit(&self, offset: usize) -> bool {
       self.cfg & (1 << offset) != 0
    }

    fn set_cfg_bit(&mut self, offset: usize, set: bool) {
        let op = 1 << offset;
        if set {
            self.cfg |= op;
        } else {
            self.cfg &= !op;
        }
    }

    fn aa(&self) -> bool { self.get_cfg_bit(5) }
    fn set_aa(& mut self, set: bool) { self.set_cfg_bit(5, set); }

    fn tc(&self) -> bool { self.get_cfg_bit(6) }
    fn set_tc(& mut self, set: bool) { self.set_cfg_bit(6, set); }

    fn rd(&self) -> bool { self.get_cfg_bit(7) }
    fn set_rd(& mut self, set: bool) { self.set_cfg_bit(7, set); }

    fn ra(&self) -> bool { self.get_cfg_bit(8) }
    fn set_ra(& mut self, set: bool) { self.set_cfg_bit(8, set); }

    fn rcode(&self) -> u8 {
        ntohs((self.cfg & 0xF000) >> 12) as u8
    }

    fn set_rcode(& mut self, rc: u8) {
        self.cfg &= 0x0FFF;
        self.cfg |= htons(rc as u16) << 12;
    }
}

fn build_dns_request(resolver: Ipv4Addr, port: u16, cname: String)
{
    let mut header = DnsHeader::new();
    header.id = 1;
    header.set_opcode(DnsOperations::Query);
    header.qdcount = 1;
}

fn main() -> Result<(), DiggerError> {
    banner();

    let args = DiggerArguments::parse();
    let parameters = sanitize_arguments(args);

    parameters.dump();

    let socket = UdpSocket::bind("127.0.0.1:0").expect("Cannot bind to UDP port");
    println!("Opened socket at {}", socket.local_addr()
                                        .expect("Could not get socket address"));

    build_dns_request(parameters.resolver, parameters.port, parameters.cname);
    // build DNS packet in a buffer
    // socket.send_to(buffer, SockAddr(resolver, port))

    Ok(())
}
