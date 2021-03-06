use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub type Port = u16;
pub type PortSet = HashSet<Port>;
pub type FailCounts = [usize; 4];
pub type Protocol = u8;
pub type PortIpSet = HashMap<Port, IpSet>;
pub type IpSet = HashSet<Ipv4Addr>;
pub type IpFailCounts = HashMap<Ipv4Addr, FailCounts>;

#[derive(Copy, Clone, PartialEq)]
pub enum PortType {
    SERVICE = 0,
    MALWARE = 1,
    OTHER = 2,
    ZERO = 3,
    GENERIC = 4,
    NONE = 5,
}

#[derive(Copy, Clone, PartialEq)]
pub enum IpSweep {
    IPSweepNarrow = 0,
    IPSweepModerate = 1,
    IPSweepBroad = 2,
    IPSweepNone = 3,
}

pub static TRIGGER_REG: &str = r"\s*(?:(\d+)=)?(\w+)\+(non-)?(\w+)\s*";

#[derive(Copy, Clone, PartialEq)]
pub struct Trigger {
    pub catnum: u8,
    pub ipsweep: IpSweep,
    pub portfocus: PortType,
    pub negative: bool,
    pub curpf: PortType,
}

impl Trigger {
    pub fn new(catnum: u8, ips: IpSweep, pf: PortType, negative: bool) -> Self {
        Trigger {
            catnum: catnum,
            ipsweep: ips,
            portfocus: pf,
            negative: negative,
            curpf: PortType::NONE,
        }
    }
}
