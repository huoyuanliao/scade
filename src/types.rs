use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub type Port = u16;
pub type PortSet = HashSet<Port>;
pub type FailCounts = [u32; 4];
pub type Protocol = u8;
pub type PortIpSet = HashMap<Port, IpSet>;
pub type IpSet = HashSet<Ipv4Addr>;
pub type IpFailCounts = HashMap<Ipv4Addr, FailCounts>;

pub enum PortType {
    SERVICE = 0,
    MALWARE = 1,
    OTHER = 2,
    ZERO = 3,
}
