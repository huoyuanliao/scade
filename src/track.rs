use std::net::IpAddr;
use std::collections::HashMap;
use std::collections::HashSet;

type IpSet = HashSet<IpAddr>;
type FailCounts = [u32; 4];
type Port = u16;
type PortIpSet = HashMap<Port, Box<IpSet>>;

struct Tracker {
    tracker_ip: IpAddr,
    total_fail_counts: FailCounts,

    ip_fail_counts: HashMap<IpAddr, FailCounts>,
    port_other_list:PortIpSet,
    port_icmp_list: Box<IpSet>,

    tcp_sm_list: PortIpSet,
    udp_sm_list: PortIpSet,
}