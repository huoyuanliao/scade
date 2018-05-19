use std::net::IpAddr;
use std::collections::HashMap;
use std::collections::HashSet;

type IpSet = HashSet<IpAddr>;
type FailCounts = [u32; 4];
type Port = u16;
type Protocol = u8;
type PortIpSet = HashMap<Port, Box<IpSet>>;
type IpFailCounts = HashMap<IpAddr, FailCounts>;

pub struct Tracker {
    tracker_ip: IpAddr,
    total_fail_counts: FailCounts,

    ip_fail_counts: IpFailCounts,
    port_other_list: PortIpSet,
    port_icmp_list: IpSet,

    tcp_sm_list: PortIpSet,
    udp_sm_list: PortIpSet,
}

fn __get_port_type(port: Port, proto: Protocol) {
    if proto == 0x6 {
        // tcp
    } else if proto == 0x11 {
        // udp
    } else if proto == 0x1 {
        // icmp
    } else {
        // other
    }
}

impl Tracker {
    pub fn new(scanner: IpAddr) -> Tracker {
        Tracker {
            tracker_ip: scanner,
            total_fail_counts: [0, 0, 0, 0],
            ip_fail_counts: IpFailCounts::new(),
            port_icmp_list: IpSet::new(),

            port_other_list: PortIpSet::new(),
            tcp_sm_list: PortIpSet::new(),
            udp_sm_list: PortIpSet::new(),
        }
    }

    fn __tcp_sm_list_add(self, ip: IpAddr, port: Port) {}

    fn __udp_sm_list_add(self, ip: IpAddr, port: Port) {}

    fn __other_list_append(self, ip: IpAddr, port: Port) {}

    fn __icmp_list_append(self, ip: IpAddr) {}

    fn __total_failcounts_add(self, port_type: u8) {}

    fn __ip_pool_append(self, ip: IpAddr, port_type: u8) {}

    pub fn track_scanned(self, ip: IpAddr, port: Port, proto: Protocol) {
        let port_type = __get_port_type(port, proto);
    }

    pub fn get_ip_failcounts_amount(self) {
        // return ip_failcounts amount
    }
}
