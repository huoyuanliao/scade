use std::net::Ipv4Addr;
use types::PortSet;
use types::FailCounts;
use types::PortIpSet;
use types::Port;
use types::IpSet;
use types::IpFailCounts;
use types::Protocol;
use smport_list::service_port_init;
use smport_list::malware_port_init;



pub fn tracker_init() -> (PortSet, PortSet) {
    let service_ports = service_port_init();
    let malware_ports = malware_port_init();
    (service_ports, malware_ports)
}

pub struct Tracker {
    tracker_ip: Ipv4Addr,
    total_fail_counts: FailCounts,

    ip_fail_counts: IpFailCounts,
    port_other_list: PortIpSet,
    port_icmp_list: IpSet,

    tcp_sm_list: PortIpSet,
    udp_sm_list: PortIpSet,
}

fn __get_port_type(port: Port, proto: Protocol) -> () {
    if proto == 0x6 || proto == 0x11 {

    }
    // if proto == 0x6 || proto == 0x11 {
    // if ServicePortList.contains_key(&port) {
    // return PortType::SERVICE;
    // } else if MalwarePortList.contains_key(&port) {
    // return PortType::MALWARE;
    // }
    // return PortType::OTHER;
    // } else if proto == 0x1 {
    // return PortType::ZERO;
    // } else {
    // return PortType::OTHER;
    // }
    //
}

impl Tracker {
    pub fn new(scanner: Ipv4Addr) -> Tracker {
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

    fn __tcp_sm_list_add(self, ip: Ipv4Addr, port: Port) {}

    fn __udp_sm_list_add(self, ip: Ipv4Addr, port: Port) {}

    fn __other_list_append(self, ip: Ipv4Addr, port: Port) {}

    fn __icmp_list_append(self, ip: Ipv4Addr) {}

    fn __total_failcounts_add(self, port_type: u8) {}

    fn __ip_pool_append(self, ip: Ipv4Addr, port_type: u8) {}

    pub fn track_scanned(self, ip: Ipv4Addr, port: Port, proto: Protocol) {
        let port_type = __get_port_type(port, proto);
    }

    pub fn get_ip_failcounts_amount(self) {
        // return ip_failcounts amount
    }
}
