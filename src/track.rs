use std::net::Ipv4Addr;
use types::FailCounts;
use types::PortIpSet;
use types::Port;
use types::IpSet;
use types::IpFailCounts;
use types::Protocol;
use types::PortType;
use smport_list::SERVICE_PORTS;
use smport_list::MALWARE_PORTS;

pub struct Tracker {
    tracker_ip: Ipv4Addr,
    total_fail_counts: FailCounts,

    ip_fail_counts: IpFailCounts,
    port_other_list: PortIpSet,
    port_icmp_list: IpSet,

    tcp_sm_list: PortIpSet,
    udp_sm_list: PortIpSet,
}

fn __get_port_type(port: Port, proto: Protocol) -> PortType {
    if proto == 0x6 || proto == 0x11 {
        if SERVICE_PORTS.contains(&port) {
            return PortType::SERVICE;
        } else if MALWARE_PORTS.contains(&port) {
            return PortType::MALWARE;
        } else {
            // other's tcp-udp
            return PortType::OTHER;
        }
    } else if proto == 0x1 {
        // icmp
        return PortType::ZERO;
    } else {
        // arp
        return PortType::OTHER;
    }
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

    fn __tcp_sm_list_add(&mut self, ip: Ipv4Addr, port: Port) {
        // self.tcp_sm_list.insert(ip, port);
        let ipset = self.tcp_sm_list.entry(port).or_insert(IpSet::new());
        ipset.insert(ip);
    }

    fn __udp_sm_list_add(&mut self, ip: Ipv4Addr, port: Port) {
        let ipset = self.udp_sm_list.entry(port).or_insert(IpSet::new());
        ipset.insert(ip);
    }

    fn __other_list_append(&mut self, ip: Ipv4Addr, port: Port) {
        let ipset = self.port_other_list.entry(port).or_insert(IpSet::new());
        ipset.insert(ip);
    }

    fn __icmp_list_append(&mut self, ip: Ipv4Addr) {
        self.port_icmp_list.insert(ip);
    }

    fn __total_failcounts_add(&mut self, port_type: PortType) {
        self.total_fail_counts[port_type as usize] += 1;
    }

    fn __ip_pool_append(self, ip: Ipv4Addr, port_type: u8) {}

    pub fn track_scanned(&mut self, ip: Ipv4Addr, port: Port, proto: Protocol) {
        let port_type = __get_port_type(port, proto);
        // calculate total failcounts
        self.__total_failcounts_add(port_type);

        // maintain icmp
        match port_type {
            PortType::SERVICE | PortType::MALWARE => {
                if proto == 0x6 {
                    self.__tcp_sm_list_add(ip, port);
                } else if proto == 0x11 {
                    self.__udp_sm_list_add(ip, port);
                }
            }
            PortType::ZERO => {
                self.__icmp_list_append(ip);
            }
            PortType::OTHER => {
                self.__other_list_append(ip, port);
            }
        }
    }

    pub fn get_ip_failcounts_amount(self) {
        // return ip_failcounts amount
    }
}
