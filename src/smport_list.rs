use types::PortSet;
use config::SERVICE_PORTS_LIST;
use config::MALWARE_PORTS_LIST;

pub fn service_port_init() -> PortSet {
    let mut service_ports = PortSet::new();
    for port in SERVICE_PORTS_LIST.iter() {
        service_ports.insert(*port);
    }
    service_ports
}

pub fn malware_port_init() -> PortSet {
    let mut malware_ports = PortSet::new();
    for port in MALWARE_PORTS_LIST.iter() {
        malware_ports.insert(*port);
    }
    malware_ports
}

pub fn sm_list_init() -> (PortSet, PortSet) {
    let service_ports = service_port_init();
    let malware_ports = malware_port_init();
    (service_ports, malware_ports)
}
