use types::PortSet;
use config::SERVICE_PORTS_LIST;
use config::MALWARE_PORTS_LIST;

lazy_static! {
    pub static ref SERVICE_PORTS: PortSet = {
        let mut service = PortSet::new();
        for port in SERVICE_PORTS_LIST.iter() {
            service.insert(*port);
        }
        service
    };
}

lazy_static! {
    pub static ref MALWARE_PORTS: PortSet = {
        let mut malware = PortSet::new();
        for port in MALWARE_PORTS_LIST.iter() {
            malware.insert(*port);
        }
        malware
    };
}
