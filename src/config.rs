use std::collections::HashMap;
use std::net::Ipv4Addr;
use types::Port;
use track::Tracker;

pub type TrackerMap = HashMap<Ipv4Addr, Tracker>;

pub struct Config {
    pub inbound_tracker_map: TrackerMap,
    pub outbound_tracker_map: TrackerMap,
}

pub static SERVICE_PORTS_LIST: [Port; 26] = [21, 53, 42, 80, 135, 139, 445, 559, 1025, 1433, 2082,
                                             2100, 2745, 2535, 3127, 3306, 3410, 5000, 5554, 6101,
                                             6129, 10000, 11768, 15118, 27374, 65506];
pub static MALWARE_PORTS_LIST: [Port; 4] = [53, 69, 137, 1434];

pub fn config_init() -> Config {
    Config {
        inbound_tracker_map: TrackerMap::new(),
        outbound_tracker_map: TrackerMap::new(),
    }
}
