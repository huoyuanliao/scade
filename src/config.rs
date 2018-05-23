use regex::Regex;

use std::sync::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use types::Port;
use types::PortType;
use types::IpSweep;
use types::TRIGGER_REG;
use track::Tracker;

type TrackerMap = HashMap<Ipv4Addr, Tracker>;
pub struct Trigger {
    catnum: u8,
    ipsweep: IpSweep,
    portfocus: PortType,
    curpf: PortType,
}

impl Trigger {
    pub fn new(catnum: u8, ips: IpSweep, pf: PortType) -> Self {
        Trigger {
            catnum: catnum,
            ipsweep: ips,
            portfocus: pf,
            curpf: PortType::NONE,
        }
    }
}

pub static SERVICE_PORTS_LIST: [Port; 26] = [21, 53, 42, 80, 135, 139, 445, 559, 1025, 1433, 2082,
                                             2100, 2745, 2535, 3127, 3306, 3410, 5000, 5554, 6101,
                                             6129, 10000, 11768, 15118, 27374, 65506];
pub static MALWARE_PORTS_LIST: [Port; 4] = [53, 69, 137, 1434];

lazy_static! {
    pub static ref TRIGGERS: Vec<Trigger> = {
        let catnum: u8;
        let negative:bool;
        let portfocus: PortType;
        let ipsweep: IpSweep;
        let trigger: Vec<Trigger> = Vec::new();
        let re = Regex::new(TRIGGER_REG).unwrap();
        for line in SCAN_TRIGGERS_RAW.iter() {
            for cap in re.captures_iter(line) {
                       
            }
        }
        
        trigger
    };
}

lazy_static! {
    pub static ref INBOUND_TRACKER_MAP: Mutex<TrackerMap> = {
    Mutex::new(
        TrackerMap::new()
        )
    };
}

lazy_static! {
    pub static ref OUTBOUND_TRACKER_MAP: Mutex<TrackerMap> = {
    Mutex::new(
        TrackerMap::new()
        )
    };
}

static SCAN_TRIGGERS_RAW: [&str; 3] =
    ["8=intense+malware", "5=intense+non-malware", "5=moderate+malware"];
