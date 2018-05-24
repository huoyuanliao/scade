use regex::Regex;
use regex::Match;

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
    negative: bool,
    curpf: PortType,
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
        let mut trigger: Vec<Trigger> = Vec::new();
        let re = Regex::new(TRIGGER_REG).unwrap();
        for line in SCAN_TRIGGERS_RAW.iter() {
            if let Some(cap) =  re.captures(line) {
                let catnum: u8 = cap.get(1).unwrap().as_str().parse().unwrap();
                let ips = ips_config_parser(cap.get(2).unwrap().as_str());
                let negative =  negative_config_parser(cap.get(3));
                let pf = pf_config_parser( cap.get(4).unwrap().as_str());
                trigger.push(Trigger::new(catnum, ips, pf, negative));
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

fn ips_config_parser(ips: &str) -> IpSweep {
    match ips {
        "narrow" | "low" | "small" | "bottom" => IpSweep::IPSweepNarrow,
        "moderate" | "medium" | "middle" => IpSweep::IPSweepModerate,
        "intense" | "wide" | "high" | "large" | "top" | "broad" => IpSweep::IPSweepBroad,
        _ => IpSweep::IPSweepNone,

    }
}

fn pf_config_parser(pf: &str) -> PortType {
    match pf {
        "service" => PortType::SERVICE,
        "malware" => PortType::MALWARE,
        "other" => PortType::OTHER,
        "icmp" => PortType::ZERO,
        "zero" => PortType::ZERO,
        "generic" => PortType::GENERIC,
        _ => PortType::NONE,
    }
}

fn negative_config_parser(neg: Option<Match>) -> bool {
    match neg {
        Some(_) => true,
        None => false,
    }
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
