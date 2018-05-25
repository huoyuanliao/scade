use std::net::Ipv4Addr;
use track::Tracker;
use types::Port;
use types::Protocol;
use types::IpSweep;
use types::PortType;
use config::INBOUND_TRACKER_MAP;
use config::IP_SCANNED_MODERATE;
use config::IP_SCANNED_HIGH;

pub fn inbound_scan(inner_ip: Ipv4Addr, outter_ip: Ipv4Addr, port: Port, proto: Protocol) {

    let mut inbound_map = INBOUND_TRACKER_MAP.lock().unwrap();
    inbound_map.entry(outter_ip)
        .and_modify(|e| e.track_scanned(outter_ip, port, proto))
        .or_insert(Tracker::new(inner_ip));
}

pub fn inbound_alert_check(outter: Ipv4Addr) {
    let inbound_map = INBOUND_TRACKER_MAP.lock().unwrap();
    if let Some(ref tracer) = inbound_map.get(&outter) {
        // do threshold check and alert
    }
}

fn evaluate_ipsweeper(tracker: &Tracker) -> IpSweep {
    let count = tracker.get_ip_failcounts_amount();
    if count < IP_SCANNED_MODERATE {
        IpSweep::IPSweepNarrow
    } else if count < IP_SCANNED_HIGH {
        IpSweep::IPSweepModerate
    } else {
        IpSweep::IPSweepBroad
    }
}

fn evaluate_portsweeper(tracker: &Tracker) -> PortType {
    let pf = PortType::NONE;
    pf
}
