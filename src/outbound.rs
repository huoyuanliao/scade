use std::net::Ipv4Addr;
use std::sync::Mutex;
use track::Tracker;
use types::Port;
use types::Protocol;
use config::OUTBOUND_TRACKER_MAP;

pub fn outbound_scan(inner_ip: Ipv4Addr, outter_ip: Ipv4Addr, port: Port, proto: Protocol) {

    let mut outbound_map = OUTBOUND_TRACKER_MAP.lock().unwrap();
    outbound_map.entry(outter_ip)
        .and_modify(|e| {
            let mut entry = e.lock().unwrap();
            entry.track_scanned(inner_ip, port, proto)
        })
        .or_insert(Mutex::new(Tracker::new(inner_ip)));
}

pub fn outbound_alert_check(outter_ip: Ipv4Addr) {}
