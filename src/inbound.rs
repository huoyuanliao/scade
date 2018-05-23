use std::net::Ipv4Addr;
use track::Tracker;
use types::Port;
use types::Protocol;
use config::INBOUND_TRACKER_MAP;

pub fn inbound_scan(inner_ip: Ipv4Addr, outter_ip: Ipv4Addr, port: Port, proto: Protocol) {

    let mut outbound_map = INBOUND_TRACKER_MAP.lock().unwrap();
    outbound_map.entry(outter_ip)
        .and_modify(|e| e.track_scanned(outter_ip, port, proto))
        .or_insert(Tracker::new(inner_ip));
}

pub fn inbound_alert_check(inner: Ipv4Addr) {}
