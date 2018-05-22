use std::net::Ipv4Addr;
use track::Tracker;
use config::Config;
use types::Port;
use types::Protocol;

pub fn outbound_check(config: &mut Config,
                      inner_ip: Ipv4Addr,
                      outter_ip: Ipv4Addr,
                      port: Port,
                      proto: Protocol)
                      -> &mut Tracker {
    let tracker = config.inbound_tracker_map.entry(inner_ip).or_insert(Tracker::new(inner_ip));
    tracker.track_scanned(outter_ip, port, proto);
    return tracker;
}

pub fn outbound_alert_check(tracker: &Tracker) {}
