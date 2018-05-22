use std::net::Ipv4Addr;
use track::Tracker;
use config::Config;

pub fn outbound_get_tracker(config: &mut Config, ip: Ipv4Addr) -> &mut Tracker {
    let tracker = config.outbound_tracker_map.entry(ip).or_insert(Tracker::new(ip));
    tracker
}

pub fn outbound_tracker_check(tracker: &Tracker) {}
