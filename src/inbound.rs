use std::net::Ipv4Addr;
use std::sync::Mutex;
use track::Tracker;
use types::Port;
use types::Protocol;
use types::IpSweep;
use types::PortType;
use types::Trigger;
use config::INBOUND_TRACKER_MAP;
use config::IP_SCANNED_MODERATE;
use config::IP_SCANNED_HIGH;
use config::SCANNER_FOCUS_MINCOUNTS;
use config::SCANNER_MODAL_DISTRIBUTIONS;
use config::TRIGGERS;

pub fn inbound_scan(inner_ip: Ipv4Addr, outter_ip: Ipv4Addr, port: Port, proto: Protocol) {

    let mut inbound_map = INBOUND_TRACKER_MAP.lock().unwrap();
    inbound_map.entry(outter_ip)
        .and_modify(|e| {
            let mut entry = e.lock().unwrap();
            entry.track_scanned(outter_ip, port, proto)
        })
        .or_insert(Mutex::new(Tracker::new(inner_ip)));
}

pub fn inbound_alert_check<'a>(outter: Ipv4Addr) {
    let inbound_map = INBOUND_TRACKER_MAP.lock().unwrap();
    if let Some(tracker) = inbound_map.get(&outter) {
        let mut tracker = tracker.lock().unwrap();
        let ips = evaluate_ipsweeper(&tracker);
        let pf = evaluate_portsweeper(&tracker);
        if pf != PortType::NONE {

            for trigger in TRIGGERS.lock().unwrap().iter_mut() {
                if ips == trigger.ipsweep {
                    if (trigger.negative && trigger.portfocus == pf) ||
                       !trigger.negative && trigger.portfocus == pf {
                        trigger.curpf = pf;
                        if tracker.trigger == Some(*trigger) {
                            tracker.trigger = Some(Trigger {
                                ..*trigger
                            });
                        }
                    }
                }
            }

        }
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
    let mut pf = PortType::NONE;

    for i in 0..4 {
        if tracker.total_fail_counts[i] >= SCANNER_FOCUS_MINCOUNTS[i] {
            let mut is_modal = true;
            pf = PortType::GENERIC;

            let failcount = tracker.total_fail_counts[i];
            let weight = SCANNER_MODAL_DISTRIBUTIONS[i][i];
            let weights = SCANNER_MODAL_DISTRIBUTIONS[i];

            for j in 0..4 {
                if j != i && failcount * weights[j] < tracker.total_fail_counts[j] * weight {
                    is_modal = false;
                    break;
                }
            }
            if is_modal {
                pf = match i {
                    0 => PortType::SERVICE,
                    1 => PortType::MALWARE,
                    2 => PortType::ZERO,
                    3 => PortType::OTHER,
                    _ => PortType::NONE, //unreachable
                };
                break;
            }
        }
    }
    return pf;
}
