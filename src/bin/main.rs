#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
extern crate scade;
extern crate pnet;
extern crate pcap;

use std::net::Ipv4Addr;
use std::path::Path;
use pcap::Capture;
use scade::Tracker;
use scade::inbound_check;
use scade::inbound_alert_check;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::ArpOperations;

type Port = u16;

fn process_packet(p: pcap::Packet) {
    if let Some(eth) = EthernetPacket::new(&p) {
        let mut scanner: Option<Ipv4Addr> = None;
        let mut scanned: Option<Ipv4Addr> = None;
        let mut scanned_port: Option<Port> = None;
        let mut protocol: Option<IpNextHeaderProtocol> = None;
        let ether_type = eth.get_ethertype();

        // arp only handle request
        if let EtherTypes::Arp = ether_type {
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                if arp.get_operation() == ArpOperations::Request {
                    scanner = Some(arp.get_sender_proto_addr());
                    scanned = Some(arp.get_target_proto_addr());
                    scanned_port = Some(0);
                    // 255 as arp protocol
                    protocol = Some(IpNextHeaderProtocol(255));
                }
            }
        }
        // tcp/udp/icmp, icmp only handle request
        if let EtherTypes::Ipv4 = ether_type {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                scanner = Some(ip.get_source());
                scanned = Some(ip.get_destination());
                protocol = Some(ip.get_next_level_protocol());
                if let Some(IpNextHeaderProtocols::Tcp) = protocol {
                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                        scanned_port = Some(tcp.get_destination());
                    }
                }
                if let Some(IpNextHeaderProtocols::Udp) = protocol {
                    if let Some(udp) = UdpPacket::new(ip.payload()) {
                        scanned_port = Some(udp.get_destination());
                    }
                }
                if let Some(IpNextHeaderProtocols::Icmp) = protocol {
                    if let Some(icmp) = IcmpPacket::new(ip.payload()) {
                        if icmp.get_icmp_type() == IcmpTypes::EchoRequest {
                            scanned_port = Some(0);
                        }
                    }
                }
            }
        }
        // return if not acceptable packet
        if scanned_port == None {
            return;
        }
        let scanned = scanned.unwrap();
        let scanned_port = scanned_port.unwrap();
        let protocol: u8 = protocol.unwrap().0;


        // let mut tracker = Tracker::new(scanner.unwrap());
        // let mut tracker = inbound_get_tracker();
        // tracker.track_scanned(scanned, scanned_port, protocol);
    }
}

fn main() {
    let pcap_file = Path::new("./pcaps/botnet-capture-20110810-neris.pcap");
    let mut cap = Capture::from_file(pcap_file).unwrap();
    while let Ok(packet) = cap.next() {
        process_packet(packet);
    }
}
