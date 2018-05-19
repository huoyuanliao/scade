#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_assignments)]
extern crate scade;
extern crate pnet;
extern crate pcap;

use std::net::IpAddr;
use std::path::Path;
use pcap::Capture;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::ArpOperations;
type Port = u16;

fn process_packet(p: pcap::Packet) {
    if let Some(eth) = EthernetPacket::new(&p) {
        let mut scanner: IpAddr;
        let mut scanned: IpAddr;
        let mut scanned_port: Port;
        let mut protocol: IpNextHeaderProtocol;
        let ether_type = eth.get_ethertype();

        //arp only handle request
        if let EtherTypes::Arp = ether_type {
          if let Some(arp) = ArpPacket::new(eth.payload()) {
            if arp.get_operation() == ArpOperations::Request {
              
            }
          }
        }
        //tcp/udp/icmp, icmp only handle request
        if let EtherTypes::Ipv4 = ether_type {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                scanner = std::net::IpAddr::V4(ip.get_source());
                scanned = std::net::IpAddr::V4(ip.get_destination());
                protocol = ip.get_next_level_protocol();
                if let IpNextHeaderProtocols::Tcp = protocol {
                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                        scanned_port = tcp.get_destination();
                    }
                }
                if let IpNextHeaderProtocols::Udp = protocol {
                    if let Some(udp) = UdpPacket::new(ip.payload()) {
                        scanned_port = udp.get_destination();
                    }
                }
                if let IpNextHeaderProtocols::Icmp = protocol {
                    if let Some(icmp) = IcmpPacket::new(ip.payload()) {
                        scanned_port = 0;
                    }
                }
            }
        }
    }
}

fn main() {
    let pcap_file = Path::new("./pcaps/botnet-capture-20110810-neris.pcap");
    let mut cap = Capture::from_file(pcap_file).unwrap();
    while let Ok(packet) = cap.next() {
        process_packet(packet);
    }
}
