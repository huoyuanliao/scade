#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
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

fn process_packet(p: pcap::Packet) {
  if let Some(eth) = EthernetPacket::new(&p) {

    match eth.get_ethertype() {
      EtherTypes::Ipv4 => {
        let ip = Ipv4Packet::new(eth.payload());
        // we only care about properly parsable ipv4 packets
        if let Some(ip) = ip {
          let protocol = ip.get_next_level_protocol();
          match protocol {
            // we only care about TCP
            IpNextHeaderProtocols::Tcp => {
              let tcp = TcpPacket::new(ip.payload());
                if let Some(tcp) = tcp {
                  //process_tcp_payload(tcp.payload());
                } else {
                  //println!("malformed tcp packet");
                }
            }

            IpNextHeaderProtocols::Udp => {
                //handle udp
            },

            _ => {},
          }
        }
      },
      _ => {
        //println!("non ipv4 packet");
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