use clap::Parser;
use pcap::{Capture, Device};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::net::Ipv6Addr;
use anyhow::{Context, Result};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to capture on
    #[arg(short, long)]
    interface: Option<String>,

    /// Number of packets to capture (0 for unlimited)
    #[arg(short, long, default_value_t = 10)]
    count: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let device = match &args.interface {
        Some(interface_name) => {
            Device::list()?
                .into_iter()
                .find(|d| d.name == *interface_name)
                .with_context(|| format!("Interface '{}' not found", interface_name))?
        }
        None => {
            println!("Available network interfaces:");
            for dev in Device::list()? {
                println!("- {}: {}", dev.name, dev.desc.unwrap_or_default());
            }
            return Ok(());
        }
    };

    println!("Capturing on device {}", device.name);

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(5000)
        .timeout(100)
        .open()?;

    let mut packet_count = 0;
    while args.count == 0 || packet_count < args.count {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                println!("\n[Packet #{}] {} bytes", packet_count, packet.header.len);

                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(value) => analyze_packet(value),
                    Err(err) => println!("Error parsing packet: {:?}", err),
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => {
                println!("Error receiving packet: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

fn analyze_packet(packet: SlicedPacket) {
    if let Some(link) = &packet.link {
        println!("Link layer: {:?}", link);
    }

    match &packet.ip {
        Some(InternetSlice::Ipv4(ipv4, _)) => {
            let source = ipv4.source_addr();
            let dest = ipv4.destination_addr();
            println!("IPv4: {} -> {}", source, dest);
            println!("Protocol: {}", ipv4.protocol());
        }
        Some(InternetSlice::Ipv6(ipv6, _)) => {
            let source = Ipv6Addr::from(ipv6.source_addr());
            let dest = Ipv6Addr::from(ipv6.destination_addr());
            println!("IPv6: {} -> {}", source, dest);
            println!("Next Header: {}", ipv6.next_header());
        }
        None => println!("No IP layer found"),
    }

    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            println!("TCP: Port {} -> {}", tcp.source_port(), tcp.destination_port());
            println!(
                "Flags: SYN={} ACK={} FIN={} RST={}",
                tcp.syn(), tcp.ack(), tcp.fin(), tcp.rst()
            );
            println!("Sequence: {}, Window: {}", tcp.sequence_number(), tcp.window_size());
        }
        Some(TransportSlice::Udp(udp)) => {
            println!("UDP: Port {} -> {}", udp.source_port(), udp.destination_port());
            println!("Length: {}", udp.length());
        }
        Some(TransportSlice::Icmpv4(_)) => println!("ICMPv4 packet"),
        Some(TransportSlice::Icmpv6(_)) => println!("ICMPv6 packet"),
        Some(TransportSlice::Unknown(u)) => println!("Unknown transport protocol: {}", u),
        None => println!("No transport layer found"),
    }

    let payload = &packet.payload;
    if !payload.is_empty() {
        println!("Payload: {} bytes", payload.len());
        let preview_len = std::cmp::min(16, payload.len());
        print!("Preview: ");
        for byte in &payload[0..preview_len] {
            print!("{:02x} ", byte);
        }
        println!();
    } else {
        println!("Payload: empty");
    }
}