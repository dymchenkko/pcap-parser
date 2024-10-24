use byteorder::{BigEndian, ReadBytesExt};
use pcap_file::pcap::PcapReader;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Duration;

#[derive(Debug)]
struct Quote {
    pkt_time: Duration,
    accept_time: String,
    issue_code: isin::ISIN,
    bids: Vec<(u64, u64)>,
    asks: Vec<(u64, u64)>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [-r] <filename>", args[0]);
        return;
    }

    let reverse_flag = args.contains(&"-r".to_string());

    let filename = if reverse_flag && args.len() >= 3 {
        &args[2]
    } else if args.len() >= 2 {
        &args[1]
    } else {
        eprintln!("Unknown file.");
        return;
    };
    let mut quotes = Vec::new();

    let file = File::open(filename).expect("Error opening file");
    let mut pcap_reader = PcapReader::new(file).unwrap();

    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.unwrap();
        if let Some(udp_payload) = parse_udp(&pkt.data) {
            let pkt_time = Duration::from_secs(pkt.timestamp.as_secs() as u64);
            if let Some(quote) = parse_quote(&udp_payload, pkt_time) {
                quotes.push(quote);
            }
        }
    }
    if reverse_flag {
        quotes.sort_by_key(|q| q.accept_time.clone());
    }

    for quote in quotes {
        print_quote(&quote);
    }
}

fn parse_udp(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(udp_packet) = UdpPacket::new(data) {
        let dest_port = udp_packet.get_destination();
        if dest_port == 15516 || dest_port == 15515 {
            return Some(udp_packet.payload().to_vec());
        }
    }

    None
}

fn parse_quote(data: &[u8], pkt_time: Duration) -> Option<Quote> {
    if data.len() < 143 || &data[34..39] != b"B6034" {
        return None;
    }
    let mut cursor = std::io::Cursor::new(&data[39..]);
    let mut issue_code_bytes = vec![0; 12];
    cursor.read_exact(&mut issue_code_bytes).ok()?;
    let issue_code = isin::parse_loose(&String::from_utf8_lossy(&issue_code_bytes)).unwrap();

    cursor.set_position(cursor.position() + 12);

    let mut bids = Vec::new();
    for _ in 0..5 {
        let price = cursor.read_u32::<BigEndian>().ok()? as u64;
        let quantity = cursor.read_u48::<BigEndian>().ok()?;
        bids.push((quantity, price));
    }

    let mut asks = Vec::new();
    for _ in 0..5 {
        let price = cursor.read_u32::<BigEndian>().ok()? as u64;
        let quantity = cursor.read_u48::<BigEndian>().ok()?;
        asks.push((quantity, price));
    }

    let mut cursor = std::io::Cursor::new(&data[240..]);
    let mut buf = [0; 8];
    cursor.read_exact(&mut buf).unwrap();
    let time_str = String::from_utf8_lossy(&buf);

    let hour = &time_str[0..2];
    let minute = &time_str[2..4];
    let second = &time_str[4..6];
    let microsecond = &time_str[6..8];

    Some(Quote {
        pkt_time,
        accept_time: format!("{}:{}:{}.{}", hour, minute, second, microsecond).to_string(),
        issue_code,
        bids,
        asks,
    })
}

fn print_quote(quote: &Quote) {
    print!(
        "{} {} {}",
        quote.pkt_time.as_secs(),
        quote.accept_time,
        quote.issue_code
    );

    for (qty, price) in quote.bids.iter().rev() {
        print!(" {}@{}", qty, price);
    }

    for (qty, price) in &quote.asks {
        print!(" {}@{}", qty, price);
    }
    println!();
}
