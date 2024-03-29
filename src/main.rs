use eyre::{Result, eyre};
use hickory_proto::op::message::Message;
use hickory_proto::serialize::binary::BinDecodable;
use hickory_proto::rr::record_data::RData;
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = "Capture DNS requests and show their QNames")]
struct Opt {
  #[arg(help = "device", default_value = "wlan0")]
  device: String,
  #[arg(long, help = "pcap filter", default_value = "ip proto \\udp and src port 53")]
  filter: String,
}

fn show_rdata(name: &str, rdata: &RData, arrow: &str) {
  match rdata {
    RData::A(ip) => {
      println!("{name} {arrow} {ip}");
    },
    RData::AAAA(ip) => {
      println!("{name} {arrow} {ip}");
    },
    RData::CNAME(cname) => {
      let s = cname.to_string();
      let cname_str = s.trim_end_matches('.');
      println!("{name} {arrow} {cname_str}");
    },

    RData::HTTPS(svcb) => {
      use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue, IpHint};
      let has_ech = svcb.svc_params().iter()
        .any(|(k, _)| matches!(k, SvcParamKey::EchConfig));
      let tag = if has_ech { "HTTPS ECH" } else { "HTTPS" };
      let mut is_first = true;
      for (_, v) in svcb.svc_params() {
        match v {
          SvcParamValue::Ipv4Hint(IpHint(ips)) => {
            for ip in ips {
              let arrow = if is_first { "=>" } else { "->" };
              println!("{name} {arrow} {tag} {ip}");
              is_first = false;
            }
          },
          SvcParamValue::Ipv6Hint(IpHint(ips)) => {
            for ip in ips {
              let arrow = if is_first { "=>" } else { "->" };
              println!("{name} {arrow} {tag} {ip}");
              is_first = false;
            }
          },
          _ => { },
        }
      }
    },

    _ => { },
  }
}

fn process(packet: &[u8]) {
  // 42 = 14 Ethernet header + 20 IPv4 header + 8 UDP header
  match Message::from_bytes(&packet[42..]) {
    Ok(msg) => {
      let qname;
      let name;
      match msg.queries().iter().next() {
        Some(q) => {
          qname = q.name().to_string();
          name = qname.trim_end_matches('.');
        },
        None => { return },
      };

      let mut is_first = true;
      for a in msg.answers() {
        let arrow = if is_first { "=>" } else { "->" };
        if let Some(rdata) = a.data() {
          show_rdata(name, rdata, arrow);
        }
        is_first = false;
      }
    },
    Err(e) => eprintln!("Error: {e:?}"),
  }
}

fn main() -> Result<()> {
  let opt = Opt::parse();
  let device = pcap::Device::list()?.into_iter()
    .find(|d| d.name == opt.device)
    .ok_or_else(|| eyre!("device {} not found", opt.device))?;

  let mut cap = pcap::Capture::from_device(device)?
    .immediate_mode(true).open()?;
  cap.filter(&opt.filter, true)?;
  loop {
    match cap.next_packet() {
      Ok(packet) => process(&packet),
      Err(pcap::Error::TimeoutExpired) => { },
      Err(e) => return Err(e.into()),
    }
  }
}
