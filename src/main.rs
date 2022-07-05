use failure::{Error, format_err};
use structopt::StructOpt;
use trust_dns_proto::op::message::Message;
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_proto::rr::record_data::RData;

#[derive(StructOpt)]
#[structopt(name = "capture-dns", about = "Capture DNS requests and show their QNames")]
struct Opt {
  #[structopt(help = "device", default_value = "wlan0")]
  device: String,
}

fn show_rdata(name: &str, rdata: &RData, arrow: &str) {
  match rdata {
    RData::A(ip) => {
      println!("{} {} {}", name, arrow, ip);
    },
    RData::AAAA(ip) => {
      println!("{} {} {}", name, arrow, ip);
    },
    RData::CNAME(cname) => {
      let s = cname.to_string();
      let cname_str = s.trim_end_matches('.');
      println!("{} {} {}", name, arrow, cname_str);
    },

    RData::HTTPS(svcb) => {
      use trust_dns_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue, IpHint};
      let has_ech = svcb.svc_params().iter()
        .any(|(k, _)| matches!(k, SvcParamKey::EchConfig));
      let tag = if has_ech { "HTTPS ECH" } else { "HTTPS" };
      let mut is_first = true;
      for (_, v) in svcb.svc_params() {
        match v {
          SvcParamValue::Ipv4Hint(IpHint(ips)) => {
            for ip in ips {
              let arrow = if is_first { "=>" } else { "->" };
              println!("{} {} {} {}", name, arrow, tag, ip);
              is_first = false;
            }
          },
          SvcParamValue::Ipv6Hint(IpHint(ips)) => {
            for ip in ips {
              let arrow = if is_first { "=>" } else { "->" };
              println!("{} {} {} {}", name, arrow, tag, ip);
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
    Err(e) => eprintln!("Error: {:?}", e),
  }
}

fn main() -> Result<(), Error> {
  let opt = Opt::from_args();
  let device = pcap::Device::list()?.into_iter()
    .find(|d| d.name == opt.device)
    .ok_or_else(|| format_err!("device {} not found", opt.device))?;

  let mut cap = pcap::Capture::from_device(device)?
    .immediate_mode(true).open()?;
  cap.filter("ip proto \\udp and src port 53", true)?;
  loop {
    match cap.next() {
      Ok(packet) => process(&packet),
      Err(pcap::Error::TimeoutExpired) => { },
      Err(e) => return Err(e.into()),
    }
  }
}
