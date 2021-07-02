// TODO: this is literally a copy of examples/utils.rs, but without an allow dead code attribute.
// The include logic does not allow having attributes in included files.

use std::cell::RefCell;
use std::str::{self, FromStr};
use std::rc::Rc;
use std::io;
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::process;
use getopts::{Options, Matches};

use smoltcp::phy::{Device, Tracer, FaultInjector};
use smoltcp::phy::{PcapWriter, PcapSink, PcapMode, PcapLinkType};
use smoltcp::time::Duration;

pub fn create_options() -> (Options, Vec<&'static str>) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    (opts, Vec::new())
}

pub fn parse_options(options: &Options, free: Vec<&str>) -> Matches {
    match options.parse(env::args().skip(1)) {
        Err(err) => {
            println!("{}", err);
            process::exit(1)
        }
        Ok(matches) => {
            if matches.opt_present("h") || matches.free.len() != free.len() {
                let brief = format!("Usage: {} [OPTION]... {}",
                                    env::args().nth(0).unwrap(), free.join(" "));
                print!("{}", options.usage(&brief));
                process::exit(if matches.free.len() != free.len() { 1 } else { 0 })
            }
            matches
        }
    }
}

pub fn add_middleware_options(opts: &mut Options, _free: &mut Vec<&str>) {
    opts.optopt("", "pcap", "Write a packet capture file", "FILE");
    opts.optopt("", "drop-chance", "Chance of dropping a packet (%)", "CHANCE");
    opts.optopt("", "corrupt-chance", "Chance of corrupting a packet (%)", "CHANCE");
    opts.optopt("", "size-limit", "Drop packets larger than given size (octets)", "SIZE");
    opts.optopt("", "tx-rate-limit", "Drop packets after transmit rate exceeds given limit \
                                      (packets per interval)", "RATE");
    opts.optopt("", "rx-rate-limit", "Drop packets after transmit rate exceeds given limit \
                                      (packets per interval)", "RATE");
    opts.optopt("", "shaping-interval", "Sets the interval for rate limiting (ms)", "RATE");
}

pub fn parse_middleware_options<D>(matches: &mut Matches, device: D, loopback: bool)
        -> FaultInjector<Tracer<PcapWriter<D, Rc<PcapSink>>>>
    where D: for<'a> Device<'a>
{
    let drop_chance      = matches.opt_str("drop-chance").map(|s| u8::from_str(&s).unwrap())
                                  .unwrap_or(0);
    let corrupt_chance   = matches.opt_str("corrupt-chance").map(|s| u8::from_str(&s).unwrap())
                                  .unwrap_or(0);
    let size_limit       = matches.opt_str("size-limit").map(|s| usize::from_str(&s).unwrap())
                                  .unwrap_or(0);
    let tx_rate_limit    = matches.opt_str("tx-rate-limit").map(|s| u64::from_str(&s).unwrap())
                                  .unwrap_or(0);
    let rx_rate_limit    = matches.opt_str("rx-rate-limit").map(|s| u64::from_str(&s).unwrap())
                                  .unwrap_or(0);
    let shaping_interval = matches.opt_str("shaping-interval").map(|s| u64::from_str(&s).unwrap())
                                  .unwrap_or(0);

    let pcap_writer: Box<io::Write>;
    if let Some(pcap_filename) = matches.opt_str("pcap") {
        pcap_writer = Box::new(File::create(pcap_filename).expect("cannot open file"))
    } else {
        pcap_writer = Box::new(io::sink())
    }

    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();

    let device = PcapWriter::new(device, Rc::new(RefCell::new(pcap_writer)) as Rc<PcapSink>,
                                 if loopback { PcapMode::TxOnly } else { PcapMode::Both });
    let device = Tracer::new(device, |_timestamp, _printer| {
        #[cfg(feature = "log")]
        trace!("{}", _printer);
    });
    let mut device = FaultInjector::new(device, seed);
    device.set_drop_chance(drop_chance);
    device.set_corrupt_chance(corrupt_chance);
    device.set_max_packet_size(size_limit);
    device.set_max_tx_rate(tx_rate_limit);
    device.set_max_rx_rate(rx_rate_limit);
    device.set_bucket_interval(Duration::from_millis(shaping_interval));
    device
}
