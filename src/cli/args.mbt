// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: cli/args.mbt

///|
pub(all) struct CliOptions {
  mut file_path : String
  mut output_format : String // "summary", "json", "csv"
  mut filter_proto : String // "", "tcp", "udp", "dns", etc.
  mut filter_port : UInt // 0 = no filter
  mut anomaly_check : Bool
  mut reassemble_tcp : Bool
} derive(Eq, Debug)

///|
pub fn default_options() -> CliOptions {
  {
    file_path: "",
    output_format: "summary",
    filter_proto: "",
    filter_port: 0U,
    anomaly_check: true,
    reassemble_tcp: false,
  }
}

///|
pub fn parse_args(args : Array[String]) -> CliOptions {
  let opts = default_options()
  let len = args.length()
  let mut i = 0

  while i < len {
    let arg = args[i]
    if arg == "--json" {
      opts.output_format = "json"
    } else if arg == "--csv" {
      opts.output_format = "csv"
    } else if arg == "--proto" && i + 1 < len {
      i = i + 1
      opts.filter_proto = args[i]
    } else if arg == "--port" && i + 1 < len {
      i = i + 1
      let port_str = args[i]
      opts.filter_port = match port_str {
        "80" => 80U
        "443" => 443U
        "53" => 53U
        "502" => 502U
        "1883" => 1883U
        _ => 0U
      }
    } else if arg == "--reassemble" {
      opts.reassemble_tcp = true
    } else if arg == "--no-anomaly" {
      opts.anomaly_check = false
    } else if opts.file_path == "" && !arg.has_prefix("-") {
      opts.file_path = arg
    }
    i = i + 1
  }

  opts
}
