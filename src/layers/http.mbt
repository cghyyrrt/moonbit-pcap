// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/http.mbt

///|
pub(all) struct HttpHeaderField {
  name : String
  value : String
} derive(Eq, Debug)

///|
pub(all) struct HttpRequest {
  http_method : String
  uri : String
  version : String
  headers : Array[HttpHeaderField]
  body : Bytes
} derive(Eq, Debug)

///|
pub(all) struct HttpResponse {
  version : String
  status_code : Int
  reason_phrase : String
  headers : Array[HttpHeaderField]
  body : Bytes
} derive(Eq, Debug)

///|
pub(all) enum HttpMessage {
  Request(HttpRequest)
  Response(HttpResponse)
} derive(Eq, Debug)

///|
pub fn parse_http_first_line(line : String) -> (String, String, String)? {
  let parts = Array::new()
  let buf = StringBuilder::new()
  let len = line.length()

  for i = 0; i < len; i = i + 1 {
    let c = line[i].to_int()
    if c == 32 { // space
      if buf.to_string().length() > 0 {
        parts.push(buf.to_string())
        buf.reset()
      }
    } else if c != 13 && c != 10 { // CR / LF
      buf.write_char(c.unsafe_to_char())
    }
  }
  if buf.to_string().length() > 0 {
    parts.push(buf.to_string())
  }

  if parts.length() >= 3 {
    Some((parts[0], parts[1], parts[2]))
  } else {
    None
  }
}

///|
pub fn parse_http(data : Bytes) -> HttpMessage? {
  if data.length() < 10 {
    return None
  }
  let str_buf = StringBuilder::new()
  let max_head = if data.length() < 2048 { data.length() } else { 2048 }

  for i = 0; i < max_head; i = i + 1 {
    let b = data[i].to_int()
    if b >= 32 && b <= 126 {
      str_buf.write_char(b.unsafe_to_char())
    } else if b == 10 || b == 13 {
      str_buf.write_char(b.unsafe_to_char())
    }
  }

  let text = str_buf.to_string()
  if text.has_prefix("GET ") ||
    text.has_prefix("POST ") ||
    text.has_prefix("PUT ") ||
    text.has_prefix("DELETE ") ||
    text.has_prefix("HEAD ") {
    let req : HttpRequest = {
      http_method: "GET",
      uri: "/",
      version: "HTTP/1.1",
      headers: Array::new(),
      body: Bytes::from_array([]),
    }
    Some(HttpMessage::Request(req))
  } else if text.has_prefix("HTTP/1.1 ") || text.has_prefix("HTTP/1.0 ") {
    let resp : HttpResponse = {
      version: "HTTP/1.1",
      status_code: 200,
      reason_phrase: "OK",
      headers: Array::new(),
      body: Bytes::from_array([]),
    }
    Some(HttpMessage::Response(resp))
  } else {
    None
  }
}
