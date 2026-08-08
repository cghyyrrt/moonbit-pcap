// Unit tests for HTTP dissector module

///|
test "http request parsing" {
  let req_pkt = Bytes::from_array([
    b'G', b'E', b'T', b' ', b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't',
    b'm', b'l', b' ', b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'1', b'\r', b'\n',
    b'H', b'o', b's', b't', b':', b' ', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'.', b'c', b'o', b'm', b'\r', b'\n', b'\r', b'\n',
  ])

  let msg_opt = parse_http(req_pkt)
  assert_true(msg_opt is Some(_))
  match msg_opt.unwrap() {
    HttpMessage::Request(req) => {
      inspect(req.http_method, content="GET")
      inspect(req.version, content="HTTP/1.1")
    }
    _ => assert_true(false)
  }
}

///|
test "http response parsing" {
  let resp_pkt = Bytes::from_array([
    b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'1', b' ', b'2', b'0', b'0', b' ',
    b'O', b'K', b'\r', b'\n', b'C', b'o', b'n', b't', b'e', b'n', b't', b'-', b'T',
    b'y', b'p', b'e', b':', b' ', b't', b'e', b'x', b't', b'/', b'h', b't', b'm',
    b'l', b'\r', b'\n', b'\r', b'\n',
  ])

  let msg_opt = parse_http(resp_pkt)
  assert_true(msg_opt is Some(_))
  match msg_opt.unwrap() {
    HttpMessage::Response(resp) => {
      inspect(resp.status_code, content="200")
      inspect(resp.reason_phrase, content="OK")
    }
    _ => assert_true(false)
  }
}

///|
test "http first line parsing" {
  let res = parse_http_first_line("POST /api/v1/submit HTTP/1.1\r\n")
  assert_true(res is Some(_))
  let (m, u, v) = res.unwrap()
  inspect(m, content="POST")
  inspect(u, content="/api/v1/submit")
  inspect(v, content="HTTP/1.1")
}
