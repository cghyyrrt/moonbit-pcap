///|
test "application protocol registry classifies standard and industrial ports" {
  assert_true(classify_application_port(80U) is HTTP)
  assert_true(classify_application_port(53U) is DNS)
  assert_true(classify_application_port(44818U) is EtherNetIP)
  assert_true(classify_application_port(20000U) is DNP3)
  assert_true(classify_application_port(9999U) is UnknownApplication(_))
  assert_true(is_industrial_application(EtherNetIP))
  assert_true(!is_industrial_application(HTTP))
}

///|
test "application protocol registry uses payload signatures" {
  let http = classify_application_payload(
    0U,
    Bytes::from_array([b'G', b'E', b'T', b' ']),
  )
  assert_true(http is HTTP)
  let mqtt = classify_application_payload(
    0U,
    Bytes::from_array([b'\x10', b'\x02', b'\x00', b'\x00']),
  )
  assert_true(mqtt is MQTT)
  let unknown = classify_application_payload(0U, Bytes::from_array([]))
  assert_true(unknown is UnknownApplication(_))
}
