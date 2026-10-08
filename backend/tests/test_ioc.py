import pytest
from app.schemas.ioc import IOCType
from app.services.ioc import detect_ioc_type, normalize_ioc, process_ioc_input


def test_detect_ipv4():
    ioc_type, err = detect_ioc_type("8.8.8.8")
    assert ioc_type == IOCType.IPV4
    assert err is None


def test_detect_ipv6():
    ioc_type, err = detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ioc_type == IOCType.IPV6
    assert err is None


def test_detect_domain():
    ioc_type, err = detect_ioc_type("malicious-c2.example.com")
    assert ioc_type == IOCType.DOMAIN
    assert err is None


def test_detect_url():
    ioc_type, err = detect_ioc_type("https://threat-portal.net/payload.bin?ref=target")
    assert ioc_type == IOCType.URL
    assert err is None


def test_detect_md5():
    ioc_type, err = detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e")
    assert ioc_type == IOCType.MD5
    assert err is None


def test_detect_sha1():
    ioc_type, err = detect_ioc_type("356a192b7913b04c54574d18c28d46e6395428ab")
    assert ioc_type == IOCType.SHA1
    assert err is None


def test_detect_sha256():
    ioc_type, err = detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert ioc_type == IOCType.SHA256
    assert err is None


def test_detect_invalid_ioc():
    ioc_type, err = detect_ioc_type("not_an_ioc_@@@!!!")
    assert ioc_type is None
    assert err is not None


def test_normalize_ipv4():
    res = normalize_ioc("192.168.01.01", IOCType.IPV4)
    assert res.is_valid
    assert res.canonical_value == "192.168.1.1"


def test_normalize_ipv6():
    res = normalize_ioc("2001:0db8:0000:0000:0000:ff00:0042:8329", IOCType.IPV6)
    assert res.is_valid
    assert res.canonical_value == "2001:db8::ff00:42:8329"


def test_normalize_domain():
    res = normalize_ioc("  HTTP://Sub.Example.COM/path  ", IOCType.DOMAIN)
    assert res.is_valid
    assert res.canonical_value == "sub.example.com"


def test_normalize_url():
    res = normalize_ioc("HTTPS://Example.COM/dir//sub/index.html?param=1", IOCType.URL)
    assert res.is_valid
    assert res.canonical_value == "https://example.com/dir/sub/index.html?param=1"


def test_normalize_hashes_lowercase():
    res_md5 = normalize_ioc("D41D8CD98F00B204E9800998ECF8427E", IOCType.MD5)
    assert res_md5.is_valid
    assert res_md5.canonical_value == "d41d8cd98f00b204e9800998ecf8427e"

    res_sha256 = normalize_ioc("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", IOCType.SHA256)
    assert res_sha256.is_valid
    assert res_sha256.canonical_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_process_ioc_input():
    result = process_ioc_input("  8.8.8.8  ")
    assert result.is_valid
    assert result.detected_type == IOCType.IPV4
    assert result.canonical_value == "8.8.8.8"
