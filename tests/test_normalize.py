from tip.normalize import defang, detect_type, host_from_url, is_public, make_ioc, norm_ts, refang, virustotal_url


def test_refang_and_defang():
    assert refang("hxxps://evil[.]com/path") == "https://evil.com/path"
    assert refang("hxxp://bad(.)org/a") == "http://bad.org/a"
    assert refang("evil[dot]com") == "evil.com"
    assert defang("https://evil.com/x.exe") == "hxxps://evil[.]com/x[.]exe"
    assert defang("http://1.2.3.4:8080/a") == "hxxp://1[.]2[.]3[.]4:8080/a"


def test_detect_type():
    assert detect_type("https://a.com/x") == "url"
    assert detect_type("sub.evil.com") == "domain"
    assert detect_type("1.2.3.4") == "ipv4"
    assert detect_type("2606:4700:4700::1111") == "ipv6"
    assert detect_type("0" * 32) == "md5"
    assert detect_type("a" * 40) == "sha1"
    assert detect_type("b" * 64) == "sha256"
    assert detect_type("user@bad.com") == "email"
    assert detect_type("not an ioc") is None
    assert detect_type("double..dot.com") is None


def test_make_ioc_normalization():
    ioc = make_ioc("HTTP://Evil[.]COM/PathX", "test")
    assert ioc is not None
    assert ioc.type == "url"
    assert ioc.value == "http://evil.com/PathX"

    domain = make_ioc("Sub.Evil.COM.", "test")
    assert domain is not None and domain.value == "sub.evil.com"

    assert make_ioc("192.168.1.1", "test") is None
    assert make_ioc("127.0.0.1", "test") is None
    assert make_ioc("localhost", "test") is None
    assert make_ioc("", "test") is None
    assert make_ioc("just some text", "test") is None


def test_host_from_url():
    assert host_from_url("http://a.b.example.net:8080/x") == "a.b.example.net"
    assert host_from_url("not a url") is None


def test_is_public():
    assert is_public("8.8.8.8", "ipv4")
    assert not is_public("10.0.0.1", "ipv4")
    assert not is_public("::1", "ipv6")
    assert not is_public("bad.local", "domain")


def test_norm_ts():
    assert norm_ts("2026-10-04 16:32:20") == "2026-10-04T16:32:20Z"
    assert norm_ts("2026-10-04") == "2026-10-04T00:00:00Z"
    assert norm_ts("2026-10-04T16:32:20.123456") == "2026-10-04T16:32:20Z"
    assert norm_ts(None) is None


def test_virustotal_url():
    assert virustotal_url("domain", "evil[.]com") == "https://www.virustotal.com/gui/domain/evil.com"
    assert virustotal_url("ipv4", "1[.]2[.]3[.]4").endswith("/ip-address/1.2.3.4")
    assert virustotal_url("sha256", "a" * 64).endswith("/file/" + "a" * 64)
    url_link = virustotal_url("url", "hxxp://evil[.]com/a b")
    assert url_link.startswith("https://www.virustotal.com/gui/search/")
    assert " " not in url_link
