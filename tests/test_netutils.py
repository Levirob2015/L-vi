from loginshield.netutils import (
    client_ip,
    ip_in_networks,
    normalize_ip,
    parse_ip,
    parse_networks,
)


def test_parse_ip_varianten():
    assert str(parse_ip("192.0.2.10")) == "192.0.2.10"
    assert str(parse_ip(" 192.0.2.10 ")) == "192.0.2.10"
    assert str(parse_ip("192.0.2.10:443")) == "192.0.2.10"
    assert str(parse_ip("[2001:db8::1]:443")) == "2001:db8::1"
    assert str(parse_ip("2001:db8::1")) == "2001:db8::1"
    # IPv4-mapped IPv6 wird auf IPv4 normalisiert, sonst waeren es zwei Identitaeten
    assert str(parse_ip("::ffff:192.0.2.10")) == "192.0.2.10"
    assert parse_ip("kein-ip") is None
    assert parse_ip("") is None
    assert parse_ip(None) is None


def test_parse_networks_ignoriert_muell():
    networks = parse_networks(["10.0.0.0/8", "quatsch", "", "203.0.113.5"])
    assert len(networks) == 2


def test_ip_in_networks():
    networks = parse_networks(["10.0.0.0/8", "2001:db8::/32"])
    assert ip_in_networks("10.1.2.3", networks)
    assert ip_in_networks("2001:db8::99", networks)
    assert not ip_in_networks("11.1.2.3", networks)
    assert not ip_in_networks(None, networks)
    assert not ip_in_networks("10.1.2.3", [])


def test_client_ip_ohne_proxy_ignoriert_header():
    # Kernpunkt: ein gefaelschter Header darf die echte Adresse nicht ersetzen.
    assert client_ip("198.51.100.7", "1.2.3.4") == "198.51.100.7"


def test_client_ip_mit_vertrauenswuerdigem_proxy():
    proxies = parse_networks(["10.0.0.0/8"])
    assert client_ip("10.0.0.1", "203.0.113.9", proxies) == "203.0.113.9"


def test_client_ip_nimmt_rechteste_nicht_proxy_adresse():
    proxies = parse_networks(["10.0.0.0/8"])
    # Der Client hat "1.1.1.1" selbst erfunden, danach haengen echte Hops.
    forwarded = "1.1.1.1, 203.0.113.9, 10.0.0.5"
    assert client_ip("10.0.0.1", forwarded, proxies) == "203.0.113.9"


def test_client_ip_unbekannter_peer_trotz_proxy_liste():
    proxies = parse_networks(["10.0.0.0/8"])
    assert client_ip("198.51.100.7", "203.0.113.9", proxies) == "198.51.100.7"


def test_client_ip_ohne_peer():
    assert client_ip(None, None) is None
    assert normalize_ip("::ffff:10.0.0.1") == "10.0.0.1"
