import logging
import os
import random

import certifi
import pytest

import httpcore
import httpx
from httpx._utils import (  # see https://github.com/encode/httpx/issues/2492
    get_ca_bundle_from_env,  # only available in `httpx.create_ssl_context()` (with exception handling)
    guess_json_utf,  # not available
    is_https_redirect,  # only availble by check `Authorization` header removed
    same_origin,  # only available in Client._redirect_headers
)

from .common import TESTS_DIR


@pytest.mark.parametrize(
    "encoding",
    (
        "utf-32",
        "utf-8-sig",
        "utf-16",
        "utf-8",
        "utf-16-be",
        "utf-16-le",
        "utf-32-be",
        "utf-32-le",
    ),
)
def test_encoded(encoding):
    data = "{}".encode(encoding)
    assert guess_json_utf(data) == encoding


def test_bad_utf_like_encoding():
    assert guess_json_utf(b"\x00\x00\x00\x00") is None


@pytest.mark.parametrize(
    ("encoding", "expected"),
    (
        ("utf-16-be", "utf-16"),
        ("utf-16-le", "utf-16"),
        ("utf-32-be", "utf-32"),
        ("utf-32-le", "utf-32"),
    ),
)
def test_guess_by_bom(encoding, expected):
    data = "\ufeff{}".encode(encoding)
    assert guess_json_utf(data) == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        (
            '<http:/.../front.jpeg>; rel=front; type="image/jpeg"',
            [{"url": "http:/.../front.jpeg", "rel": "front", "type": "image/jpeg"}],
        ),
        ("<http:/.../front.jpeg>", [{"url": "http:/.../front.jpeg"}]),
        ("<http:/.../front.jpeg>;", [{"url": "http:/.../front.jpeg"}]),
        (
            '<http:/.../front.jpeg>; type="image/jpeg",<http://.../back.jpeg>;',
            [
                {"url": "http:/.../front.jpeg", "type": "image/jpeg"},
                {"url": "http://.../back.jpeg"},
            ],
        ),
        ("", []),
    ),
)
def test_parse_header_links(value, expected):
    all_links = httpx.Response(200, headers={"link": value}).links.values()
    assert all(link in all_links for link in expected)


def test_logging_request(server, caplog):
    caplog.set_level(logging.INFO)
    with httpx.Client() as client:
        response = client.get(server.url)
        assert response.status_code == 200

    assert caplog.record_tuples == [
        (
            "httpx",
            logging.INFO,
            'HTTP Request: GET http://127.0.0.1:8000/ "HTTP/1.1 200 OK"',
        )
    ]


def test_logging_redirect_chain(server, caplog):
    caplog.set_level(logging.INFO)
    with httpx.Client(follow_redirects=True) as client:
        response = client.get(server.url.copy_with(path="/redirect_301"))
        assert response.status_code == 200

    assert caplog.record_tuples == [
        (
            "httpx",
            logging.INFO,
            'HTTP Request: GET http://127.0.0.1:8000/redirect_301 "HTTP/1.1 301 Moved Permanently"',
        ),
        (
            "httpx",
            logging.INFO,
            'HTTP Request: GET http://127.0.0.1:8000/ "HTTP/1.1 200 OK"',
        ),
    ]


def test_logging_ssl(caplog):
    caplog.set_level(logging.DEBUG)
    with httpx.Client():
        pass

    cafile = certifi.where()
    assert caplog.record_tuples == [
        (
            "httpx",
            logging.DEBUG,
            "load_ssl_context verify=True cert=None trust_env=True http2=False",
        ),
        (
            "httpx",
            logging.DEBUG,
            f"load_verify_locations cafile='{cafile}'",
        ),
    ]


def test_get_ssl_cert_file():
    # Two environments is not set.
    assert get_ca_bundle_from_env() is None

    os.environ["SSL_CERT_DIR"] = str(TESTS_DIR)
    # SSL_CERT_DIR is correctly set, SSL_CERT_FILE is not set.
    ca_bundle = get_ca_bundle_from_env()
    assert ca_bundle is not None and ca_bundle.endswith("tests")

    del os.environ["SSL_CERT_DIR"]
    os.environ["SSL_CERT_FILE"] = str(TESTS_DIR / "test_utils.py")
    # SSL_CERT_FILE is correctly set, SSL_CERT_DIR is not set.
    ca_bundle = get_ca_bundle_from_env()
    assert ca_bundle is not None and ca_bundle.endswith("tests/test_utils.py")

    os.environ["SSL_CERT_FILE"] = "wrongfile"
    # SSL_CERT_FILE is set with wrong file,  SSL_CERT_DIR is not set.
    assert get_ca_bundle_from_env() is None

    del os.environ["SSL_CERT_FILE"]
    os.environ["SSL_CERT_DIR"] = "wrongpath"
    # SSL_CERT_DIR is set with wrong path,  SSL_CERT_FILE is not set.
    assert get_ca_bundle_from_env() is None

    os.environ["SSL_CERT_DIR"] = str(TESTS_DIR)
    os.environ["SSL_CERT_FILE"] = str(TESTS_DIR / "test_utils.py")
    # Two environments is correctly set.
    ca_bundle = get_ca_bundle_from_env()
    assert ca_bundle is not None and ca_bundle.endswith("tests/test_utils.py")

    os.environ["SSL_CERT_FILE"] = "wrongfile"
    # Two environments is set but SSL_CERT_FILE is not a file.
    ca_bundle = get_ca_bundle_from_env()
    assert ca_bundle is not None and ca_bundle.endswith("tests")

    os.environ["SSL_CERT_DIR"] = "wrongpath"
    # Two environments is set but both are not correct.
    assert get_ca_bundle_from_env() is None


@pytest.mark.parametrize(
    ["environment", "proxies"],
    [
        ({}, {}),
        ({"HTTP_PROXY": "http://127.0.0.1"}, {"http://": "http://127.0.0.1"}),
        (
            {"https_proxy": "http://127.0.0.1", "HTTP_PROXY": "https://127.0.0.1"},
            {"https://": "http://127.0.0.1", "http://": "https://127.0.0.1"},
        ),
        ({"all_proxy": "http://127.0.0.1"}, {"all://": "http://127.0.0.1"}),
        ({"TRAVIS_APT_PROXY": "http://127.0.0.1"}, {}),
        ({"no_proxy": "127.0.0.1"}, {"all://127.0.0.1": None}),
        ({"no_proxy": "192.168.0.0/16"}, {"all://192.168.0.0/16": None}),
        ({"no_proxy": "::1"}, {"all://[::1]": None}),
        ({"no_proxy": "localhost"}, {"all://localhost": None}),
        ({"no_proxy": "github.com"}, {"all://*github.com": None}),
        ({"no_proxy": ".github.com"}, {"all://*.github.com": None}),
    ],
)
def test_get_environment_proxies(environment, proxies):
    as_classes = {
        pattern: None if proxy is None else httpx.Proxy(url=proxy)
        for pattern, proxy in proxies.items()
    }

    os.environ.update(environment)
    client = httpx.Client()

    for pat, transport in client._mounts.items():
        expected = as_classes[pat.pattern]
        if transport is None:
            assert expected is None
        else:
            assert isinstance(transport, httpx.HTTPTransport)
            assert isinstance(
                transport._pool, (httpcore.HTTPProxy, httpcore.SOCKSProxy)
            )
            proxy_url = transport._pool._proxy_url

            assert proxy_url.scheme == expected.url.raw_scheme
            assert proxy_url.host == expected.url.raw_host
            assert proxy_url.port == expected.url.port
            assert proxy_url.target == expected.url.raw_path


@pytest.mark.parametrize(
    "headers, output",
    [
        ([("content-type", "text/html")], [("content-type", "text/html")]),
        ([("authorization", "s3kr3t")], [("authorization", "[secure]")]),
        ([("proxy-authorization", "s3kr3t")], [("proxy-authorization", "[secure]")]),
    ],
)
def test_obfuscate_sensitive_headers(headers, output):
    as_dict = {k: v for k, v in output}
    headers_class = httpx.Headers({k: v for k, v in headers})
    assert repr(headers_class) == f"Headers({as_dict!r})"


def test_same_origin():
    origin1 = httpx.URL("https://example.com")
    origin2 = httpx.URL("HTTPS://EXAMPLE.COM:443")
    assert same_origin(origin1, origin2)


def test_not_same_origin():
    origin1 = httpx.URL("https://example.com")
    origin2 = httpx.URL("HTTP://EXAMPLE.COM")
    assert not same_origin(origin1, origin2)


def test_is_https_redirect():
    url = httpx.URL("http://example.com")
    location = httpx.URL("https://example.com")
    assert is_https_redirect(url, location)


def test_is_not_https_redirect():
    url = httpx.URL("http://example.com")
    location = httpx.URL("https://www.example.com")
    assert not is_https_redirect(url, location)


def test_is_not_https_redirect_if_not_default_ports():
    url = httpx.URL("http://example.com:9999")
    location = httpx.URL("https://example.com:1337")
    assert not is_https_redirect(url, location)


@pytest.mark.parametrize(
    ["pattern", "url", "expected"],
    [
        ("http://example.com", "http://example.com", True),
        ("http://example.com", "https://example.com", False),
        ("http://example.com", "http://other.com", False),
        ("http://example.com:123", "http://example.com:123", True),
        ("http://example.com:123", "http://example.com:456", False),
        ("http://example.com:123", "http://example.com", False),
        ("all://example.com", "http://example.com", True),
        ("all://example.com", "https://example.com", True),
        ("http://", "http://example.com", True),
        ("http://", "https://example.com", False),
        ("all://", "https://example.com:123", True),
        ("", "https://example.com:123", True),
    ],
)
def test_url_matches(pattern, url, expected):
    client = httpx.Client(mounts={pattern: httpx.BaseTransport()})
    pattern = next(iter(client._mounts))
    assert pattern.matches(httpx.URL(url)) == expected


def test_pattern_priority():
    matchers = [
        "all://",
        "http://",
        "http://example.com",
        "http://example.com:123",
    ]
    random.shuffle(matchers)

    transport = httpx.BaseTransport()
    client = httpx.Client(mounts={m: transport for m in matchers})

    assert [pat.pattern for pat in client._mounts] == [
        "http://example.com:123",
        "http://example.com",
        "http://",
        "all://",
    ]
