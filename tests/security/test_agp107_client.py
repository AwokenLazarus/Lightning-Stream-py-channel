"""AGP-107: the URL rule xbt-rs got in fix wave 6 (AGP-105, `wire::sendable_url`), ported to B1.

The rule: the host a payer keys its book by and binds a payment to is the host the request is sent
to. The first test checks the rule itself against the two things that read the string after the
client does: urllib's parser and the resolver's reading of a number as an IPv4 address. The others
are the paths that must call it.

  cd tests/security && ~/xbt-rnd/b1/.venv/bin/python -B -m unittest test_agp107_client
"""
import itertools
import os
import socket
import sys
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from test_agp093_client import O, Rig  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402

TOKENS = ["a", "B", "example", "1", "127", "0", "0x7f", "08", ".", ":", "@", "[", "]", "::1", "%61", "-", "_", "\\", " ", "80", "ｂ"]


def sendable(url):
    try:
        return xc.sendable_url(url) == url
    except ChannelError as e:
        assert e.code == "bad_request", e.code
        return False


class TheRule(unittest.TestCase):
    def test_every_url_the_rule_lets_through_is_read_alike_by_the_book_the_parser_and_the_resolver(self):
        """Every authority of up to three tokens from 21 (9,723 URLs). For each one let through:
        urllib reads the host and port request_url read, and a host the resolver would take for an
        IPv4 address (inet_aton) is that address in its usual form, so no second spelling of it
        gets a key of its own."""
        let, n = 0, 0
        for k in (1, 2, 3):
            for parts in itertools.product(TOKENS, repeat=k):
                n += 1
                url = "http://" + "".join(parts) + "/p?q"
                if not sendable(url):
                    continue
                let += 1
                _, host, port, _ = xc.request_url(url)
                u = urllib.parse.urlsplit(url)
                self.assertEqual((u.hostname, 80 if u.port is None else u.port), (host.strip("[]"), int(port)), url)
                try:
                    quad = socket.inet_ntoa(socket.inet_aton(host))
                except OSError:
                    continue
                self.assertEqual(quad, host, f"{url}: the resolver reads {host!r} as {quad}")
        self.assertEqual(n, 21 + 21 ** 2 + 21 ** 3)
        self.assertGreater(let, 500, "control: the rule lets plain names and addresses through")

    def test_what_is_refused_and_what_is_not(self):
        for u in ["https://api.example/x", "HTTPS://API.Example:443/x", "https://api.example:0443/x", "https://api.example:/x",
                  "https://u:p@api.example/x", "https://api.example?x", "https://api.example./x", "http://127.0.0.1:8402/v1/q",
                  "http://[::1]:80/x", "http://a_b-c.example"]:
            self.assertTrue(sendable(u), u)
        for u in ["/v1/q", "http:/h/x", "http:///x", "http://a\\@b/x", "http://a b/x", "http://h/x\ty", "http://a@b@c/x",
                  "http://a<b>@c/x", "http://%61pi.example/x", "http://ｂ.example/x", "http://127.1/x", "http://2130706433/x",
                  "http://0x7f.0.0.1/x", "http://0x/x", "http://1.2.3/x", "http://01.2.3.4/x", "http://127.0.0.1./x",
                  "http://[0:0:0:0:0:0:0:1]/x", "http://[::1]x/", "http://[::1/x", "http://h:65536/", "http://h:8a/"]:
            self.assertFalse(sendable(u), u)


class ThePaths(unittest.TestCase):
    def refused(self, call):
        with self.assertRaises(ChannelError) as e:
            call()
        self.assertEqual(e.exception.code, "bad_request")

    def test_a_request_under_a_spelling_that_is_refused_asks_and_funds_nothing(self):
        r = Rig()
        asked = []
        real = r.c.http
        r.c.http = lambda *a, **k: (asked.append(a), real(*a, **k))[1]
        for url in ("http://127.1:8402/v1/q", "http://a\\@api.example/v1/q", "/v1/q"):
            self.refused(lambda: r.c.request("GET", url))
            self.refused(lambda: r.c.request_conditional("GET", url))
        self.assertEqual((asked, r.sends, r.c.channels), ([], [], {}))
        self.assertEqual(r.get(), 200, "control: the seller's own spelling is paid")
        self.assertEqual(sorted(r.c.channels), [O])


if __name__ == "__main__":
    unittest.main()
