"""
Tests for the pure-logic helpers in subtle_response_solver.py and
timing_attack_solver.py.
"""
from subtle_response_solver import canonicalize
from timing_attack_solver import random_ip


class TestCanonicalize:
    def test_strips_csrf_token_quoted(self):
        html = '<input name="csrf" value="ABC123" type="hidden">'
        out = canonicalize(html)
        assert "ABC123" not in out
        assert "STRIPPED" in out

    def test_strips_csrf_token_value_first(self):
        html = '<input value="XYZ789" name="csrf" type="hidden">'
        out = canonicalize(html)
        assert "XYZ789" not in out

    def test_leaves_unrelated_content_alone(self):
        html = '<p>Hello world</p>'
        assert canonicalize(html) == html

    def test_strips_multiple_csrf_tokens(self):
        html = ('<input name="csrf" value="tok1" />'
                '<input name="csrf" value="tok2" />')
        out = canonicalize(html)
        assert "tok1" not in out
        assert "tok2" not in out


class TestRandomIp:
    def test_returns_valid_format(self):
        for _ in range(50):
            ip = random_ip()
            octets = ip.split(".")
            assert len(octets) == 4
            for o in octets:
                n = int(o)
                assert 0 <= n <= 255

    def test_avoids_reserved_first_octets(self):
        # First octets we explicitly skip: 10, 127, 169, 172, 192, 198.
        for _ in range(200):
            first = int(random_ip().split(".")[0])
            assert first not in (10, 127, 169, 172, 192, 198)

    def test_first_octet_in_range(self):
        for _ in range(100):
            first = int(random_ip().split(".")[0])
            assert 1 <= first <= 223
