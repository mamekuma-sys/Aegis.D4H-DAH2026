"""Bounded HTTP request and Base64-JSON cookie parsing tests."""

import base64
import json
import unittest

from aegis_defender.http_semantics import MAX_COOKIE_VALUE, parse_http_request


def request(target="/admin", cookie=None, complete=True):
    lines = [f"GET {target} HTTP/1.1", "Host: team1.lig.internal:8083"]
    if cookie is not None:
        lines.append(f"Cookie: {cookie}")
    ending = "\r\n\r\n" if complete else "\r\n"
    return ("\r\n".join(lines) + ending).encode("latin-1")


def encoded(document, strip_padding=False):
    value = base64.urlsafe_b64encode(
        json.dumps(document, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return value.rstrip("=") if strip_padding else value


class TestHttpRequestView(unittest.TestCase):
    def test_percent_encoded_path_and_unpadded_cookie_are_normalized(self):
        payload = request(
            "/%61%64%6D%69%6E",
            "session = " + encoded({"user": "guest", "role": "admin"}, strip_padding=True),
        )
        view = parse_http_request(payload)
        self.assertEqual(view.method, "GET")
        self.assertEqual(view.target, "/admin")
        self.assertTrue(view.cookie_claim_matches("session", "role", ("admin",)))

    def test_absolute_form_is_reduced_to_path_and_query(self):
        view = parse_http_request(request("http://team1.lig.internal:8083/admin?view=1"))
        self.assertEqual(view.target, "/admin?view=1")

    def test_claim_order_and_boolean_values_do_not_break_parser(self):
        value = encoded({"admin": True, "role": "admin", "user": "operator"})
        view = parse_http_request(request(cookie=f"other=x; session={value}"))
        self.assertTrue(view.cookie_claim_matches("session", "role", ("admin",)))
        self.assertTrue(view.cookie_claim_matches("session", "admin", ("true",)))

    def test_guest_and_nested_claims_do_not_match_admin_role(self):
        for document in ({"role": "user"}, {"role": {"name": "admin"}}):
            with self.subTest(document=document):
                view = parse_http_request(request(cookie="session=" + encoded(document)))
                self.assertFalse(view.cookie_claim_matches("session", "role", ("admin",)))

    def test_incomplete_or_malformed_requests_fail_open(self):
        samples = (
            b"",
            request(complete=False),
            b"BROKEN /admin HTTP/1.1\r\n\r\n",
            b"GET /admin HTTP/9.9\r\n\r\n",
            b"GET /admin HTTP/1.1\r\nCookie: session=%%%\r\n\r\n",
        )
        for payload in samples:
            with self.subTest(payload=payload[:20]):
                view = parse_http_request(payload)
                if view is not None:
                    self.assertFalse(view.cookie_claim_matches("session", "role", ("admin",)))

    def test_oversized_cookie_is_ignored(self):
        view = parse_http_request(request(cookie="session=" + "A" * (MAX_COOKIE_VALUE + 1)))
        self.assertIsNotNone(view)
        self.assertFalse(view.cookie_claim_matches("session", "role", ("admin",)))


if __name__ == "__main__":
    unittest.main()
