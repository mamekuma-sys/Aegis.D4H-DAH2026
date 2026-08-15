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
        self.assertEqual(view.path, "/admin")
        self.assertEqual(view.query_pairs, (("view", "1"),))

    def test_empty_query_does_not_change_protected_route(self):
        view = parse_http_request(request("/admin?"))
        self.assertEqual(view.path, "/admin")

    def test_claim_order_and_boolean_values_do_not_break_parser(self):
        value = encoded({"admin": True, "role": "admin", "user": "operator"})
        view = parse_http_request(request(cookie=f"other=x; session={value}"))
        self.assertTrue(view.cookie_claim_matches("session", "role", ("admin",)))
        self.assertTrue(view.cookie_claim_matches("session", "admin", ("true",)))

    def test_observed_lenient_base64_noise_and_padding_are_canonicalized(self):
        value = encoded({"role": "admin", "user": "guest"})
        variants = (
            value + "==",
            value.rstrip("=") + "====",
            value[:8] + "..*~.." + value[8:],
            value[:12] + " " + value[12:],
        )
        for variant in variants:
            with self.subTest(length=len(variant)):
                view = parse_http_request(request(cookie=f"session={variant}"))
                self.assertTrue(view.cookie_claim_matches("session", "role", ("admin",)))

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

    def test_nested_and_canonical_ssrf_targets_match(self):
        targets = (
            "/fetch?url=http%3A%2F%2Fhelper-box%3A08080%2F%2Fsecret",
            "/fetch?url=http%3A%2F%2F127.0.0.1%3A8082%2Ffetch%3Furl%3Dhttp%253A%252F%252FHELPER-BOX.%253A8080%252Fsecret%253F",
        )
        for target in targets:
            with self.subTest(target=target):
                view = parse_http_request(request(target))
                self.assertTrue(view.ssrf_target_matches(
                    ("url",), ("helper-box",), (8080,), "/secret"
                ))

    def test_ssrf_scope_mismatches_do_not_match(self):
        view = parse_http_request(request(
            "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fhealth"
            "&next=http%3A%2F%2Fexample.invalid%3A8080%2Fsecret"
        ))
        self.assertFalse(view.ssrf_target_matches(
            ("url",), ("helper-box",), (8080,), "/secret"
        ))
        self.assertFalse(view.ssrf_target_matches(
            ("next",), ("helper-box",), (8080,), "/secret"
        ))
        self.assertFalse(view.ssrf_target_matches(
            ("url",), ("helper-box",), (8081,), "/health"
        ))

    def test_sql_comments_controls_and_brackets_are_canonicalized(self):
        targets = (
            "/product?id=-1%20UNION%0A%0ASELECT%20k%2Cv%2C3%20FROM%20app_meta",
            "/product?id=0%2F%2Ax%2A%2FUNION%2F%2Ax%2A%2FSELECT%2F%2Ax%2A%2F1%2Cv%2C3%2F%2Ax%2A%2FFROM%2F%2Ax%2A%2F%5Bapp_meta%5D",
        )
        for target in targets:
            with self.subTest(target=target):
                view = parse_http_request(request(target))
                self.assertTrue(view.sql_source_matches(("id",), "app_meta"))

    def test_partial_or_wrong_parameter_sql_markers_do_not_match(self):
        targets = (
            "/product?id=select%20v%20from%20app_meta",
            "/product?id=union%20select%20app_meta",
            "/product?note=union%20select%20v%20from%20app_meta&id=1",
            "/product?id=union%20select%20v%20from%20products",
        )
        for target in targets:
            with self.subTest(target=target):
                view = parse_http_request(request(target))
                self.assertFalse(view.sql_source_matches(("id",), "app_meta"))


if __name__ == "__main__":
    unittest.main()
