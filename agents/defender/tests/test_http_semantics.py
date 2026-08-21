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


def json_request(method, target, document):
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return (
        f"{method} {target} HTTP/1.1\r\nHost: service\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body


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

    def test_graphql_semantics_survive_route_and_query_encoding(self):
        samples = (
            request("/%67%72%61%70%68%71%6C?query=%257B%2520missionAudit%2520%257Bnotes%257D%257D"),
            request("http://service:8082/%25%36%37%72%61%70%68%71%6C?query={missionAudit}"),
            json_request(
                "POST", "/%67%72%25%36%31%70%68%71%6C",
                {"query": "{ missionAudit { lastDeployment { notes } } }"},
            ),
        )
        for payload in samples:
            with self.subTest(payload=payload[:50]):
                view = parse_http_request(payload)
                self.assertEqual(view.path, "/graphql")
                self.assertTrue(view.graphql_field_matches(
                    "query", ("missionAudit",), ("query",)
                ))

    def test_graphql_substrings_and_normal_queries_do_not_match(self):
        samples = (
            request("/graphql?query={notmissionAuditLog}"),
            json_request("POST", "/graphql", {"query": "{ systemHealth }"}),
            json_request("POST", "/graphql", {"operation": "missionAudit"}),
        )
        for payload in samples:
            view = parse_http_request(payload)
            self.assertFalse(view.graphql_field_matches(
                "query", ("missionAudit",), ("query",)
            ))

    def test_rsc_base64_ref_matches_exact_environment_name(self):
        ref = base64.b64encode(b"process.env.MC2_INTERNAL_API_TOKEN").decode("ascii")
        view = parse_http_request(json_request(
            "POST", "/api/rsc-action", {"ref": ref, "token": "session"}
        ))
        self.assertTrue(view.json_base64_matches(
            "ref", ("process.env.MC2_INTERNAL_API_TOKEN",)
        ))
        self.assertFalse(view.json_base64_matches("ref", ("process.env.FLAG",)))

    def test_rsc_base64_ref_accepts_only_bounded_observed_noise(self):
        encoded = base64.b64encode(b"process.env.MC2_INTERNAL_API_TOKEN").decode("ascii")
        for marker in (" ", ".", "*", "~"):
            noisy = marker.join((encoded[:12], encoded[12:28], encoded[28:]))
            view = parse_http_request(json_request(
                "POST", "/api/rsc-action", {"ref": noisy}
            ))
            self.assertTrue(view.json_base64_matches(
                "ref", ("process.env.MC2_INTERNAL_API_TOKEN",)
            ))

        invalid = parse_http_request(json_request(
            "POST", "/api/rsc-action", {"ref": encoded[:12] + "!" + encoded[12:]}
        ))
        self.assertFalse(invalid.json_base64_matches(
            "ref", ("process.env.MC2_INTERNAL_API_TOKEN",)
        ))

    def test_portal_ssti_requires_full_observed_token_chain(self):
        malicious = parse_http_request(request(
            "/portal/feedback?service_id=%7B%7B%20(lipsum%7Cattr('__globals__'))"
            ".get('__builtins__').get('open')('/flag').read()%20%7D%7D"
        ))
        normal = parse_http_request(request(
            "/portal/feedback?service_id=please+open+flag+report"
        ))
        required = ("lipsum", "attr", "__globals__", "__builtins__", "open", "flag")
        self.assertTrue(malicious.query_token_set_matches(("service_id",), required))
        self.assertFalse(normal.query_token_set_matches(("service_id",), required))


if __name__ == "__main__":
    unittest.main()


class TestPathTraversalCanonicalization(unittest.TestCase):
    def test_encoding_variants_collapse_to_flag(self):
        variants = (
            "/config?file=../../../../flag",
            "/config?file=....//....//flag",
            "/config?file=..%c0%afflag",
            "/config?file=..;/..;/flag",
            "/config?file=..\\..\\flag",
            "/config?file=..%5c..%5cflag",
            "/config?file=..%252f..%252fflag",
        )
        for target in variants:
            with self.subTest(target=target):
                view = parse_http_request(request(target))
                self.assertTrue(
                    view.path_traversal_target_matches(("file",), ("flag",)),
                    msg=target,
                )

    def test_benign_config_query_does_not_match(self):
        view = parse_http_request(request("/config?file=settings.json"))
        self.assertFalse(view.path_traversal_target_matches(("file",), ("flag",)))
        view = parse_http_request(request("/config?file=flag"))
        self.assertFalse(view.path_traversal_target_matches(("file",), ("flag",)))
