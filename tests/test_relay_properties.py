from __future__ import annotations

import base64
from urllib.parse import unquote, urlsplit
import unittest

from hypothesis import given, strategies as st

import ucloud_sandboxes_sdk.relay as relay_module
from ucloud_sandboxes_sdk import (
    RelayApiError,
    RelayRequest,
    http_tunnel_url,
    model_relay_env,
)


REGISTRATION_TOKEN = "0123456789abcdef0123456789abcdef"
INJECTION_CHARACTERS = "/?#%:;@&=+$,[]\\\r\n\t'\"<>|`é雪💥"
UNICODE_SCALARS = st.characters(blacklist_categories=("Cs",))
INJECTION_TEXT = st.tuples(
    st.text(UNICODE_SCALARS, max_size=16),
    st.sampled_from(tuple(INJECTION_CHARACTERS)),
    st.text(UNICODE_SCALARS, max_size=16),
).map(lambda parts: "".join(parts))
JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(UNICODE_SCALARS, max_size=64),
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(
            st.text(UNICODE_SCALARS, max_size=24),
            children,
            max_size=5,
        ),
    ),
    max_leaves=12,
)
MALFORMED_TAGS = st.one_of(
    st.none(),
    st.just({"encoding": "json"}),
    st.builds(
        lambda extra_key: {
            "encoding": "json",
            "value": None,
            extra_key: "injected",
        },
        INJECTION_TEXT.filter(lambda value: value not in {"encoding", "value"}),
    ),
    st.builds(
        lambda encoding: {"encoding": encoding, "value": None},
        INJECTION_TEXT.filter(lambda value: value not in {"json", "base64"}),
    ),
    st.builds(
        lambda value: {"encoding": "base64", "value": value},
        st.one_of(st.none(), st.booleans(), st.integers(), st.lists(JSON_SCALARS)),
    ),
)


def _relay_request() -> RelayRequest:
    return RelayRequest(
        request_id="request",
        rollout_id="rollout",
        registration_token=REGISTRATION_TOKEN,
        endpoint="/v1/chat/completions",
        method="POST",
        headers={},
        body=None,
        body_bytes=b"",
        lease_id="lease",
    )


class RelayPropertyTests(unittest.TestCase):
    @given(rollout_id=INJECTION_TEXT)
    def test_rollout_ids_remain_one_url_path_segment(self, rollout_id: str) -> None:
        model_url = model_relay_env("https://relay.example/", rollout_id)[
            "OPENAI_BASE_URL"
        ]
        model_parts = urlsplit(model_url)
        self.assertEqual(model_parts.query, "")
        self.assertEqual(model_parts.fragment, "")
        self.assertEqual(model_parts.path.split("/")[1::2], ["rollouts", "v1"])
        self.assertEqual(unquote(model_parts.path.split("/")[2]), rollout_id)

        tunnel_url = http_tunnel_url(
            "https://relay.example/",
            rollout_id,
            "/upstream",
            registration_token=REGISTRATION_TOKEN,
        )
        tunnel_parts = urlsplit(tunnel_url)
        self.assertEqual(tunnel_parts.query, "")
        self.assertEqual(tunnel_parts.fragment, "")
        self.assertEqual(
            tunnel_parts.path.split("/")[1:],
            [
                "tunnels",
                tunnel_parts.path.split("/")[2],
                "_relay",
                REGISTRATION_TOKEN,
                "upstream",
            ],
        )
        self.assertEqual(unquote(tunnel_parts.path.split("/")[2]), rollout_id)

    @given(body=st.one_of(st.binary(max_size=1024), JSON_VALUES))
    def test_tagged_response_bodies_round_trip(self, body: object) -> None:
        payload = relay_module._response_payload(_relay_request(), body, 207, None)
        decoded, body_bytes = relay_module._decode_body(payload["body"], payload)

        if isinstance(body, bytes):
            self.assertIsNone(decoded)
            self.assertEqual(body_bytes, body)
            self.assertEqual(payload["body"]["encoding"], "base64")
        else:
            self.assertEqual(decoded, body)
            self.assertEqual(payload["body"]["encoding"], "json")

    @given(tag=MALFORMED_TAGS)
    def test_malformed_body_tags_are_rejected(self, tag: object) -> None:
        with self.assertRaises(RelayApiError):
            relay_module._decode_body(tag, {"body": tag})

    @given(
        prefix=st.binary(max_size=32),
        invalid=st.sampled_from(("%", "?", "#", "\r", "\n", "\x00", "é", "💥")),
        suffix=st.binary(max_size=32),
    )
    def test_injected_base64_is_rejected(
        self,
        prefix: bytes,
        invalid: str,
        suffix: bytes,
    ) -> None:
        value = (
            base64.b64encode(prefix).decode("ascii")
            + invalid
            + base64.b64encode(suffix).decode("ascii")
        )
        with self.assertRaisesRegex(RelayApiError, "base64 body is invalid"):
            relay_module._decode_body(
                {"encoding": "base64", "value": value},
                {"body": value},
            )


if __name__ == "__main__":
    unittest.main()
