import asyncio
import io
import json
import unittest
from unittest.mock import AsyncMock, patch

from tests import test_client as helpers
import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import AsyncSandboxClient, Image, SandboxApiError, SandboxClient


class BuilderAdmissionTests(unittest.TestCase):
    def test_sync_submission_waits_for_cold_builder_without_reuploading_context(self):
        submissions = []
        uploads = []
        timeouts = []

        def respond(req, timeout=None):
            timeouts.append(timeout)
            if req.method == "PUT":
                uploads.append(req.full_url)
            if req.full_url.endswith("/v1/images/build"):
                submissions.append(req.data)
                if len(submissions) <= 8:
                    code = ("builder_not_ready", "builder_busy", "node_admission_closed")[(len(submissions)-1) % 3]
                    raise client_module.error.HTTPError(req.full_url, 503, "not admitted", {"Retry-After": "0"},
                        io.BytesIO(json.dumps({"retryable": True, "error_code": code}).encode()))
                return helpers._SyncResponse(b'{"build":{"build_id":"build-one","status":"running"}}')
            return helpers._SyncResponse(b'{}')

        with helpers.docker_context() as context, patch.object(client_module, "open_no_redirect", respond), patch.object(client_module.time, "sleep"):
            result = SandboxClient("http://gateway.invalid").submit_image_build(Image.from_dockerfile(name="image", context_path=context))
        self.assertEqual(result["build_id"], "build-one")
        self.assertEqual(len(submissions), 9)
        self.assertTrue(all(body == submissions[0] for body in submissions))
        self.assertEqual(len(uploads), 1)
        self.assertGreater(timeouts[0], 590)
        self.assertLessEqual(timeouts[0], 600)

    def test_async_submission_waits_for_cold_builder_and_honors_explicit_timeout(self):
        submissions = []

        def respond(method, url, kwargs, _call):
            if str(url).endswith("/v1/images/build"):
                submissions.append(kwargs)
                if len(submissions) <= 8:
                    return helpers._AsyncResponse('{"retryable":true,"error_code":"builder_not_ready"}', status=503)
                return helpers._AsyncResponse('{"build":{"build_id":"build-one","status":"running"}}')
            return helpers._AsyncResponse('{}')

        async def scenario(context):
            session = helpers._ScriptedAsyncSession(respond)
            client = AsyncSandboxClient("http://gateway.invalid", session=session)
            with patch.object(client_module, "_async_sleep_for_retry", AsyncMock(return_value=True)):
                result = await client.submit_image_build(Image.from_dockerfile(name="image", context_path=context), timeout_seconds=123)
            self.assertEqual(result["build_id"], "build-one")
            self.assertEqual(sum(method == "PUT" for method, *_ in session.requests), 1)

        with helpers.docker_context() as context:
            asyncio.run(scenario(context))
        self.assertEqual(len(submissions), 9)
        self.assertTrue(all(req["data"] == submissions[0]["data"] for req in submissions))
        self.assertGreater(submissions[0]["timeout"].total, 120)
        self.assertLessEqual(submissions[0]["timeout"].total, 123)

    def test_build_does_not_retry_ambiguous_or_terminal_failure(self):
        for body in ({"retryable": True}, {"error_code": "builder_not_ready", "retryable": False}):
            with self.subTest(body=body):
                failure = client_module.error.HTTPError("http://gateway.invalid/v1/images/build", 503, "failed", {}, io.BytesIO(json.dumps(body).encode()))
                with patch.object(client_module, "open_no_redirect", side_effect=failure) as post, self.assertRaises(SandboxApiError):
                    SandboxClient("http://gateway.invalid")._request_json("POST", "/v1/images/build", payload={"id": "image"})
                self.assertEqual(post.call_count, 1)

    def test_build_admission_wait_stops_at_deadline(self):
        clock = [0.0]
        def reject(req, timeout=None):
            raise client_module.error.HTTPError(req.full_url, 503, "not ready", {"Retry-After": "1"},
                io.BytesIO(b'{"retryable":true,"error_code":"builder_not_ready"}'))
        with (
            patch.object(client_module, "open_no_redirect", side_effect=reject) as post,
            patch.object(client_module.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(client_module.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0]+delay)),
            patch.object(client_module.random, "random", return_value=0),
            self.assertRaises(SandboxApiError),
        ):
            SandboxClient("http://gateway.invalid")._request_json("POST", "/v1/images/build", payload={"id": "image"}, timeout_seconds=2)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(clock[0], 1)
