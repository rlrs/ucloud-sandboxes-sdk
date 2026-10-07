import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ucloud_sandboxes_sdk import ImageRecipe
from ucloud_sandboxes_sdk.client import AsyncSandboxClient, SandboxApiError, SandboxClient

MODULE = "ucloud_sandboxes_sdk.client"


class FakeGateway:
    """Answers the recipe endpoints as the gateway does; records requests."""

    def __init__(self, contexts=()):
        self.contexts, self.calls, self.states = dict(contexts), [], {}

    def __call__(self, method, path, *, payload=None, body=None, body_size=None, content_type=None,
                 timeout_seconds=None):
        self.calls.append((method, path, payload))
        if path.startswith("/v1/image-contexts/"):
            digest = path.rsplit("/", 1)[1].replace("%3A", ":")
            if method == "GET":
                if digest not in self.contexts:
                    raise SandboxApiError("missing", status_code=404)
                return {"digest": digest, "size": self.contexts[digest]}
            self.contexts[digest] = body_size
            return {"digest": digest, "size": body_size, "deduplicated": False}
        if path == "/v1/image-recipes":
            return {"registered": len(payload["recipes"]), "changed": len(payload["recipes"]),
                    "recipes": [{"name": row["name"], "image_id": "recipe-" + row["context_archive_digest"][7:47],
                                 "changed": True} for row in payload["recipes"]]}
        if path == "/v1/images/ensure":
            return {"images": {name: self.states.get(name, {"state": "unknown"}) for name in payload["names"]}}
        raise AssertionError(path)


def context(root, name, text):
    path = Path(root) / name
    path.mkdir()
    (path / "Dockerfile").write_text(text)
    return path


class ImageRecipeClientTests(unittest.TestCase):
    def test_register_uploads_each_context_once_and_registers_the_names(self):
        with TemporaryDirectory() as root:
            a, b = context(root, "a", "FROM scratch\n"), context(root, "b", "FROM busybox\n")
            client, gateway = SandboxClient("http://gateway"), FakeGateway()
            client._request_json = gateway
            result = client.register_image_recipes([
                ImageRecipe("prime/tmax:task_1", a, retention="pinned"), ImageRecipe("prime/tmax:task_2", b),
                ImageRecipe("alias/tmax:task_1", a)])
            again = client.register_image_recipes([ImageRecipe("prime/tmax:task_1", a, retention="pinned")])
        self.assertEqual(result["registered"], 3)
        puts = [call for call in gateway.calls if call[0] == "PUT"]
        self.assertEqual(len(puts), 2)  # a's context is shared, and the second registration finds it.
        rows = next(call[2]["recipes"] for call in gateway.calls if call[1] == "/v1/image-recipes")
        self.assertEqual(rows[0]["retention"], "pinned")
        self.assertEqual(rows[0]["context_archive_digest"], rows[2]["context_archive_digest"])
        self.assertEqual(set(rows[0]), {"name", "context_archive_digest", "context_archive_size", "dockerfile",
                                        "build_args", "retention"})
        self.assertEqual(again["registered"], 1)

    def test_names_are_batched_and_unique(self):
        client, gateway = SandboxClient("http://gateway"), FakeGateway()
        client._request_json = gateway
        with patch(MODULE + ".IMAGE_RECIPE_BATCH", 2):
            statuses = client.ensure_images(["a:1", "b:1", "a:1", "c:1"])
        self.assertEqual(list(statuses), ["a:1", "b:1", "c:1"])
        self.assertEqual([len(call[2]["names"]) for call in gateway.calls], [2, 1])
        with self.assertRaises(TypeError):
            client.ensure_images("a:1")
        with self.assertRaises(ValueError):
            ImageRecipe("x:1", ".", retention="forever")

    def test_wait_polls_only_unsettled_names_through_transient_errors(self):
        client = SandboxClient("http://gateway")
        client.ensure_images = Mock(side_effect=[
            {"a:1": {"state": "building"}, "b:1": {"state": "failed", "error": "pip"}},
            SandboxApiError("busy", status_code=503),
            {"a:1": {"state": "ready", "reference": "r/a@sha256:" + "0" * 64}},
        ])
        seen = []
        with patch(MODULE + ".time.sleep"):
            final = client.wait_for_images(["a:1", "b:1"], timeout_seconds=600, on_status=seen.append)
        self.assertEqual({name: status["state"] for name, status in final.items()}, {"a:1": "ready", "b:1": "failed"})
        self.assertEqual([call.args[0] for call in client.ensure_images.call_args_list],
                         [["a:1", "b:1"], ["a:1"], ["a:1"]])
        self.assertEqual(len(seen), 3)

    def test_wait_gives_up_at_its_deadline_and_on_permanent_errors(self):
        client, now = SandboxClient("http://gateway"), [0.0]
        client.ensure_images = Mock(return_value={"a:1": {"state": "building"}})

        def sleep(delay):
            now[0] += delay

        with patch(MODULE + ".time.monotonic", side_effect=lambda: now[0]), \
                patch(MODULE + ".time.sleep", side_effect=sleep):
            with self.assertRaisesRegex(TimeoutError, "1 of 1"):
                client.wait_for_images(["a:1"], timeout_seconds=30, poll_interval_seconds=10)
        client.ensure_images = Mock(side_effect=SandboxApiError("bad", status_code=400))
        with self.assertRaises(SandboxApiError):
            client.wait_for_images(["a:1"])

    def test_async_client_registers_and_waits(self):
        async def scenario(root):
            client, gateway = AsyncSandboxClient("http://gateway"), FakeGateway()
            client._request_json = AsyncMock(side_effect=gateway)
            registered = await client.register_image_recipes([ImageRecipe("t:1", context(root, "a", "FROM scratch\n"))])
            gateway.states["t:1"] = {"state": "ready", "reference": "r/t@sha256:" + "0" * 64}
            with patch(MODULE + ".asyncio.sleep", AsyncMock()):
                final = await client.wait_for_images(["t:1"], timeout_seconds=60)
            return registered, final

        with TemporaryDirectory() as root:
            registered, final = asyncio.run(scenario(root))
        self.assertEqual(registered["registered"], 1)
        self.assertEqual(final["t:1"]["state"], "ready")


if __name__ == "__main__":
    unittest.main()
