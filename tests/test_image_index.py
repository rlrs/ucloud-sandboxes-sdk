import asyncio
import unittest
from urllib import parse

from ucloud_sandboxes_sdk.client import AsyncSandboxClient, SandboxApiError, SandboxClient

NAMES = [{"name": f"prime/tmax:task_{i}", "environment": "tmax", "kind": "build", "state": "not_built"}
         for i in range(5)]


class FakeIndex:
    """Answers the image-index endpoints as the gateway does; records requests."""

    def __init__(self):
        self.calls = []

    def answer(self, method, path, **kwargs):
        self.calls.append((method, path))
        url = parse.urlsplit(path)
        query = dict(parse.parse_qsl(url.query))
        if url.path == "/v1/image-index":
            return {"environments": {"tmax": {"names": 5, "tasks": 5}}, "totals": {"names": 5, "tasks": 5}}
        if url.path == "/v1/image-index/names":
            after, limit = query.get("after", ""), int(query["limit"])
            rows = [row for row in NAMES if row["name"] > after][:limit]
            more = rows and rows[-1]["name"] < NAMES[-1]["name"]
            return {"names": rows, "next": rows[-1]["name"] if more else None}
        if url.path == "/v1/image-index/name":
            if query["name"] != NAMES[0]["name"]:
                raise SandboxApiError("name is not registered", status_code=404,
                                      body={"error_code": "image_name_unknown"})
            return {**NAMES[0], "tasks": ["task_0"]}
        if url.path == "/v1/image-index/task-ids":
            return {"environment": query["environment"], "task_ids": ["task_0", "task_1"],
                    "excluded": {"failed": 1}}
        raise AssertionError(path)


def sync_client():
    client, index = SandboxClient("http://gateway"), FakeIndex()
    client._request_json = index.answer
    return client, index


def async_client():
    client, index = AsyncSandboxClient("http://gateway"), FakeIndex()

    async def answer(method, path, **kwargs):
        return index.answer(method, path, **kwargs)

    client._request_json = answer
    return client, index


class ImageIndexTests(unittest.TestCase):
    def test_summary_names_name_and_task_ids(self):
        client, index = sync_client()
        self.assertEqual(client.image_index_summary()["totals"]["names"], 5)
        self.assertEqual(list(client.image_index_names(environment="tmax", page_size=2)), NAMES)
        pages = [path for _, path in index.calls if path.startswith("/v1/image-index/names")]
        self.assertEqual(len(pages), 3)
        self.assertIn("environment=tmax", pages[0])
        self.assertNotIn("after=", pages[0])
        self.assertIn("after=prime%2Ftmax%3Atask_1", pages[1])
        self.assertEqual(client.image_index_name(NAMES[0]["name"])["tasks"], ["task_0"])
        self.assertIsNone(client.image_index_name("prime/tmax:missing"))
        self.assertEqual(client.image_index_task_ids("tmax"), {
            "environment": "tmax", "task_ids": ["task_0", "task_1"], "excluded": {"failed": 1}})

    def test_async_client_matches(self):
        client, index = async_client()

        async def run():
            names = [row async for row in client.image_index_names(state="not_built", page_size=4)]
            return (await client.image_index_summary(), names, await client.image_index_name("x"),
                    await client.image_index_task_ids("tmax"))

        summary, names, missing, task_ids = asyncio.run(run())
        self.assertEqual(summary["totals"]["tasks"], 5)
        self.assertEqual(names, NAMES)
        self.assertIn("state=not_built", index.calls[0][1])
        self.assertIsNone(missing)
        self.assertEqual(task_ids["task_ids"], ["task_0", "task_1"])

    def test_invalid_arguments_and_answers_are_refused(self):
        client, _ = sync_client()
        for size in (0, 5001, True, 1.5):
            with self.assertRaises(ValueError):
                list(client.image_index_names(page_size=size))
        with self.assertRaises(ValueError):
            client.image_index_task_ids(" ")
        client._request_json = lambda *args, **kwargs: {"task_ids": "task_0"}
        with self.assertRaises(SandboxApiError):
            client.image_index_task_ids("tmax")


if __name__ == "__main__":
    unittest.main()
