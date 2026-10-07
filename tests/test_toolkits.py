import unittest

from ucloud_sandboxes_sdk import Image, SandboxSpec


class ToolkitSpecTests(unittest.TestCase):
    def test_a_spec_without_toolkits_sends_exactly_what_it_sent_before(self):
        self.assertNotIn("toolkits", SandboxSpec(id="a", image=Image.from_registry("r/i:1")).to_dict())

    def test_toolkits_are_sent_as_a_list_of_references(self):
        spec = SandboxSpec(id="a", image=Image.from_registry("r/i:1"),
                           toolkits=("vf-harness:v1", "x@sha256:" + "b" * 64))
        self.assertEqual(spec.to_dict()["toolkits"], ["vf-harness:v1", "x@sha256:" + "b" * 64])

    def test_a_single_string_is_not_mistaken_for_a_list_of_toolkits(self):
        with self.assertRaisesRegex(TypeError, "sequence"):
            SandboxSpec(id="a", image=Image.from_registry("r/i:1"), toolkits="vf-harness:v1")


if __name__ == "__main__":
    unittest.main()
