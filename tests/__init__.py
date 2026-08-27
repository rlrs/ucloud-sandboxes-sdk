"""Shared deterministic settings for the SDK's generated tests."""

from hypothesis import settings


settings.register_profile(
    "ucloud-sdk",
    deadline=None,
    derandomize=True,
    print_blob=True,
)
settings.load_profile("ucloud-sdk")
