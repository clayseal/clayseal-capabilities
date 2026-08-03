"""Sandbox backend resolution — the substrate is a deployment choice."""
import pytest

from agentauth.capabilities.sandbox.backend import (
    PLUGIN_GROUP,
    IVisorBackend,
    SandboxBackend,
    default_sandbox_backend,
)


@pytest.fixture
def clean_registry():
    from agentauth.core import plugins
    before = dict(getattr(plugins, "_REGISTRY", {}).get(PLUGIN_GROUP, {}))
    yield
    registry = getattr(plugins, "_REGISTRY", {})
    if PLUGIN_GROUP in registry:
        registry[PLUGIN_GROUP].clear()
        registry[PLUGIN_GROUP].update(before)


def test_default_is_the_builtin_ivisor_backend():
    backend = default_sandbox_backend()
    assert isinstance(backend, IVisorBackend)
    assert backend.name == "ivisor"


def test_builtin_satisfies_the_protocol():
    assert isinstance(IVisorBackend(), SandboxBackend)


def test_registered_plugin_shadows_the_builtin(clean_registry):
    from agentauth.core.plugins import register_plugin

    class FakeBackend:
        name = "ivisor"

        def run(self, spec, **sinks):
            return "fake outcome"

    register_plugin(PLUGIN_GROUP, "ivisor", FakeBackend())
    assert default_sandbox_backend().run(None) == "fake outcome"


def test_alternative_substrate_can_register_under_its_own_name(clean_registry):
    from agentauth.core.plugins import register_plugin

    class GvisorBackend:
        name = "gvisor"

        def run(self, spec, **sinks):
            return "gvisor outcome"

    register_plugin(PLUGIN_GROUP, "gvisor", GvisorBackend())
    assert default_sandbox_backend("gvisor").name == "gvisor"


def test_unknown_backend_raises_with_registration_guidance():
    with pytest.raises(LookupError, match="register_plugin"):
        default_sandbox_backend("does-not-exist")
