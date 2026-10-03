from types import SimpleNamespace
import pytest
from inferroute_cli import confidential, pi_attested, agents
from inferroute_local import macos_vm
from inferroute_local.macos_vm import runtime


def test_mac_missing_runtime_refuses_before_pi_or_model(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    monkeypatch.setattr(macos_vm, "required_for", lambda *a: True)
    monkeypatch.setattr(confidential, "_need_extra", lambda: None)
    monkeypatch.setattr(
        confidential,
        "_resolve_model",
        lambda *a: SimpleNamespace(short="synthetic", model_id="synthetic"),
    )

    def fail(*a, **k):
        pytest.fail("host Pi/config/model startup must not run")

    monkeypatch.setattr(agents, "binary_for", fail)
    monkeypatch.setattr(pi_attested, "config_dir", fail)
    monkeypatch.setattr(confidential, "_open_session", fail)

    def refuse():
        raise macos_vm.VMUnavailable("missing authenticated runtime")

    monkeypatch.setattr(runtime, "locate", refuse)
    assert (
        confidential.launch([], agent="pi", probant={"matter": "Synthetic/Active"}) == 2
    )
    assert "Refusing before Pi startup" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_mac_never_accepts_unconfined_launch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "off")
    monkeypatch.setattr(macos_vm, "required_for", lambda *a: True)
    monkeypatch.setattr(confidential, "_need_extra", lambda: None)
    monkeypatch.setattr(
        confidential,
        "_resolve_model",
        lambda *a: SimpleNamespace(short="synthetic", model_id="synthetic"),
    )

    def fail(*a, **k):
        pytest.fail("unconfined mac launch must not resolve runtime or Pi")

    monkeypatch.setattr(runtime, "locate", fail)
    monkeypatch.setattr(agents, "binary_for", fail)
    assert (
        confidential.launch([], agent="pi", probant={"matter": "Synthetic/Active"}) == 2
    )


def test_failed_guest_preflight_never_snapshots_matter(tmp_path, monkeypatch):
    import asyncio
    from inferroute_local.macos_vm import backend as module

    closed = []
    fake_runtime = SimpleNamespace(
        runner=tmp_path / "unused-runner",
        directory=tmp_path,
        close=lambda: closed.append(True),
    )

    async def spawn(*args, **kwargs):
        return SimpleNamespace(returncode=78)

    def snapshot(*args):
        pytest.fail("no matter capability before guest readiness")

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(module, "WorkspaceSnapshot", snapshot)

    async def run():
        backend = module.Backend(fake_runtime, tmp_path)
        with pytest.raises(macos_vm.VMUnavailable, match="before Pi startup"):
            await backend.prepare()
        assert not backend.ready

    asyncio.run(run())
    assert closed == [True]
