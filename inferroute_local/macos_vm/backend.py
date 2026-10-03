"""Lifecycle adapter used by confidential.launch; native stdout remains Pi RPC."""

import asyncio, socket, threading
from . import VMUnavailable
from .broker import Broker
from .workspace import WorkspaceSnapshot


class Backend:
    def __init__(self, runtime, workspace):
        self.runtime = runtime
        self.workspace = workspace
        self.snapshot = None
        self.proc = None
        self.broker = None
        self.errors = []
        self.sockets = []
        self.thread = None
        self.exported = ()

    @property
    def ready(self):
        return (
            self.broker is not None
            and self.broker.ready.is_set()
            and not self.errors
            and self.proc is not None
            and self.proc.returncode is None
        )

    @property
    def label(self):
        return (
            "require, Linux VM (no NIC or host shares; address-level guest confinement)"
            if self.ready
            else "required Linux VM confinement unavailable"
        )

    async def prepare(self):
        # No active matter bytes released until guest preflight succeeds.
        # Take the approved snapshot only after readiness; initial broker has empty capability.
        class Empty:
            files = {}

        self.broker = Broker(Empty())
        host, child = socket.socketpair()
        status, status_child = socket.socketpair()
        host.settimeout(600)
        status.settimeout(600)
        self.sockets = [host, child, status, status_child]

        def serve():
            try:
                self.broker.serve(host)
            except BaseException as e:
                self.errors.append(type(e).__name__)
            finally:
                try:
                    host.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                host.close()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

        def serve_status():
            try:
                self.broker.serve_status(status)
            except BaseException as e:
                if not self.broker.complete:
                    self.errors.append(type(e).__name__)
            finally:
                status.close()

        self.status_thread = threading.Thread(target=serve_status, daemon=True)
        self.status_thread.start()
        try:
            self.proc = await asyncio.create_subprocess_exec(
                str(self.runtime.runner),
                "--owned-runtime",
                str(self.runtime.directory / "boot.json"),
                "--bridge-fd",
                str(child.fileno()),
                "--status-fd",
                str(status_child.fileno()),
                pass_fds=(child.fileno(), status_child.fileno()),
                env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty"},
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            child.close()
            status_child.close()
            deadline = asyncio.get_running_loop().time() + 30
            while not self.ready:
                if (
                    self.errors
                    or self.proc.returncode is not None
                    or asyncio.get_running_loop().time() > deadline
                ):
                    raise VMUnavailable(
                        "VM confinement preflight failed before Pi startup"
                    )
                await asyncio.sleep(0.02)
            self.snapshot = WorkspaceSnapshot(self.workspace)
            self.broker.snapshot = self.snapshot
        except BaseException:
            await self.close()
            raise

    def configure(
        self, plan, *, model_url, model_key, search_url=None, create_drafts=False
    ):
        if not self.ready:
            raise VMUnavailable("VM preflight is not ready")
        self.broker.configure(plan, model_url, model_key, search_url, create_drafts)

    async def finish(self):
        code = await self.proc.wait()
        await asyncio.to_thread(self.thread.join, 5)
        if code != 0 or self.errors or not self.broker.complete:
            raise VMUnavailable("VM stop/export completion could not be proved")
        # Agent output is held host-side until native runner has proved VM .stopped.
        if self.broker.agent_exit == 0:
            self.exported = self.snapshot.commit(self.broker.uploads)
        return self.broker.agent_exit

    async def close(self):
        if self.broker is not None:
            self.broker.close()
        if self.proc is not None and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 10)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        for stream in self.sockets:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        if self.thread is not None:
            await asyncio.to_thread(self.thread.join, 2)
        if getattr(self, "status_thread", None) is not None:
            await asyncio.to_thread(self.status_thread.join, 2)
        if self.snapshot is not None:
            self.snapshot.close()
            self.snapshot = None
        if self.runtime is not None:
            self.runtime.close()
            self.runtime = None
