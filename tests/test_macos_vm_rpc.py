import asyncio
from types import SimpleNamespace
import pytest
from inferroute_cli import probant_web as W


@pytest.mark.parametrize("terminates_line", [False, True])
def test_oversized_guest_record_is_bounded_and_stops_agent(tmp_path, terminates_line):
    bridge = W.Bridge(
        matter="Synthetic/Active",
        date_bound="2020-01-01",
        workspace=tmp_path,
        summary={},
        search_endpoint="",
        receipt=lambda: SimpleNamespace(counters={}),
        rebuild_summary=lambda: {},
        export=lambda: tmp_path / "record",
    )

    class Stream:
        def __init__(self):
            self.reads = 0

        async def read(self, size):
            self.reads += 1
            assert self.reads <= 129
            if self.reads == 129 and terminates_line:
                return b"x" * 65535 + b"\n"
            return b"x" * 65536

    stream = Stream()
    stopped = []

    async def stop():
        stopped.append(True)

    bridge.stop_agent = stop

    async def run():
        with pytest.raises(ValueError, match="RPC event exceeded"):
            await bridge.pump(
                SimpleNamespace(stdout=stream, stdin=None, returncode=None)
            )

    asyncio.run(run())
    assert stopped == [True]
    assert stream.reads == 129
