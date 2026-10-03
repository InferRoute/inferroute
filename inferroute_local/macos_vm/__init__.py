"""macOS Linux VM confinement. Unsigned/missing runtimes never launch agents."""


class VMUnavailable(RuntimeError):
    """Required VM confinement cannot be established; never downgrade."""


def required_for(agent, probant=None):
    import sys

    return sys.platform == "darwin" and agent == "pi" and probant is not None
