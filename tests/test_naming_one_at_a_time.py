from inferroute_cli.naming_demo.server import OneAtATime


def test_one_run_at_a_time_per_network():
    g = OneAtATime()
    assert g.take("a")
    assert not g.take("a")      # same network, run still going
    assert g.take("b")          # another network
    g.give("a")
    assert g.take("a")          # free again once the first run ended
    assert g.take("") and g.take("")  # no key (old site build): never blocked
