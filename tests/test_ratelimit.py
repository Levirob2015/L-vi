import pytest

from loginshield.ratelimit import SlidingWindow


def test_limit_wird_durchgesetzt():
    window = SlidingWindow(limit=3, window=60)
    assert [window.hit("a", now=0)[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after, count = window.hit("a", now=0)
    assert not allowed
    assert retry_after > 0
    assert count == 4


def test_fenster_gleitet():
    window = SlidingWindow(limit=2, window=10)
    window.hit("a", now=0)
    window.hit("a", now=5)
    assert not window.hit("a", now=6)[0]
    # Der Treffer bei 0 faellt aus dem Fenster, die anderen beiden nicht.
    assert window.hit("a", now=11)[0] is False
    # Erst wenn alle alten Treffer verfallen sind, geht es weiter.
    assert window.hit("a", now=22)[0] is True


def test_abgewiesene_versuche_zaehlen_weiter_mit():
    # Wer nach der Sperre weiter haemmert, verlaengert seine eigene Wartezeit.
    window = SlidingWindow(limit=1, window=10)
    window.hit("a", now=0)
    _, first_retry, _ = window.hit("a", now=1)
    _, second_retry, count = window.hit("a", now=9)
    assert count == 3
    # Der aelteste Treffer bestimmt die Wartezeit, sie sinkt mit der Zeit.
    assert second_retry < first_retry


def test_schluessel_sind_unabhaengig():
    window = SlidingWindow(limit=1, window=60)
    assert window.hit("a", now=0)[0]
    assert window.hit("b", now=0)[0]
    assert not window.hit("a", now=0)[0]


def test_reset():
    window = SlidingWindow(limit=1, window=60)
    window.hit("a", now=0)
    window.reset("a")
    assert window.hit("a", now=0)[0]
    window.hit("b", now=0)
    window.reset()
    assert len(window) == 0


def test_speicher_ist_gedeckelt():
    window = SlidingWindow(limit=5, window=60, max_keys=10)
    for index in range(100):
        window.hit(f"ip-{index}", now=0)
    assert len(window) <= 10


def test_ungueltige_parameter():
    with pytest.raises(ValueError):
        SlidingWindow(limit=0, window=60)
    with pytest.raises(ValueError):
        SlidingWindow(limit=5, window=0)


def test_peek_zaehlt_nicht_mit():
    window = SlidingWindow(limit=2, window=60)
    window.hit("a", now=0)
    assert window.peek("a", now=0) == 1
    assert window.peek("a", now=0) == 1
    assert window.peek("unbekannt", now=0) == 0
