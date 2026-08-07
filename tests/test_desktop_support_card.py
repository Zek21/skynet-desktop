"""The daily support card: shown once a day, dismissible, and pointing at the RIGHT wallet.

Owner directive 2026-08-07: the desktop app should surface the sponsorship ask once a day and
carry the support QR. Two things here are worth locking rather than trusting:

1. **The QR encodes a payment URL.** If those bytes are ever swapped -- by accident or not --
   sponsors' money goes somewhere else, and nobody would notice by looking at the app. The
   image is a hash-pinned payload member in the release gate, and this suite decodes it.
2. **"Once a day" is easy to get subtly wrong.** A UTC day boundary shows the card twice in one
   local day for anyone west of UTC; a rolling 24h window drifts later on every launch until it
   interrupts mid-session. The renderer uses a LOCAL calendar-day stamp, pinned below.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "desktop" / "renderer"
SUPPORT_QR = RENDERER / "support-qr.png"
SUPPORT_URL = "https://paypal.me/exzilcalanza"


def read(name: str) -> str:
    return (RENDERER / name).read_text(encoding="utf-8")


def test_the_support_qr_ships_with_the_app():
    assert SUPPORT_QR.is_file(), "the support QR must be a real payload member, not a remote asset"
    assert SUPPORT_QR.stat().st_size > 0


def test_the_support_qr_decodes_to_the_owners_wallet():
    """The one test that would catch a swapped or corrupted payment QR."""
    cv2 = pytest.importorskip("cv2", reason="OpenCV needed to decode the QR")
    image = cv2.imread(str(SUPPORT_QR))
    assert image is not None, "support QR is not a readable image"

    decoded, _points, _straight = cv2.QRCodeDetector().detectAndDecode(image)

    assert decoded == SUPPORT_URL, f"support QR points at {decoded!r}, not the owner's wallet"


def test_the_card_is_in_the_markup_with_the_qr_and_the_link():
    html = read("index.html")
    assert 'id="supportCard"' in html
    assert 'id="supportClose"' in html
    assert 'src="support-qr.png"' in html
    assert SUPPORT_URL in html


def test_the_card_is_dismissible():
    """A sponsorship ask with no way out is a dark pattern."""
    html = read("index.html")
    app = read("app.js")
    assert 'id="supportClose"' in html
    assert "dismissSupportCard" in app
    assert "supportClose" in app and "addEventListener" in app


def test_the_card_starts_hidden_so_it_cannot_flash_before_the_day_check():
    html = read("index.html")
    card = re.search(r"<div class=\"support-card\"[^>]*>", html)
    assert card and "hidden" in card.group(0)


def test_the_hidden_attribute_is_not_defeated_by_a_bare_display_rule():
    """`display:flex` out-ranks the [hidden] attribute -- the exact trap that pinned an
    earlier panel permanently on screen."""
    css = read("app.css")
    assert ".support-card:not([hidden])" in css
    assert not re.search(r"^\.support-card\s*\{[^}]*display\s*:", css, re.MULTILINE | re.DOTALL)


def test_the_qr_sits_on_a_white_plate_so_it_stays_scannable():
    """Black-on-transparent over a dark UI renders black-on-black and never scans."""
    css = read("app.css")
    block = re.search(r"\.support-qr\s*\{[^}]*\}", css)
    assert block and re.search(r"background:\s*#fff", block.group(0))


def test_the_frequency_is_a_LOCAL_calendar_day():
    app = read("app.js")
    assert "localDayStamp" in app
    body = re.search(r"function localDayStamp\([^)]*\)\s*\{(.*?)\n  \}", app, re.DOTALL)
    assert body, "localDayStamp must exist as a named, reviewable rule"
    code = body.group(1)

    assert "getFullYear" in code and "getMonth" in code and "getDate" in code
    # A UTC stamp rolls over mid-evening for western timezones and shows the card twice in one
    # local day. Assert against the FUNCTION BODY -- the surrounding comment names toISOString
    # precisely to explain why it is wrong, so scanning the whole file matches the warning.
    assert "toISOString" not in code
    assert "getUTC" not in code


def test_the_due_rule_is_seen_today_or_not():
    """Pin the actual predicate: due when never seen or last seen on another day."""
    app = read("app.js")
    body = re.search(r"function supportCardDue\([^)]*\)\s*\{(.*?)\n  \}", app, re.DOTALL)
    assert body, "supportCardDue must exist as a named, reviewable rule"
    assert "!lastShown || lastShown !== today" in body.group(1)


def test_unavailable_storage_does_not_nag_on_every_launch():
    """If localStorage throws, the card must NOT fall back to showing every time."""
    app = read("app.js")
    reader = re.search(r"function readSupportLastShown\(\)\s*\{(.*?)\n  \}", app, re.DOTALL)
    assert reader
    # The catch branch returns TODAY, i.e. "already shown", rather than null/"".
    assert "return localDayStamp();" in reader.group(1)


def test_the_ask_is_framed_as_sponsorship_not_investment():
    """Standing branding rule: this is sponsorship, never equity or investment."""
    html = read("index.html")
    assert re.search(r"Sponsorship\s*—\s*not equity or investment", html, re.IGNORECASE)


def test_the_qr_is_a_reviewed_release_payload_member():
    """Hash-pinned in the gate, so the payment target cannot change without failing release."""
    from tools import skynet_desktop_release_gate as gate
    from tools import skynet_desktop_build_stamp as stamp

    assert "renderer/support-qr.png" in gate.SOURCE_MEMBERS
    assert "renderer/support-qr.png" in stamp.SOURCE_MEMBERS
