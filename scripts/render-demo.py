#!/usr/bin/env python3
# File purpose: Rebuilds the illustrated README demo from SVG scenes and project logo assets.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Render the silent display-management demo with FFmpeg's librsvg decoder.

The scene follows unsynchronized startup, a shared playlist start time, alerts,
a broadcast, one display's link loss and screen-power behavior.
Run from any directory; --preview-dir also saves selected SVG/PNG review frames.
"""

import argparse
import base64
from html import escape
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

WIDTH, HEIGHT, DURATION = 1280, 720, 58.0
FPS, LOGO_LOOP = 10, 3.6
SCREEN_WIDTH = 288
SCREEN_HEIGHT = SCREEN_WIDTH * 9 // 16
CORNER_OVERLAY_HEIGHT = 20
BANNER_GAP = 6

# Illustrative timings. Each display starts on its own (renderer start, then
# authenticated); only the playlist start time is shared, as in the renderer.
STARTUP = ((0.0, 2.8), (1.4, 5.4), (3.0, 6.6))
PLAYLIST_START, ROTATION = 8.0, 4.0
# Each banner, serial light and sound is a separate command.
ALERTS = (
    {"start": 16.0, "end": 23.0, "severity": "warning", "message": "Link congestion",
     "light": (16.2, 24.0), "sound": (16.4, 17.12)},
    {"start": 19.5, "end": 26.0, "severity": "critical", "message": "Database latency",
     "light": (19.7, 27.0), "sound": (19.9, 20.98)},
    {"start": 23.0, "end": 28.0, "severity": "info", "message": "Deployment in progress",
     "light": (23.2, 29.0), "sound": (23.4, 23.95)},
)
BROADCAST = {"start": 30.5, "end": 35.5, "severity": "info",
             "message": "Maintenance tonight at 22:00", "sound": (30.7, 31.25)}
# The loaded pages keep rotating; the status N turns red once the loss is detected.
LINK_LOSS = {"display": 1, "start": 36.0, "detected": 36.6, "restored": 43.0}
# The controller's own wording one minute before a scheduled power-off.
REMINDER = {"start": 46.0, "end": 50.0, "severity": "warning",
            "message": "Screen will turn off in 1 minute"}
POWER_OFF, POWER_ON = 50.0, 54.0
BANNER_COLORS = {"info": "#1565c0", "warning": "#ef6c00", "critical": "#c62828"}
PHASES = ((0.0, 8.0, "STARTUP"), (8.0, 16.0, "PLAYLISTS"), (16.0, 30.0, "ALERTS"),
          (30.0, 36.0, "BROADCAST"), (36.0, 46.0, "LINK LOSS"),
          (46.0, 58.0, "SCREEN POWER"))
# Displays 02 and 03 rotate with one interval and start time, so they change together.
PLAYLISTS = (("Infrastructure",), ("Network", "Database", "Throughput"),
             ("Service health", "Storage"))
PAGES = {
    "Infrastructure": ("Hosts and service capacity", "HOSTS ONLINE", "24 / 24",
                       "CPU AVERAGE", "42%", "Cluster activity", "#5bb9f6", 0.0),
    "Network": ("Core links and edge traffic", "UPLINK", "840 Mb/s",
                "PACKET LOSS", "0.02%", "Traffic over time", "#5bb9f6", 1.2),
    "Database": ("Queries and storage response", "QUERIES / SEC", "1,280",
                 "P95 LATENCY", "18 ms", "Query latency", "#b493ed", 2.1),
    "Throughput": ("Requests across the application", "REQUESTS / SEC", "3,420",
                   "SUCCESS RATE", "99.98%", "Application throughput", "#41c78f", 3.0),
    "Service health": ("Customer-facing application status", "AVAILABLE", "99.99%",
                       "SERVICES", "12 / 12", "Response time", "#41c78f", 0.7),
    "Storage": ("Capacity and backup status", "USED CAPACITY", "61%",
                "LAST BACKUP", "02:00", "Daily growth", "#5bb9f6", 2.6),
}


def _text(x, y, value, size=12, color="#b8cce0", weight=400, anchor="start"):
    """Return escaped SVG text with explicit typography."""
    return (f'<text x="{x:g}" y="{y:g}" font-size="{size:g}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{escape(str(value))}</text>')


def _rect(x, y, width, height, fill, radius=0, stroke="none", extra=""):
    """Return one rectangle with optional border and SVG attributes."""
    return (f'<rect x="{x:g}" y="{y:g}" width="{width:g}" height="{height:g}" '
            f'rx="{radius:g}" fill="{fill}" stroke="{stroke}" {extra}/>')


def _image(x, y, width, height, uri):
    """Embed a supplied PNG data URI without adding external dependencies."""
    if not uri:
        return ""
    return (f'<image x="{x:g}" y="{y:g}" width="{width:g}" height="{height:g}" '
            f'href="{escape(uri, quote=True)}" preserveAspectRatio="xMidYMid meet"/>')


def _during(t, window):
    """Test a half-open time interval for independently timed outputs."""
    return window[0] <= t < window[1]


def _light_on(t, alert):
    """Blink an amber serial light at 1 Hz and 50 percent duty cycle."""
    return (_during(t, alert["light"])
            and int((t - alert["light"][0] + 1e-9) * 2) % 2 == 0)


def _link_down(display, t):
    """Report whether one display's network link is down, detected or not."""
    return (display == LINK_LOSS["display"]
            and _during(t, (LINK_LOSS["start"], LINK_LOSS["restored"])))


def _link_lost(display, t):
    """Report whether one display's status N shows a detected link loss."""
    return (display == LINK_LOSS["display"]
            and _during(t, (LINK_LOSS["detected"], LINK_LOSS["restored"])))


def _clock(t):
    """Show morning playback, then jump to the evening power-off and next morning."""
    if t < REMINDER["start"]:
        seconds = 9 * 3600 + t
    elif t < POWER_ON:
        seconds = 18 * 3600 - (POWER_OFF - t)
    else:
        seconds = 8 * 3600 + t - POWER_ON
    seconds = int(seconds)
    return f"{seconds // 3600:02}:{seconds // 60 % 60:02}:{seconds % 60:02}"


def _header(logos):
    """Draw the product header and identify the illustration."""
    return "".join((
        _rect(0, 0, WIDTH, 86, "#0e1b2b"),
        _image(20, 8, 235, 70, logos.get("brand", "")),
        '<path d="M270 22v42" stroke="#35485e"/>',
        _text(294, 39, "Display management example", 25, "#f1f5fc", 700),
        _text(294, 65, "Web dashboards · Display actions · Self-hosted", 13, "#9bb4ce"),
        _text(1240, 35, "ILLUSTRATIVE DEMO", 10, "#8fa7c2", 700, "end"),
        _text(1240, 57, "Three Linux display clients", 11, "#8fa7c2", 400, "end"),
    ))


def _room():
    """Build the wall, floor, chair and desk behind the three displays."""
    out = [_rect(0, 86, 1280, 538, "#17283c"), _rect(0, 86, 266, 538, "#122035"),
           _rect(270, 86, 974, 422, "#20344c")]
    for x in (278, 600, 922, 1236):
        out.append(f'<path d="M{x} 86v422" stroke="#2d425a"/>')
    out.append('<path d="M266 86v422M1260 86v496" stroke="#354b64" stroke-width="2"/>')
    out.append('<path d="M270 508 0 624h1280l-36-116Z" fill="#17273a"/>')
    for x in (370, 620, 870, 1120):
        end = 640 + (x - 745) * 1.7
        out.append(f'<path d="M{x} 508 {end:g} 624" stroke="#294056"/>')
    out.append(_rect(626, 493, 150, 110, "#0a1523", 20, "#43566c"))
    out.append(_rect(636, 503, 130, 91, "#17283b", 14))
    for x in range(649, 760, 12):
        out.append(f'<path d="M{x} 513v62" stroke="#263c52"/>')
    out += ['<path d="M48 556h1182l50 43H0Z" fill="#40536b"/>',
            _rect(0, 600, 1280, 16, "#24374e"),
            '<path d="M0 599h1280" stroke="#6b8096"/>',
            _rect(44, 615, 14, 9, "#071322"), _rect(1220, 615, 14, 9, "#071322")]
    return "".join(out)


def _integration(t):
    """Show the administrator-supplied monitoring-to-API adapter."""
    active = _during(t, (ALERTS[0]["start"], ALERTS[-1]["light"][1])) or _during(
        t, (BROADCAST["start"], BROADCAST["end"]))
    accent = "#ab92eb" if active else "#8da7c4"
    out = [_text(30, 124, "MONITORING → API", 12, "#b9cee4", 700)]
    boxes = ((146, "Monitoring system", "Your existing alerting", "Notifications or webhooks"),
             (267, "Script / webhook", "Administrator-provided", "Maps incidents to API calls"),
             (399, "NeoDSE HTTPS API", "Authenticated requests", "Scoped service-account token"))
    for y, title, line1, line2 in boxes:
        out += [_rect(30, y, 210, 88, "#1a2d44", 9, "#3e536d"),
                f'<circle cx="46" cy="{y + 23}" r="3.5" fill="{accent}"/>',
                _text(58, y + 28, title, 14, "#edf4fe", 700),
                _text(44, y + 51, line1, 11, "#a4bdd6"),
                _text(44, y + 70, line2, 10.5, "#8fa8c3")]
    for start, end in ((234, 259), (355, 391)):
        out.append(f'<path d="M135 {start}v{end-start}" stroke="{accent}" '
                   'stroke-width="1.5" marker-end="url(#flow-arrow)"/>')
    out.append('<path d="M242 440h32" stroke="#8da7c4" stroke-width="1.5" '
               'marker-end="url(#flow-arrow)"/>')
    if _during(t, (BROADCAST["start"], BROADCAST["end"])):
        lines = ("One broadcast request", "Same banner and sound everywhere")
    else:
        lines = ("Separate requests per display", "Banner · Serial light · Sound")
    out += [_text(135, 516, lines[0], 11, "#c3d4e8", 500, "middle"),
            _text(135, 538, lines[1], 11, "#8fa8c3", 400, "middle")]
    return "".join(out)


def _chart(x, y, width, height, color, phase, t):
    """Draw a deterministic compact line chart with a translucent area."""
    out = []
    for offset in (0, height / 2, height):
        out.append(f'<path d="M{x:g} {y+offset:g}h{width:g}" stroke="#26384c"/>')
    points = []
    for i in range(23):
        value = (0.49 + 0.17 * math.sin(i * 0.52 + phase + t * 0.14)
                 + 0.09 * math.cos(i * 1.41 + phase))
        points.append((x + width * i / 22, y + height * (1 - value)))
    path = " ".join(("M" if i == 0 else "L") + f"{px:.1f},{py:.1f}"
                    for i, (px, py) in enumerate(points))
    out += [f'<path d="{path} L{x+width:g},{y+height:g} L{x:g},{y+height:g}Z" '
            f'fill="{color}" fill-opacity=".10"/>',
            f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.2" '
            'stroke-linejoin="round"/>']
    return "".join(out)


def _dashboard(x, y, width, height, page, display, t, logos, banner):
    """Render an illustrative web page and its independent native overlays."""
    # Live page data stops updating while the display's network link is down.
    data_t = LINK_LOSS["start"] if _link_down(display, t) else t
    subtitle, key1, val1, key2, val2, chart, color, phase = PAGES[page]
    out = [_rect(x, y, width, height, "#0b1522")]
    out += [_rect(x + 8, y, 96, CORNER_OVERLAY_HEIGHT, "#000", 0),
            _text(x + 14, y + 14, f"Display {display + 1:02}", 11, "#f1f5fc", 700),
            _rect(x + width - 78, y, 70, CORNER_OVERLAY_HEIGHT, "#000", 0),
            _text(x + width - 14, y + 14, _clock(t), 11,
                  "#f1f5fc", 700, "end")]
    out += [_text(x + 14, y + 49, page, 14, "#eaf3ff", 700),
            _text(x + 14, y + 62, subtitle, 9.5, "#8fa8c3")]
    card_width = (width - 38) / 2
    for position, key, value in ((x + 14, key1, val1), (x + 24 + card_width, key2, val2)):
        out += [_rect(position, y + 69, card_width, 36, "#15263a", 5),
                _text(position + 9, y + 80, key, 8, "#98b3cd", 600),
                _text(position + 9, y + 98, value, 17, color, 700)]
    out += [_text(x + 14, y + 118, chart, 9, "#a6bed6", 600),
            _chart(x + 14, y + 125, width - 28, 19, color, phase, data_t),
            _text(x + 14, y + height - 7, "LIVE · Last 15 minutes", 8, "#7896b3"),
            _image(x + width - 26, y + height - 17, 16, 11,
                   logos["lost" if _link_lost(display, t) else "health"])]
    if banner:
        out.append(_banner(x, y, width, banner))
    return "".join(out)


def _banner(x, y, width, alert):
    """Add a floating banner below the persistent display name and clock."""
    left, top, banner_width = x + 12, y + CORNER_OVERLAY_HEIGHT + BANNER_GAP, width - 24
    return "".join((
        _rect(left + 1, top + 4, banner_width, 28, "#000", 8,
              extra='fill-opacity=".3"'),
        _rect(left, top, banner_width, 28, BANNER_COLORS[alert["severity"]], 8,
              "#ffffff", 'stroke-opacity=".28"'),
        f'<circle cx="{left+16:g}" cy="{top+14:g}" r="6" fill="none" '
        'stroke="white" stroke-width="1.5"/>',
        _text(left + 16, top + 18, "i", 11, "#fff", 700, "middle"),
        _text(left + banner_width / 2 + 7, top + 18, alert["message"], 11,
              "#fff", 700, "middle"),
    ))


def _speaker(x, y, active, t):
    """Draw a monitor's own lower-bezel speaker and optional local sound waves."""
    out = [_rect(x - 18, y - 4, 36, 8, "#040c16", 3, "#3f5268")]
    for offset in range(-12, 15, 4):
        out.append(f'<path d="M{x+offset:g} {y-1:g}v2" stroke="#71849a"/>')
    if active:
        opacity = 0.75 + 0.25 * math.sin(t * 24) ** 2
        for offset in (0, 7, 14):
            out.append(f'<path d="M{x+24+offset:g} {y-6-offset/2:g}q{8+offset/3:g} '
                       f'{6+offset/2:g} 0 {12+offset:g}M{x-24-offset:g} '
                       f'{y-6-offset/2:g}q{-8-offset/3:g} {6+offset/2:g} 0 {12+offset:g}" '
                       f'fill="none" stroke="#c4b5ff" stroke-width="2" opacity="{opacity:.3f}"/>')
    return "".join(out)


def _active_banner(display, t):
    """Pick the per-display, broadcast or scheduled banner shown at a time."""
    for banner in (ALERTS[display], BROADCAST, REMINDER):
        if banner["start"] <= t < banner["end"]:
            return banner
    return None


def _waiting_logo(display, t, logos):
    """Restart the waiting animation whenever a display's status color changes."""
    started, connected = STARTUP[display]
    if t < started:
        return ""
    phase, since = ("info", started) if t < connected else ("success", connected)
    frames = logos[phase]
    return frames[int(round((t - since) * FPS)) % len(frames)]


def _monitor(display, t, logos):
    """Compose one physical monitor, its screen, serial strip and speaker."""
    x, y, outer_width = 282 + display * 322, 200, SCREEN_WIDTH + 16
    screen_x, screen_y, width, height = x + 8, y + 11, SCREEN_WIDTH, SCREEN_HEIGHT
    outer_height = height + 28
    alert = ALERTS[display]
    banner = _active_banner(display, t)
    power_off = POWER_OFF <= t < POWER_ON
    out = [_rect(x - 4, y + 5, outer_width + 8, outer_height + 1, "#091322", 5),
           _rect(x, y, outer_width, outer_height, "#111e2d", 5, "#64788f"),
           _rect(screen_x - 1, screen_y - 1, width + 2, height + 2, "#000", 2)]
    light = _light_on(t, alert)
    out.append(_rect(x + 14, y + 4, outer_width - 28, 3,
                     "#ffb347" if light else "#3d3526", 1))
    if light:
        out.append(_rect(x + 13, y + 2, outer_width - 26, 7, "#ffb347", 2,
                         extra='fill-opacity=".13"'))
    if not power_off:
        if t < PLAYLIST_START:
            out += [_rect(screen_x, screen_y, width, height, "#000"),
                    _image(screen_x + 25, screen_y + (height - 82) / 2, width - 50, 82,
                           _waiting_logo(display, t, logos))]
        else:
            pages = PLAYLISTS[display]
            page = pages[int((t - PLAYLIST_START) / ROTATION) % len(pages)]
            out.append(_dashboard(screen_x, screen_y, width, height, page,
                                  display, t, logos, banner))
    sound = _during(t, alert["sound"]) or _during(t, BROADCAST["sound"])
    out.append(_speaker(x + outer_width / 2, y + outer_height + 5, sound, t))
    labels = ("SINGLE PAGE", "THREE-PAGE ROTATION", "TWO-PAGE ROTATION")
    label, color = labels[display], "#a7bfd7"
    if _link_down(display, t):
        label, color = "NETWORK LINK LOST", "#ed6464"
    out.append(_text(x + outer_width / 2, y + outer_height + 33,
                     f"DISPLAY {display + 1:02} · {label}", 10.5, color, 700, "middle"))
    return "".join(out)


def _caption(t):
    """Explain the current action without inventing any product screen."""
    if t < 4:
        return ("Each display starts on its own schedule.",
                "Blue: connecting to the controller · Green: authenticated, waiting for content")
    if t < PLAYLIST_START:
        return ("Playlists share one start time: 09:00:08.",
                "Displays that connect early hold the green waiting screen")
    if t < 12:
        return ("All three dashboards appear in the same second.",
                "Existing web pages preload behind the waiting screen until the start time")
    if t < 16:
        return ("Rotations stay in step across displays.",
                "Displays 02 and 03 change page together every 4 seconds")
    if t < 19.5:
        return ("Display 01 receives its own warning.",
                "A monitoring alert becomes a banner, serial light and sound on one display")
    if t < 23:
        return ("Display 02 receives a critical database alert.",
                "Each client has its own banner, serial light and audio output")
    if t < 26:
        return ("Display 03 receives an information notice.",
                "Independent banners · Display name and clock stay visible above them")
    if t < 30:
        return ("Banners expire; serial lights stop separately.",
                "A banner timer does not switch off a light · Light-off is an explicit request")
    if t < 36:
        return ("One broadcast request reaches every display.",
                "Same banner and sound on all three · Each display reports its own result")
    if t < LINK_LOSS["restored"]:
        return ("Display 02 loses its network link: its status N turns red.",
                "Loaded pages keep rotating on the local clock, in step with Display 03")
    if t < REMINDER["start"]:
        return ("The link returns and the status N turns green again.",
                "Reconnection is automatic · Playback never stopped")
    if t < POWER_OFF:
        return ("A reminder banner precedes the scheduled power-off.",
                "Weekly screen-power schedule · Optional reminder before 18:00")
    if t < POWER_ON:
        return ("18:00: scheduled power-off, the screens go black.",
                "HDMI-CEC controls the screens · Linux clients stay running")
    return ("08:00: scheduled power-on restores the dashboards.",
            "The clients kept running · Playlists continue at their wall-clock position")


def _footer(t):
    """Draw concise explanatory captions and the six-stage progress strip."""
    main, detail = _caption(t)
    out = [_rect(0, 624, 1280, 96, "#0b1727"),
           '<path d="M0 624h1280" stroke="#30465e"/>',
           _text(640, 649, main, 20, "#eef4ff", 700, "middle"),
           _text(640, 673, detail, 12, "#9db8d2", 400, "middle")]
    for i, (start, end, title) in enumerate(PHASES):
        left, width = 30 + i * 207, 178
        active = start <= t < end
        color = "#80baff" if active else "#768fa9"
        out += [_text(left + width / 2, 700, title, 10, color, 700, "middle"),
                _rect(left, 712, width, 3, "#293e55", 1)]
        fraction = 1 if t >= end else max(0, (t - start) / (end - start))
        if fraction:
            out.append(_rect(left, 712, width * fraction, 3,
                             "#80baff" if active else "#456685", 1))
    return "".join(out)


def scene_svg(t: float, logos: dict) -> str:
    """Return the complete 1280×720 scene for a time in the 58-second loop."""
    t = float(t) % DURATION
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" '
           'viewBox="0 0 1280 720" role="img">',
           '<title>NeoDSE display-management example</title>',
           '<defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="8" refY="5" '
           'markerWidth="5" markerHeight="5" orient="auto">'
           '<path d="M0 0 10 5 0 10Z" fill="#8da7c4"/></marker></defs>',
           '<g font-family="DejaVu Sans, Arial, sans-serif">', _room(), _header(logos),
           _integration(t)]
    out.extend(_monitor(i, t, logos) for i in range(3))
    out += ['<path d="M282 440h954" stroke="#71869b" stroke-width="3"/>',
            _text(766, 462, "Individual display audio · Optional compatible serial light controllers",
                  11, "#91abc4", 400, "middle"),
            _text(766, 613, "Sound shown visually · Optional serial lights", 11,
                  "#9fb6d0", 500, "middle"), _footer(t), '</g></svg>']
    return "".join(out)


def run_ffmpeg(*arguments):
    """Run the system FFmpeg without shell parsing or hiding failures."""
    subprocess.run(
        ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
         '-filter_threads', '1', '-filter_complex_threads', '1', *map(str, arguments)],
        check=True,
    )


def image_uri(path):
    """Embed an unmodified generated logo frame in the scene SVG."""
    return 'data:image/png;base64,' + base64.b64encode(path.read_bytes()).decode('ascii')


def prepare_logos(root, work):
    """Sample the shipped waiting animations and completed green and red health N."""
    animations = {}
    for name in ('info', 'success'):
        directory = work / name
        directory.mkdir()
        run_ffmpeg('-i', root / f'assets/images/logo-status-{name}.gif',
                   '-vf', f'fps={FPS},scale=256:-1', '-frames:v', str(int(LOGO_LOOP * FPS)),
                   '-start_number', '0', directory / '%02d.png')
        frames = sorted(directory.glob('*.png'))
        if len(frames) != int(LOGO_LOOP * FPS):
            raise RuntimeError(
                f'{name}: expected {int(LOGO_LOOP * FPS)} frames '
                f'from the {LOGO_LOOP}-second logo loop')
        animations[name] = [image_uri(path) for path in frames]
    # Frame 59 contains the completed mark, before the native fade-out.
    brand = work / 'brand.png'
    run_ffmpeg('-i', root / 'assets/images/logo-status-info.gif',
               '-vf', 'select=eq(n\\,59),scale=256:-1', '-frames:v', '1', brand)
    health = {}
    for name in ('success', 'critical'):
        path = work / f'health-{name}.png'
        run_ffmpeg('-i', root / f'assets/images/logo-status-{name}.gif',
                   '-vf', 'select=eq(n\\,59),crop=650:430:40:100,scale=48:-1',
                   '-frames:v', '1', path)
        health[name] = image_uri(path)
    return animations, image_uri(brand), health


def render_demo(root, output, preview):
    """Render code-defined scenes and atomically replace the final GIF."""
    if shutil.which('ffmpeg') is None:
        raise RuntimeError('Install FFmpeg with its librsvg decoder before rendering the demo')
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.neodse-demo-', dir=output.parent) as directory:
        work = Path(directory)
        animations, brand, health = prepare_logos(root, work)
        frames = work / 'frames'
        frames.mkdir()
        if preview:
            preview.mkdir(parents=True, exist_ok=True)
        samples = {0, 20, 40, 60, 75, 80, 130, 170, 210, 240, 280, 315,
                   350, 370, 400, 440, 470, 520, 560}
        logos = {**animations, 'brand': brand,
                 'health': health['success'], 'lost': health['critical']}
        for number in range(int(DURATION * FPS)):
            t = number / FPS
            source = scene_svg(t, logos)
            frame = frames / f'{number:04d}.svg'
            frame.write_text(source)
            if preview and number in samples:
                saved = preview / f'{number:04d}.svg'
                saved.write_text(source)
                run_ffmpeg('-i', saved, '-frames:v', '1', saved.with_suffix('.png'))
        palette = work / 'palette.png'
        run_ffmpeg('-framerate', str(FPS), '-i', frames / '%04d.svg',
                   '-vf', 'palettegen=max_colors=256:stats_mode=diff',
                   '-frames:v', '1', palette)
        result = work / 'demo.gif'
        run_ffmpeg('-framerate', str(FPS), '-i', frames / '%04d.svg', '-i', palette,
                   '-lavfi', 'paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle',
                   '-loop', '0', result)
        os.replace(result, output)
    print(f'Rendered {output}: {WIDTH}x{HEIGHT}, {DURATION:g} seconds, {FPS} fps (silent GIF).',
          flush=True)


def main():
    """Regenerate the README illustration and optional review stills."""
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=root / 'neodse-display-management.gif')
    parser.add_argument('--preview-dir', type=Path,
                        help='also save selected SVG/PNG stills to inspect the sequence')
    args = parser.parse_args()
    try:
        render_demo(root, args.output, args.preview_dir)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Demo rendering failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
