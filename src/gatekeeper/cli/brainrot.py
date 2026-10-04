"""Brain rot sounds for the terminal, used only while useless mode is on."""

import os
import random
import shutil
import sqlite3
import subprocess
import sys
from importlib import resources
from pathlib import Path
from typing import TextIO

from gatekeeper.pipeline import useless_mode
from gatekeeper.server.types import Verdict

ASSETS = resources.files("gatekeeper") / "assets" / "brainrot"
MIN_SCARE_SECONDS = 5
MAX_SCARE_SECONDS = 40
MUTE_ENV = "GATEKEEPER_MUTE"
USELESS_QUESTION_MARKER = "Useless mode asked"

# The first player found is used. All of them can play the WAV files.
PLAYERS = (
    ["pw-play"],
    ["paplay"],
    ["aplay", "-q"],
    ["afplay"],
    ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet"],
)
# One of these plays at each random scare.
SCARE_SOUNDS = (
    "fnaf_jumpscare", "jumpscare", "airhorn", "fahhh", "gyatt", "sigma", "rizz", "ohio", "sus",
    "goofy_ahh", "roblox_oof", "emotional_damage", "fart_reverb", "spongebob_fail", "huh", "bonk",
    "sheesh", "windows_error", "sad_violin", "vine_boom",
)
ASK_SOUNDS = ("role_reveal", "oh_hell_nah")


def sound_for(verdict: Verdict | str, text: str = "") -> str:
    """The brain rot sound for a decision. `text` is its summary or first reason."""
    verdict = Verdict(verdict)
    if verdict == Verdict.DENY:
        return "bruh" if USELESS_QUESTION_MARKER in text else "vine_boom"
    if verdict == Verdict.ASK:
        return random.choice(ASK_SOUNDS)
    return "anime_wow"


def useless_mode_on(conn: sqlite3.Connection, session_id: str | None) -> bool:
    """Whether useless mode is on for the session (or globally, with no session)."""
    return useless_mode.state(conn, session_id, useless_mode.session_config(conn, session_id))[0]


def sound_path(name: str) -> Path:
    return Path(str(ASSETS / "sounds" / f"{name}.wav"))


def play(name: str | None, out: TextIO | None = None) -> None:
    """Start a sound without waiting for it, or ring the terminal bell when there is no player."""
    if os.environ.get(MUTE_ENV):
        return
    path = sound_path(name) if name else None
    if path is not None and path.exists():
        for command in PLAYERS:
            if shutil.which(command[0]):
                subprocess.Popen(
                    [*command, str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,  # a short command can exit while the clip plays on
                )
                return
    stream = out or sys.stdout
    stream.write("\a")
    stream.flush()


def next_scare_delay() -> float:
    return random.uniform(MIN_SCARE_SECONDS, MAX_SCARE_SECONDS)


def scare(out: TextIO | None = None) -> None:
    """Play a random loud brain rot sound."""
    play(random.choice(SCARE_SOUNDS), out)
