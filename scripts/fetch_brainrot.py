"""Downloads the brain rot sounds used by useless mode (GK-10).

Run once with `uv run python scripts/fetch_brainrot.py` and commit the output. Sounds are cut to
a few seconds and converted to WAV so every common audio player can play them (needs ffmpeg).
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

ASSETS = Path(__file__).resolve().parents[1] / "src" / "gatekeeper" / "assets" / "brainrot"
SOUND_BASE = "https://www.myinstants.com/media/sounds/"
MAX_SOUND_SECONDS = 4
# Some hosts refuse the default httpx user agent.
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130 Safari/537.36"}

# Sounds added by hand, not downloaded by this script: name -> where they came from.
CUSTOM_SOUNDS = {
    "session_start": "played when a new Claude Code session starts; converted from myinstants.mp3,"
    " which the project owner added",
}

# name -> myinstants file name (without .mp3)
SOUNDS = {
    "vine_boom": "vine-boom",
    "bruh": "movie_1",
    "role_reveal": "among-us-role-reveal-sound",
    "oh_hell_nah": "oh-my-god-bro-oh-hell-nah-man",
    "anime_wow": "anime-wow-sound-effect",
    "metal_pipe": "metal-pipe-clang",
    "taco_bell": "taco-bell-bong-sfx",
    "fart_reverb": "fart-with-reverb",
    "emotional_damage": "emotional-damage-meme",
    "spongebob_fail": "spongebob-fail",
    "gyatt": "gyatt",
    "sigma": "sigma",
    "rizz": "rizz",
    "ohio": "ohio",
    "sus": "sus",
    "fahhh": "fahhh",
    "huh": "huh",
    "bonk": "bonk",
    "goofy_ahh": "goofy-ahh-sound",
    "roblox_oof": "roblox-oof-sound",
    "airhorn": "mlg-airhorn",
    "sad_violin": "sad-violin-meme",
    "fnaf_jumpscare": "fnaf-jumpscare",
    "jumpscare": "jumpscare",
    "windows_error": "windows-xp-error-sound",
    "sheesh": "sheeesh",
}

def main() -> None:
    if shutil.which("ffmpeg") is None:
        raise SystemExit("ffmpeg is required to convert the sounds")
    (ASSETS / "sounds").mkdir(parents=True, exist_ok=True)
    # A sound dropped from the list above should not linger, but hand-added ones stay.
    for stale in (ASSETS / "sounds").glob("*.wav"):
        if stale.stem not in SOUNDS and stale.stem not in CUSTOM_SOUNDS:
            stale.unlink()
    credits = [
        "# Brain rot media credits",
        "",
        "Downloaded by `scripts/fetch_brainrot.py`. These are internet memes; the rights belong to",
        "their creators. Sounds are cut to a few seconds and converted to WAV.",
        "",
        "## Sounds",
    ]
    with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=30) as client:
        for name, slug in SOUNDS.items():
            url = f"{SOUND_BASE}{slug}.mp3"
            response = client.get(url)
            response.raise_for_status()
            with tempfile.TemporaryDirectory() as folder:
                source = Path(folder) / "clip.mp3"
                source.write_bytes(response.content)
                subprocess.run(
                    [
                        "ffmpeg", "-y", "-loglevel", "error", "-i", str(source),
                        "-t", str(MAX_SOUND_SECONDS), "-ac", "1", "-ar", "22050",
                        "-af", "loudnorm", str(ASSETS / "sounds" / f"{name}.wav"),
                    ],
                    check=True,
                )
            credits.append(f"- `sounds/{name}.wav`: {url}")
    credits += [f"- `sounds/{name}.wav`: {note}" for name, note in CUSTOM_SOUNDS.items()]
    (ASSETS / "CREDITS.md").write_text("\n".join(credits) + "\n")
    print(f"Wrote {len(SOUNDS)} sounds to {ASSETS} (hand-added sounds kept)")


if __name__ == "__main__":
    main()
