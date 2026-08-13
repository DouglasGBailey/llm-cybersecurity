"""Synthesize narration segments via edge-tts, one MP3 per scene, so each
scene's on-screen duration can be matched exactly to its spoken audio.
"""
import asyncio
import subprocess
from pathlib import Path

import edge_tts

VOICE = "en-US-AndrewNeural"
OUT_DIR = Path(__file__).parent / "audio"
OUT_DIR.mkdir(exist_ok=True)

SEGMENTS = [
    ("01_title", "This is the automated test suite for the LLM Cybersecurity Agent Platform, "
                 "a controlled, scope gated, multi agent security assessment tool."),
    ("02_command", "Let's activate the environment and run the full suite with pytest."),
    ("03_scroll", "Sixty eight tests cover every component: scope enforcement, "
                  "each of the six scanning agents, evidence collection, report generation, "
                  "and the opt in A I triage step. All tests mock their network and subprocess calls, "
                  "so nothing here touches a live target."),
    ("04_summary", "Sixty eight passed, zero failed, in under a second. "
                   "This suite has also been live verified end to end against a real D V W A lab container."),
    ("05_outro", "The full platform is open source on GitHub."),
]


async def synth_all():
    for name, text in SEGMENTS:
        out_path = OUT_DIR / f"{name}.mp3"
        communicate = edge_tts.Communicate(text, VOICE)
        await communicate.save(str(out_path))
        print(f"synthesized {out_path}")


def get_duration(path: Path) -> float:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=nw=1:nk=1", str(path)],
        capture_output=True, text=True, check=True,
    )
    return float(result.stdout.strip())


if __name__ == "__main__":
    asyncio.run(synth_all())
    durations = {}
    for name, _ in SEGMENTS:
        d = get_duration(OUT_DIR / f"{name}.mp3")
        durations[name] = d
        print(f"{name}: {d:.2f}s")
    import json
    (OUT_DIR / "durations.json").write_text(json.dumps(durations, indent=2))
