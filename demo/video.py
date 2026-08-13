"""Render a terminal-style demo video of the pytest suite, with scene
durations matched exactly to the pre-synthesized narration segments in
audio/durations.json (see narration.py).

Static scenes (title/outro/summary) are rendered as a single PNG and held
by ffmpeg for the scene duration. Animated scenes (typing the command,
scrolling real pytest output) are rendered as a PNG sequence at a fixed fps.
"""
import json
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).parent
FRAMES = ROOT / "frames"
AUDIO = ROOT / "audio"
ASSETS = ROOT / "assets"
FRAMES.mkdir(exist_ok=True)
ASSETS.mkdir(exist_ok=True)

W, H = 1280, 720
BG = (30, 30, 46)          # catppuccin mocha base
HEADER_BG = (24, 24, 37)
FG = (205, 214, 244)
DIM = (108, 112, 134)
GREEN = (166, 227, 161)
BLUE = (137, 180, 250)
YELLOW = (249, 226, 175)
RED = (243, 139, 168)
MAUVE = (203, 166, 247)

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_SIZE = 20
LINE_H = 27
MONO = ImageFont.truetype(FONT_PATH, FONT_SIZE)
MONO_BOLD = ImageFont.truetype(FONT_BOLD_PATH, FONT_SIZE)
TITLE_FONT = ImageFont.truetype(FONT_BOLD_PATH, 44)
SUBTITLE_FONT = ImageFont.truetype(FONT_PATH, 24)

FPS_STATIC = 24
FPS_ANIM = 20

TERM_TOP = 56
TERM_PAD_X = 28
TERM_PAD_TOP = 20


def base_canvas() -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, W, TERM_TOP], fill=HEADER_BG)
    for i, color in enumerate([RED, YELLOW, GREEN]):
        draw.ellipse([24 + i * 26, TERM_TOP // 2 - 7, 24 + i * 26 + 14, TERM_TOP // 2 + 7], fill=color)
    label = "bash — pytest tests/ -v"
    bbox = draw.textbbox((0, 0), label, font=MONO)
    draw.text(((W - (bbox[2] - bbox[0])) / 2, (TERM_TOP - FONT_SIZE) / 2 - 2), label, font=MONO, fill=DIM)
    return img


def colorize_line(line: str):
    if "PASSED" in line:
        return GREEN
    if "FAILED" in line or "ERROR" in line:
        return RED
    if line.startswith("===") :
        return YELLOW
    if line.startswith("tests/"):
        return FG
    return DIM


def wrap_prompt_frame(typed_lines: list[str], cursor_visible: bool) -> Image.Image:
    img = base_canvas()
    draw = ImageDraw.Draw(img)
    y = TERM_TOP + TERM_PAD_TOP
    for line in typed_lines:
        draw.text((TERM_PAD_X, y), "$ ", font=MONO_BOLD, fill=BLUE)
        prompt_w = draw.textbbox((0, 0), "$ ", font=MONO_BOLD)[2]
        draw.text((TERM_PAD_X + prompt_w, y), line, font=MONO, fill=FG)
        y += LINE_H
    if cursor_visible:
        draw.rectangle([TERM_PAD_X, y, TERM_PAD_X + 12, y + FONT_SIZE], fill=FG)
    return img


def render_title_scene():
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    title = "LLM Cybersecurity Agent Platform"
    subtitle = "Automated Test Suite — End-to-End Demo"
    tb = draw.textbbox((0, 0), title, font=TITLE_FONT)
    sb = draw.textbbox((0, 0), subtitle, font=SUBTITLE_FONT)
    draw.text(((W - (tb[2] - tb[0])) / 2, H / 2 - 60), title, font=TITLE_FONT, fill=MAUVE)
    draw.text(((W - (sb[2] - sb[0])) / 2, H / 2 + 10), subtitle, font=SUBTITLE_FONT, fill=DIM)
    img.save(ASSETS / "01_title.png")


def render_command_scene(fps: int, duration: float):
    lines_to_type = [
        "source venv/bin/activate && python -m pytest tests/ -v",
    ]
    full_text = lines_to_type[0]
    n_frames = int(duration * fps)
    # Reserve the last ~25% of frames as a hold (cursor blinking) after typing finishes.
    type_frames = int(n_frames * 0.7)
    hold_frames = n_frames - type_frames
    chars_per_frame = max(1, len(full_text) / type_frames)

    idx = 0
    frame_i = 0
    for f in range(type_frames):
        idx = min(len(full_text), int((f + 1) * chars_per_frame))
        cursor_visible = (f // 3) % 2 == 0
        img = wrap_prompt_frame([full_text[:idx]], cursor_visible)
        img.save(FRAMES / "02_command" / f"frame_{frame_i:05d}.png")
        frame_i += 1
    for f in range(hold_frames):
        cursor_visible = (f // 3) % 2 == 0
        img = wrap_prompt_frame([full_text], cursor_visible)
        img.save(FRAMES / "02_command" / f"frame_{frame_i:05d}.png")
        frame_i += 1


def truncate_to_width(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> str:
    if draw.textlength(text, font=font) <= max_width:
        return text
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if draw.textlength(text[:mid], font=font) <= max_width:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo]


def render_scroll_scene(fps: int, duration: float, output_lines: list[str]):
    n_frames = int(duration * fps)
    max_visible = 20  # lines that fit in the terminal body
    n_lines = len(output_lines)
    max_text_width = W - 2 * TERM_PAD_X
    # Map frame index -> number of lines revealed so far (monotonic, covers all lines).
    frame_i = 0
    for f in range(n_frames):
        progress = (f + 1) / n_frames
        revealed = max(1, min(n_lines, round(progress * n_lines)))
        visible = output_lines[max(0, revealed - max_visible):revealed]

        img = base_canvas()
        draw = ImageDraw.Draw(img)
        y = TERM_TOP + TERM_PAD_TOP
        prompt = "$ source venv/bin/activate && python -m pytest tests/ -v"
        draw.text((TERM_PAD_X, y), prompt, font=MONO, fill=BLUE)
        y += LINE_H + 6
        for line in visible:
            color = colorize_line(line)
            font = MONO_BOLD if "===" in line else MONO
            fitted = truncate_to_width(draw, line, font, max_text_width)
            draw.text((TERM_PAD_X, y), fitted, font=font, fill=color)
            y += LINE_H
        img.save(FRAMES / "03_scroll" / f"frame_{frame_i:05d}.png")
        frame_i += 1


def render_summary_scene():
    img = base_canvas()
    draw = ImageDraw.Draw(img)
    y = TERM_TOP + TERM_PAD_TOP
    prompt = "$ source venv/bin/activate && python -m pytest tests/ -v"
    draw.text((TERM_PAD_X, y), prompt, font=MONO, fill=BLUE)
    y += LINE_H + 20

    big_font = ImageFont.truetype(FONT_BOLD_PATH, 34)
    draw.text((TERM_PAD_X, y), "68 passed in 0.78s", font=big_font, fill=GREEN)
    y += 55

    captions = [
        ("scope guard", "12"),
        ("recon agent", "5"),
        ("webapp analyzer", "5"),
        ("api analyzer", "7"),
        ("infra analyzer", "9"),
        ("code analyzer", "7"),
        ("llm security analyzer", "8"),
        ("evidence collector", "5"),
        ("report generator", "5"),
        ("ai triage analyzer", "5"),
    ]
    draw.text((TERM_PAD_X, y), "Breakdown:", font=MONO_BOLD, fill=FG)
    y += LINE_H
    for name, count in captions:
        draw.text((TERM_PAD_X + 20, y), f"- {name}: {count} tests", font=MONO, fill=DIM)
        y += 24

    draw.text((TERM_PAD_X, H - 50), "Zero live network calls required to run this suite.", font=MONO, fill=YELLOW)
    img.save(ASSETS / "04_summary.png")


def render_outro_scene():
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    line1 = "68 / 68 tests passing"
    line2 = "Live-verified against a real DVWA lab container"
    line3 = "github.com/DouglasGBailey/llm-cybersecurity"
    f1 = TITLE_FONT
    f2 = SUBTITLE_FONT
    f3 = SUBTITLE_FONT
    b1 = draw.textbbox((0, 0), line1, font=f1)
    b2 = draw.textbbox((0, 0), line2, font=f2)
    b3 = draw.textbbox((0, 0), line3, font=f3)
    draw.text(((W - (b1[2] - b1[0])) / 2, H / 2 - 70), line1, font=f1, fill=GREEN)
    draw.text(((W - (b2[2] - b2[0])) / 2, H / 2 - 5), line2, font=f2, fill=DIM)
    draw.text(((W - (b3[2] - b3[0])) / 2, H / 2 + 40), line3, font=f3, fill=BLUE)
    img.save(ASSETS / "05_outro.png")


def build_ffmpeg_segment(kind: str, name: str, duration: float):
    out = ROOT / f"seg_{name}.mp4"
    if kind == "static":
        img_path = ASSETS / f"{name}.png"
        subprocess.run([
            "ffmpeg", "-y", "-loop", "1", "-framerate", str(FPS_STATIC), "-i", str(img_path),
            "-t", f"{duration:.3f}", "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-vf", f"fps={FPS_STATIC}", str(out),
        ], check=True, capture_output=True)
    else:
        frame_dir = FRAMES / name
        subprocess.run([
            "ffmpeg", "-y", "-framerate", str(FPS_ANIM), "-i", str(frame_dir / "frame_%05d.png"),
            "-t", f"{duration:.3f}", "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-vf", f"fps={FPS_STATIC}", str(out),
        ], check=True, capture_output=True)
    return out


def main():
    durations = json.loads((AUDIO / "durations.json").read_text())
    (FRAMES / "02_command").mkdir(exist_ok=True)
    (FRAMES / "03_scroll").mkdir(exist_ok=True)

    output_lines = Path("/tmp/pytest_output.txt").read_text().splitlines()
    output_lines = [ln.rstrip() for ln in output_lines if ln.strip()]

    print("Rendering static scenes...")
    render_title_scene()
    render_summary_scene()
    render_outro_scene()

    print("Rendering command typing animation...")
    render_command_scene(FPS_ANIM, durations["02_command"])

    print("Rendering scroll animation...")
    render_scroll_scene(FPS_ANIM, durations["03_scroll"], output_lines)

    print("Encoding scene segments...")
    segs = []
    segs.append(build_ffmpeg_segment("static", "01_title", durations["01_title"]))
    segs.append(build_ffmpeg_segment("anim", "02_command", durations["02_command"]))
    segs.append(build_ffmpeg_segment("anim", "03_scroll", durations["03_scroll"]))
    segs.append(build_ffmpeg_segment("static", "04_summary", durations["04_summary"]))
    segs.append(build_ffmpeg_segment("static", "05_outro", durations["05_outro"]))

    concat_list = ROOT / "concat_video.txt"
    concat_list.write_text("\n".join(f"file '{s.name}'" for s in segs))
    video_out = ROOT / "video_silent.mp4"
    subprocess.run([
        "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat_list),
        "-c", "copy", str(video_out),
    ], check=True, cwd=ROOT, capture_output=True)
    print(f"Silent video: {video_out}")


if __name__ == "__main__":
    main()
