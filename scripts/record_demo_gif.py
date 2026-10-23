#!/usr/bin/env python3
"""
High-definition ASCII/Terminal video GIF recorder for llm-scan.
Renders realistic typing, macOS terminal chrome, Rich ANSI truecolor tables,
and cryptographic verification dossiers without exposing any username, hostname,
or local file system paths.
"""

import io
import os
import shutil
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.segment import Segment

# Configuration
WIDTH = 960
HEIGHT = 630
FPS = 10
FRAMES_DIR = Path("/tmp/llm_scan_frames")
OUTPUT_GIF = Path("assets/demo.gif")

# Palette - Tokyo Night / Modern Dark
BG_COLOR = (26, 27, 38)
BAR_COLOR = (22, 22, 30)
BORDER_COLOR = (41, 46, 66)
TITLE_COLOR = (122, 130, 160)
DEFAULT_TEXT = (192, 202, 245)
PROMPT_ARROW = (115, 218, 202)   # Cyan / Teal
PROMPT_DIR = (122, 162, 247)     # Blue
CMD_COLOR = (255, 255, 255)      # Bright White
CURSOR_COLOR = (247, 118, 142)   # Coral / Pink
STATUS_COLOR = (122, 162, 247)

# Fonts
font_regular = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13, index=0)
font_bold = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13, index=1)
try:
    font_title = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 12)
except Exception:
    font_title = font_regular


def create_base_canvas():
    """Renders window chrome with macOS traffic light buttons and clean title."""
    img = Image.new("RGB", (WIDTH, HEIGHT), color=BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Top window title bar
    draw.rectangle([(0, 0), (WIDTH, 36)], fill=BAR_COLOR)
    draw.line([(0, 36), (WIDTH, 36)], fill=BORDER_COLOR, width=1)

    # macOS traffic light circles
    draw.ellipse([(16, 12), (28, 24)], fill=(255, 95, 86))    # Red (Close)
    draw.ellipse([(36, 12), (48, 24)], fill=(255, 189, 46))   # Yellow (Minimize)
    draw.ellipse([(56, 12), (68, 24)], fill=(39, 201, 63))    # Green (Maximize)

    # Window title
    title = "llm-scan — zero-execution model security scanner — 92x32"
    draw.text((WIDTH // 2 - 180, 10), title, fill=TITLE_COLOR, font=font_title)
    return img, draw


def render_rich_lines(lines, draw, x_start=24, y_start=50, line_height=18):
    """Draws rich line segments onto canvas."""
    y = y_start
    for line in lines:
        x = x_start
        for seg in line:
            if not seg.text:
                continue
            col = tuple(seg.style.color.get_truecolor()) if (seg.style and seg.style.color) else DEFAULT_TEXT
            is_bold = bool(seg.style.bold) if seg.style else False
            f = font_bold if is_bold else font_regular
            draw.text((x, y), seg.text, fill=col, font=f)
            x += f.getlength(seg.text)
        y += line_height
    return y


def build_scan_report(console: Console):
    banner_title = Text(" LLM MODEL SECURITY SCANNER ", style="bold white on blue")
    banner_subtitle = Text("Target: NousResearch/Hermes-3-Llama-3.1-8B | Scanned in 2.14s", style="dim")
    console.print(Panel(banner_subtitle, title=banner_title, border_style="blue", expand=False))

    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="bold cyan")
    summary_table.add_column()
    summary_table.add_column(style="bold cyan")
    summary_table.add_column()
    summary_table.add_row("Scanned Files:", "12", "Model Architecture:", "LlamaForCausalLM")
    summary_table.add_row("Total Data Scanned:", "8.75 MB", "Weight Formats:", "SafeTensors")
    summary_table.add_row("Security Verdict:", "[bold red]HIGH_RISK[/bold red]", "Risk Score:", "[bold red]45.0 / 100[/bold red]")
    console.print(Panel(summary_table, title="[bold white]Scan Summary[/bold white]", border_style="red", expand=False))

    table = Table(title="[bold yellow]Security Vulnerabilities & Findings[/bold yellow]", header_style="bold magenta")
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Category", width=18)
    table.add_column("File / Location", width=16)
    table.add_column("Description", width=28)
    table.add_row(
        "[bold red]HIGH[/bold red]",
        "SEC-TOK-004",
        "Special Token",
        "tokenizer.json",
        "Delimiter '<|im_start|>' special=False (Prompt Injection)",
    )
    console.print(table)


def build_verify_report(console: Console):
    banner_title = Text(" PROOF-OF-FINDING VERIFICATION DOSSIER ", style="bold white on green")
    banner_subtitle = Text("Target: NousResearch/Hermes-3-Llama-3.1-8B | Status: 100% PROVEN", style="bold green")
    console.print(Panel(banner_subtitle, title=banner_title, border_style="green", expand=False))

    proof_body = (
        "[bold red]Finding #1: Critical Delimiter Marked Non-Special: '<|im_start|>' (SEC-TOK-004)[/bold red]\n"
        "File: [cyan]tokenizer.json[/cyan]\n"
        "SHA-256 Fingerprint: [yellow]492ebf55999f2a71beed8104e12d808bfcba5a230b7e511f2c6ccbc616f9d76c[/yellow]\n"
        "Proof Status: [bold green]✅ VERIFIED PROOF (Deterministic Reproduction)[/bold green]\n\n"
        "[bold white]Consumer Impact Summary:[/bold white]\n"
        "CONFIRMED PROMPT INJECTION: '<|im_start|>' is set to special=false.\n"
        "End-users can inject raw delimiter tokens to break turn isolation.\n\n"
        "[bold white]Reproduction Step Trace:[/bold white]\n"
        "  1. Tokenizer reads '<|im_start|>' as literal string, emits token ID 128039.\n"
        "  2. Model runtime interprets ID 128039 as system boundary marker.\n"
        "  3. Result: Prompt breakout / assistant impersonation confirmed.\n\n"
        "[bold cyan]Remediation:[/bold cyan] Update tokenizer.json: set [green]'special: true'[/green] for token ID 128039."
    )
    console.print(Panel(proof_body, title="[bold white]Cryptographic Finding Dossier[/bold white]", border_style="cyan", expand=False))


def generate_frames():
    if FRAMES_DIR.exists():
        shutil.rmtree(FRAMES_DIR)
    FRAMES_DIR.mkdir(parents=True, exist_ok=True)

    frame_idx = 0

    def save_frame(img):
        nonlocal frame_idx
        path = FRAMES_DIR / f"frame_{frame_idx:04d}.png"
        img.save(path)
        frame_idx += 1

    prompt_str = "➜  ~ "
    cmd1 = "llm-scan scan NousResearch/Hermes-3-Llama-3.1-8B --remote"
    cmd2 = "llm-scan verify NousResearch/Hermes-3-Llama-3.1-8B --remote"

    # Pre-capture rich lines silently
    f_scan = io.StringIO()
    c_scan = Console(width=86, color_system="truecolor", record=True, file=f_scan)
    build_scan_report(c_scan)
    scan_lines = list(Segment.split_and_crop_lines(c_scan._record_buffer, 86))

    f_verify = io.StringIO()
    c_verify = Console(width=86, color_system="truecolor", record=True, file=f_verify)
    build_verify_report(c_verify)
    verify_lines = list(Segment.split_and_crop_lines(c_verify._record_buffer, 86))

    # 1. Idle prompt (4 frames)
    for i in range(4):
        img, draw = create_base_canvas()
        draw.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
        cursor = "▋" if i % 2 == 0 else ""
        draw.text((68, 50), cursor, fill=CURSOR_COLOR, font=font_bold)
        save_frame(img)

    # 2. Type cmd1
    step = 3
    for i in range(0, len(cmd1) + 1, step):
        img, draw = create_base_canvas()
        draw.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
        typed = cmd1[:i]
        draw.text((68, 50), typed, fill=CMD_COLOR, font=font_regular)
        x_cur = 68 + font_regular.getlength(typed)
        draw.text((x_cur, 50), "▋", fill=CURSOR_COLOR, font=font_bold)
        save_frame(img)

    # 3. Enter pressed -> Status lines (6 frames)
    status_messages = [
        "[*] Connecting to Hugging Face Hub API...",
        "[*] Zero-execution inspection: configs, tokenizer, templates...",
        "[*] Evaluating 42 security rules across 13 scanners...",
    ]
    for s_idx in range(len(status_messages)):
        img, draw = create_base_canvas()
        draw.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
        draw.text((68, 50), cmd1, fill=CMD_COLOR, font=font_regular)

        y = 75
        for m in status_messages[: s_idx + 1]:
            draw.text((24, y), m, fill=STATUS_COLOR, font=font_regular)
            y += 20
        save_frame(img)
        save_frame(img)

    # 4. Display Scan Report (hold 25 frames = 2.5s)
    img_scan, draw_scan = create_base_canvas()
    draw_scan.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
    draw_scan.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
    draw_scan.text((68, 50), cmd1, fill=CMD_COLOR, font=font_regular)
    render_rich_lines(scan_lines, draw_scan, x_start=24, y_start=76, line_height=18)

    for _ in range(25):
        save_frame(img_scan)

    # 5. Clear for command 2
    # Type cmd2
    for i in range(0, len(cmd2) + 1, step):
        img, draw = create_base_canvas()
        draw.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
        typed = cmd2[:i]
        draw.text((68, 50), typed, fill=CMD_COLOR, font=font_regular)
        x_cur = 68 + font_regular.getlength(typed)
        draw.text((x_cur, 50), "▋", fill=CURSOR_COLOR, font=font_bold)
        save_frame(img)

    # 6. Status verify lines
    verify_status = [
        "[*] Finding Verification Engine: target acquired",
        "[*] Computing cryptographic SHA-256 byte fingerprints...",
        "[*] Synthesizing deterministic reproduction walkthrough...",
    ]
    for s_idx in range(len(verify_status)):
        img, draw = create_base_canvas()
        draw.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
        draw.text((68, 50), cmd2, fill=CMD_COLOR, font=font_regular)

        y = 75
        for m in verify_status[: s_idx + 1]:
            draw.text((24, y), m, fill=(115, 218, 202), font=font_regular)
            y += 20
        save_frame(img)
        save_frame(img)

    # 7. Display Proof-of-Finding Dossier (hold 35 frames = 3.5s)
    img_verify, draw_verify = create_base_canvas()
    draw_verify.text((24, 50), "➜ ", fill=PROMPT_ARROW, font=font_bold)
    draw_verify.text((42, 50), " ~ ", fill=PROMPT_DIR, font=font_bold)
    draw_verify.text((68, 50), cmd2, fill=CMD_COLOR, font=font_regular)
    render_rich_lines(verify_lines, draw_verify, x_start=24, y_start=76, line_height=18)

    for _ in range(35):
        save_frame(img_verify)

    print(f"Generated {frame_idx} frames in {FRAMES_DIR}")

    # Compile with Pillow (Pure Python, zero external dependency)
    OUTPUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    print("Compiling animated GIF with Pillow...")
    frame_files = sorted(FRAMES_DIR.glob("frame_*.png"))
    images = [Image.open(f).convert("RGB") for f in frame_files]
    quantized_images = [img.convert("P", palette=Image.ADAPTIVE, colors=128) for img in images]

    quantized_images[0].save(
        OUTPUT_GIF,
        save_all=True,
        append_images=quantized_images[1:],
        optimize=True,
        duration=100,  # 100ms per frame = 10 FPS
        loop=0,
    )

    size_kb = OUTPUT_GIF.stat().st_size / 1024
    print(f"Successfully generated {OUTPUT_GIF} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    generate_frames()
