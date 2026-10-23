#!/usr/bin/env python3
"""
Comprehensive, Slow-Paced ASCII/Terminal Video GIF Recorder for llm-scan.
Demonstrates all major scanner functionalities with zero personal information:
  1. CLI Help & Command Discovery (`llm-scan --help`)
  2. Remote Hugging Face Scan (`llm-scan scan <model> --remote`)
  3. Proof-of-Finding Verification Engine (`llm-scan verify <model> --remote --format html`)
  4. Regulatory Framework Crosswalk Matrix (`llm-scan compliance`)
  5. 42 Registered Security Rules Catalog (`llm-scan list-rules`)
  6. 5-Phase End-to-End LLM Lifecycle Threat Model (`llm-scan threat-model`)

All usernames, hostnames, and private file paths are strictly omitted.
"""

import io
import os
import shutil
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.segment import Segment

# Dimensions & FPS
WIDTH = 980
HEIGHT = 650
FPS = 10
FRAMES_DIR = Path("/tmp/llm_scan_frames")
OUTPUT_GIF = Path("assets/demo.gif")

# Color Palette - Tokyo Night / Modern Dark Theme
BG_COLOR = (26, 27, 38)
BAR_COLOR = (22, 22, 30)
BORDER_COLOR = (41, 46, 66)
TITLE_COLOR = (122, 130, 160)
DEFAULT_TEXT = (192, 202, 245)
PROMPT_ARROW = (115, 218, 202)   # Cyan / Teal
PROMPT_DIR = (122, 162, 247)     # Blue
CMD_COLOR = (255, 255, 255)      # White
CURSOR_COLOR = (247, 118, 142)   # Coral / Pink
STATUS_COLOR = (122, 162, 247)   # Muted Blue

# Fonts
font_regular = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13, index=0)
font_bold = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13, index=1)
try:
    font_title = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 12)
except Exception:
    font_title = font_regular


def create_base_canvas():
    """Renders macOS terminal window chrome with traffic lights and clean title."""
    img = Image.new("RGB", (WIDTH, HEIGHT), color=BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Window bar
    draw.rectangle([(0, 0), (WIDTH, 36)], fill=BAR_COLOR)
    draw.line([(0, 36), (WIDTH, 36)], fill=BORDER_COLOR, width=1)

    # Traffic light buttons
    draw.ellipse([(16, 12), (28, 24)], fill=(255, 95, 86))    # Red (Close)
    draw.ellipse([(36, 12), (48, 24)], fill=(255, 189, 46))   # Yellow (Minimize)
    draw.ellipse([(56, 12), (68, 24)], fill=(39, 201, 63))    # Green (Maximize)

    # Window title
    title = "llm-scan — zero-execution model security scanner & verifier"
    draw.text((WIDTH // 2 - 200, 10), title, fill=TITLE_COLOR, font=font_title)
    return img, draw


def render_rich_lines(lines, draw, x_start=24, y_start=48, line_height=18):
    """Draws Rich line segments onto Pillow canvas."""
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


def build_help_output(console: Console):
    title = Text(" LLM MODEL SECURITY SCANNER (llm-scan v1.0.0) ", style="bold white on blue")
    console.print(Panel(Text("Zero-execution static analysis scanner & proof verification engine for LLMs.", style="dim"), title=title, border_style="blue", expand=False))

    table = Table(title="[bold cyan]Core CLI Commands[/bold cyan]", header_style="bold magenta")
    table.add_column("Command", style="bold yellow", width=14)
    table.add_column("Description", width=68)
    table.add_row("scan", "Audit model directory, single file, or remote Hugging Face repository")
    table.add_row("verify", "Prove findings with cryptographic SHA-256 fingerprints & reproduction trace")
    table.add_row("compliance", "Display regulatory crosswalk (OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act)")
    table.add_row("list-rules", "List all 42 registered security detection rules and vulnerability signatures")
    table.add_row("threat-model", "Display the 5-phase end-to-end LLM security lifecycle threat model")
    console.print(table)


def build_scan_output(console: Console):
    banner_title = Text(" LLM MODEL SECURITY SCANNER ", style="bold white on blue")
    banner_subtitle = Text("Target: NousResearch/Hermes-3-Llama-3.1-8B | Scanned in 2.14s (Zero-Execution)", style="dim")
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

    rem = Text("Remediation: Set 'special: true' for '<|im_start|>' in tokenizer.json to escape user turns.", style="green")
    console.print(Panel(rem, title="[bold green]Priority Remediation Guidelines[/bold green]", border_style="green", expand=False))


def build_verify_output(console: Console):
    banner_title = Text(" PROOF-OF-FINDING VERIFICATION DOSSIER ", style="bold white on green")
    banner_subtitle = Text("Target: NousResearch/Hermes-3-Llama-3.1-8B | Status: 100% PROVEN", style="bold green")
    console.print(Panel(banner_subtitle, title=banner_title, border_style="green", expand=False))

    proof_body = (
        "[bold red]Finding #1: Critical Delimiter Marked Non-Special: '<|im_start|>' (SEC-TOK-004)[/bold red]\n"
        "File: [cyan]tokenizer.json[/cyan]\n"
        "SHA-256 Fingerprint: [yellow]492ebf55999f2a71beed8104e12d808bfcba5a230b7e511f2c6ccbc616f9d76c[/yellow]\n"
        "Proof Status: [bold green]✅ VERIFIED PROOF (Deterministic Reproduction)[/bold green]\n\n"
        "[bold white]Consumer Impact Summary:[/bold white]\n"
        "CONFIRMED PROMPT INJECTION: '<|im_start|>' declared with special=false.\n"
        "End-users can inject raw delimiter tokens to break turn isolation.\n\n"
        "[bold white]Reproduction Step Trace:[/bold white]\n"
        "  1. Tokenizer reads '<|im_start|>' as literal string, emits token ID 128039.\n"
        "  2. Model runtime interprets ID 128039 as system boundary marker.\n"
        "  3. Result: Prompt breakout / assistant impersonation confirmed.\n\n"
        "[bold cyan]HTML Proof Certificate:[/bold cyan] [green]cert.html[/green] successfully exported [✓]"
    )
    console.print(Panel(proof_body, title="[bold white]Cryptographic Finding Dossier[/bold white]", border_style="cyan", expand=False))


def build_compliance_output(console: Console):
    table = Table(title="[bold green]Security Framework Crosswalk Matrix[/bold green]", header_style="bold magenta")
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("OWASP LLM", style="magenta", width=18)
    table.add_column("MITRE ATLAS", style="yellow", width=18)
    table.add_column("NIST AI RMF", style="cyan", width=16)
    table.add_column("EU AI Act (2024/1689)", style="blue", width=20)

    matrix = [
        ("SEC-PCK-001", "LLM03: Supply Chain", "AML.T0010: Supply", "MANAGE-2.4 (Vet)", "Art. 15 / 55 (Systemic)"),
        ("SEC-RCE-002", "LLM03: Supply Chain", "AML.T0048: Exec", "MANAGE-2.4 (Vet)", "Art. 15 (Cybersecurity)"),
        ("SEC-TMPL-SSTI", "LLM03 / LLM01", "AML.T0048: Exec", "MEASURE-2.6 (Test)", "Art. 15 (Cybersecurity)"),
        ("SEC-ST-003", "LLM10: DoS Bomb", "AML.T0029: DoS", "MEASURE-2.6 (Test)", "Art. 15 (Robustness)"),
        ("SEC-TOK-004", "LLM01: Injection", "AML.T0051: Injection", "MEASURE-2.6 (Test)", "Art. 15 (Cybersecurity)"),
        ("SEC-PEFT-002", "LLM04: Poisoning", "AML.T0018: Backdoor", "MEASURE-2.6 (Test)", "Art. 15 (Robustness)"),
        ("SEC-SEC-001", "LLM02: Data Leak", "AML.T0040: IP Theft", "GOVERN-1.2 & MNG", "Art. 15 & 53 (Protect)"),
    ]
    for row in matrix:
        table.add_row(*row)
    console.print(table)


def build_rules_output(console: Console):
    table = Table(title="[bold cyan]42 Registered Security Detection Rules (Catalog)[/bold cyan]", header_style="bold magenta")
    table.add_column("Rule ID", style="bold", width=16)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Category", width=22)
    table.add_column("Vulnerability Description", width=38)

    sample_rules = [
        ("SEC-PCK-001", "[bold red]CRITICAL[/bold red]", "Deserialization", "Pickle opcode RCE (os.system, exec)"),
        ("SEC-ZIP-001", "[bold red]CRITICAL[/bold red]", "Deserialization", "ZipSlip path traversal in PyTorch archive"),
        ("SEC-RCE-MAP-001", "[bold red]HIGH[/bold red]", "Remote Code", "auto_map requiring trust_remote_code"),
        ("SEC-TMPL-SSTI-001", "[bold red]CRITICAL[/bold red]", "Chat Template SSTI", "Jinja2 reflection escape (CVE-2024-34359)"),
        ("SEC-ST-003", "[bold red]CRITICAL[/bold red]", "Format Integrity", "SafeTensors memory bomb (CVE-2023-44469)"),
        ("SEC-ONNX-001", "[bold red]CRITICAL[/bold red]", "Deserialization", "ONNX external data traversal (CVE-2024-27318)"),
        ("SEC-TOK-004", "[bold red]HIGH[/bold red]", "Special Tokens", "Delimiter '<|im_start|>' prompt injection"),
        ("SEC-TOK-006", "[bold red]HIGH[/bold red]", "Unicode Smuggling", "Unicode Bidi Trojan Override (CVE-2021-42574)"),
        ("SEC-PEFT-002", "[bold red]HIGH[/bold red]", "Adapter Poisoning", "LoRA scaling sabotage (alignment stripping)"),
        ("SEC-WGT-002", "[bold red]CRITICAL[/bold red]", "Weight Poisoning", "Poisoned weights with NaN/Inf values (DoS)"),
        ("SEC-SEC-001", "[bold red]CRITICAL[/bold red]", "Secret Leak", "Exposed HF token, OpenAI key, AWS key"),
    ]
    for rid, sev, cat, desc in sample_rules:
        table.add_row(rid, sev, cat, desc)
    console.print(table)
    console.print(Text("... and 31 more registered rules across 13 scanners (Run 'llm-scan list-rules' for full list)", style="dim"))


def build_threat_model_output(console: Console):
    tm_text = (
        "[bold white]End-to-End LLM Security Lifecycle Threat Model (5 Phases)[/bold white]\n\n"
        "1. [bold cyan]Data Collection & Curation:[/bold cyan]\n"
        "   Web scraping cache poisoning, Clean-label Trojans, PII & training data leaks.\n\n"
        "2. [bold cyan]Training & Architecture Phase:[/bold cyan]\n"
        "   Malicious Triton/CUDA kernels, Sleeper Agent weights, LoRA safety stripping.\n\n"
        "3. [bold yellow]Serialization & Distribution Phase (Primary Scanner Target):[/bold yellow]\n"
        "   Pickle RCE, trust_remote_code=True, Jinja2 SSTI, SafeTensors DoS, GGUF overflows.\n\n"
        "4. [bold cyan]Deployment & Infrastructure Phase:[/bold cyan]\n"
        "   Inference engine memory corruption (vLLM, llama.cpp), KV cache DoS exhaustion.\n\n"
        "5. [bold cyan]Post-Deployment & Inference Phase:[/bold cyan]\n"
        "   Direct/Indirect Prompt Injection, Jailbreaking, Autonomous Agent SSRF abuse."
    )
    console.print(Panel(tm_text, title="[bold green]LLM Security Threat Model[/bold green]", border_style="green", expand=False))


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

    # Pre-render lines for each scene silently
    def get_lines(render_func):
        f = io.StringIO()
        c = Console(width=90, color_system="truecolor", record=True, file=f)
        render_func(c)
        return list(Segment.split_and_crop_lines(c._record_buffer, 90))

    lines_help = get_lines(build_help_output)
    lines_scan = get_lines(build_scan_output)
    lines_verify = get_lines(build_verify_output)
    lines_compliance = get_lines(build_compliance_output)
    lines_rules = get_lines(build_rules_output)
    lines_threat_model = get_lines(build_threat_model_output)

    # Slow, deliberate typing helper
    def type_command(cmd, step=2):
        for i in range(0, len(cmd) + 1, step):
            img, draw = create_base_canvas()
            draw.text((24, 48), "➜ ", fill=PROMPT_ARROW, font=font_bold)
            draw.text((42, 48), " ~ ", fill=PROMPT_DIR, font=font_bold)
            typed = cmd[:i]
            draw.text((68, 48), typed, fill=CMD_COLOR, font=font_regular)
            x_cur = 68 + font_regular.getlength(typed)
            draw.text((x_cur, 48), "▋", fill=CURSOR_COLOR, font=font_bold)
            save_frame(img)

    def show_screen(cmd, lines, hold_frames=45):
        img, draw = create_base_canvas()
        draw.text((24, 48), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 48), " ~ ", fill=PROMPT_DIR, font=font_bold)
        draw.text((68, 48), cmd, fill=CMD_COLOR, font=font_regular)
        render_rich_lines(lines, draw, x_start=24, y_start=74, line_height=18)
        for _ in range(hold_frames):
            save_frame(img)

    def show_spinner(cmd, messages, per_msg_frames=5):
        for idx in range(len(messages)):
            img, draw = create_base_canvas()
            draw.text((24, 48), "➜ ", fill=PROMPT_ARROW, font=font_bold)
            draw.text((42, 48), " ~ ", fill=PROMPT_DIR, font=font_bold)
            draw.text((68, 48), cmd, fill=CMD_COLOR, font=font_regular)
            y = 75
            for m in messages[: idx + 1]:
                draw.text((24, y), m, fill=STATUS_COLOR, font=font_regular)
                y += 22
            for _ in range(per_msg_frames):
                save_frame(img)

    print("Generating comprehensive terminal demonstration frames...")

    # ----------------------------------------------------
    # Scene 1: CLI Discovery (`llm-scan --help`)
    # ----------------------------------------------------
    # Idle prompt (4 frames)
    for i in range(4):
        img, draw = create_base_canvas()
        draw.text((24, 48), "➜ ", fill=PROMPT_ARROW, font=font_bold)
        draw.text((42, 48), " ~ ", fill=PROMPT_DIR, font=font_bold)
        cursor = "▋" if i % 2 == 0 else ""
        draw.text((68, 48), cursor, fill=CURSOR_COLOR, font=font_bold)
        save_frame(img)

    cmd_help = "llm-scan --help"
    type_command(cmd_help, step=2)
    show_screen(cmd_help, lines_help, hold_frames=40)  # 4.0s pause

    # ----------------------------------------------------
    # Scene 2: Remote Hub Model Scan (`scan`)
    # ----------------------------------------------------
    cmd_scan = "llm-scan scan NousResearch/Hermes-3-Llama-3.1-8B --remote"
    type_command(cmd_scan, step=2)
    show_spinner(
        cmd_scan,
        [
            "[*] Connecting to Hugging Face Hub API (zero weight download)...",
            "[*] Zero-execution inspection: config.json, tokenizer.json, chat_template...",
            "[*] Evaluating 42 security rules across 13 scanners...",
        ],
        per_msg_frames=4,
    )
    show_screen(cmd_scan, lines_scan, hold_frames=50)  # 5.0s pause to read findings

    # ----------------------------------------------------
    # Scene 3: Proof-of-Finding Verification (`verify`)
    # ----------------------------------------------------
    cmd_verify = "llm-scan verify NousResearch/Hermes-3-Llama-3.1-8B --remote --format html"
    type_command(cmd_verify, step=2)
    show_spinner(
        cmd_verify,
        [
            "[*] Initializing Finding Verification Engine...",
            "[*] Computing cryptographic SHA-256 byte fingerprints...",
            "[*] Exporting interactive HTML proof certificate: cert.html [OK]",
        ],
        per_msg_frames=4,
    )
    show_screen(cmd_verify, lines_verify, hold_frames=55)  # 5.5s pause to read proof

    # ----------------------------------------------------
    # Scene 4: Regulatory Compliance Matrix (`compliance`)
    # ----------------------------------------------------
    cmd_comp = "llm-scan compliance"
    type_command(cmd_comp, step=2)
    show_screen(cmd_comp, lines_compliance, hold_frames=50)  # 5.0s pause

    # ----------------------------------------------------
    # Scene 5: 42 Security Rules Catalog (`list-rules`)
    # ----------------------------------------------------
    cmd_rules = "llm-scan list-rules"
    type_command(cmd_rules, step=2)
    show_screen(cmd_rules, lines_rules, hold_frames=50)  # 5.0s pause

    # ----------------------------------------------------
    # Scene 6: 5-Phase Threat Model (`threat-model`)
    # ----------------------------------------------------
    cmd_tm = "llm-scan threat-model"
    type_command(cmd_tm, step=2)
    show_screen(cmd_tm, lines_threat_model, hold_frames=55)  # 5.5s pause

    print(f"Generated {frame_idx} frames in {FRAMES_DIR}")

    # Compile with Pillow
    OUTPUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    print("Compiling slow, high-definition animated GIF with Pillow...")
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
    size_mb = size_kb / 1024
    print(f"Successfully generated {OUTPUT_GIF} ({size_mb:.2f} MB / {size_kb:.1f} KB)")


if __name__ == "__main__":
    generate_frames()
