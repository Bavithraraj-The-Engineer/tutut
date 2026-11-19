"""
The tutut approval window (tkinter, standard library only).

Layout, top to bottom:

    [shield]  Approve tool call?                         1 of 3 waiting
              via Claude Desktop → mcp-remote → https://…
    ┌───────────────────────────────────────────────────────────────┐
    │ delete_note                                     [Destructive] │
    │ on demo-notes                                                 │
    │ ● The server marks it destructive                              │
    └───────────────────────────────────────────────────────────────┘
    Arguments                                                1 field
    ┌───────────────────────────────────────────────────────────────┐
    │ { "title": "secrets" }            (syntax-highlighted JSON)   │
    └───────────────────────────────────────────────────────────────┘
    (o) Remember my choice for delete_note on demo-notes
    Auto-blocks in 32 s   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░
    ───────────────────────────────────────────────────────────────
    Y allow · N or Esc block                     [ Block  N ] [ Allow  Y ]

UX / safety decisions:
  - The safe action is the default: Block has keyboard focus, so a stray
    Enter blocks. There is no "Enter = Allow".
  - Allow is *armed* only after ARM_DELAY_MS, so keystrokes or a click that
    were already on their way when the window grabbed focus can't approve.
    Blocking (N, Esc, the button, closing the window) works immediately.
  - Risk badge from the server's tool annotations and the tool name; the
    more severe wins and the reason says where it came from.

Run `python -m tutut.popup_ui` to preview the window with sample requests.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
import tkinter as tk
import tkinter.font as tkfont
from typing import Any, Callable

from .models import Decision, InterceptedRequest, JsonRpcMessage
from .risk import Risk, classify, json_tokens

ARM_DELAY_MS = 700
WIDTH = 600
PAD = 22
MAX_ARG_CHARS = 12_000
MAX_ARG_LINES = 14

# Light theme (Catppuccin Latte, matching the dashboard's light mode).
C = {
    "window": "#ffffff",
    "card": "#f7f8fb",
    "inset": "#f2f4f8",
    "border": "#dde1ea",
    "text": "#2b2e3b",
    "muted": "#5c5f77",
    "subtle": "#8c8fa1",
    "accent": "#1e66f5",
    "allow": "#2f9e44",
    "allow_hover": "#268a3a",
    "allow_text": "#ffffff",
    "block": "#d20f39",
    "block_soft": "#fdecef",
    "block_soft_hover": "#fbdbe2",
    "disabled": "#eceef3",
    "disabled_text": "#a0a3b4",
    "high": "#d20f39",
    "medium": "#b86e00",
    "low": "#2f8a2b",
    "unknown": "#6c6f85",
    # JSON syntax
    "key": "#1e66f5",
    "string": "#2f8a2b",
    "number": "#d4560b",
    "literal": "#8839ef",
    "punct": "#8c8fa1",
}

UI_FONTS = ["Inter", "SF Pro Text", "Segoe UI", "Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans"]
MONO_FONTS = ["JetBrains Mono", "SF Mono", "Menlo", "Cascadia Mono", "Consolas",
              "Ubuntu Mono", "DejaVu Sans Mono", "Noto Sans Mono"]


def _blend(fg: str, bg: str, alpha: float) -> str:
    """fg over bg at `alpha` (Tk has no transparency for fills)."""
    f = [int(fg[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(bg[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * alpha + y * (1 - alpha)):02x}" for x, y in zip(f, b))


def _pick_family(root: tk.Misc, candidates: list[str], fallback: str) -> str:
    families = set(tkfont.families(root))
    return next((c for c in candidates if c in families), fallback)


def rounded_rect(canvas: tk.Canvas, x1: float, y1: float, x2: float, y2: float, r: float, **kw: Any) -> int:
    """A rounded rectangle as a smoothed polygon (doubled points keep edges straight)."""
    r = max(0.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [
        x1 + r, y1, x1 + r, y1, x2 - r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y1 + r,
        x2, y2 - r, x2, y2 - r, x2, y2, x2 - r, y2, x2 - r, y2, x1 + r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(pts, smooth=True, **kw)


def format_arguments(args: Any) -> tuple[str, str]:
    """Pretty JSON for display (truncated) and a short summary like '2 fields'."""
    if not args:
        return "", ""
    try:
        text = json.dumps(args, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(args)
    summary = f"{len(args)} field{'s' if len(args) != 1 else ''}" if isinstance(args, dict) else type(args).__name__
    if len(text) > MAX_ARG_CHARS:
        hidden = len(text) - MAX_ARG_CHARS
        text = text[:MAX_ARG_CHARS] + f"\n… {hidden:,} more characters not shown"
        summary += " · truncated"
    return text, summary


# -- widgets ----------------------------------------------------------------------


class RoundButton(tk.Canvas):
    """Rounded, keyboard-focusable button with an optional key hint."""

    VARIANTS = {
        "primary": {"fill": C["allow"], "hover": C["allow_hover"], "text": C["allow_text"], "outline": ""},
        "danger": {"fill": C["block_soft"], "hover": C["block_soft_hover"], "text": C["block"], "outline": _blend(C["block"], C["window"], 0.45)},
    }

    def __init__(self, parent: tk.Misc, *, text: str, hint: str, variant: str, command: Callable[[], None],
                 font: tkfont.Font, hint_font: tkfont.Font, bg: str, width: int = 132, height: int = 40) -> None:
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0,
                         takefocus=1, cursor="hand2")
        self.text, self.hint, self.variant, self.command = text, hint, variant, command
        self.font, self.hint_font = font, hint_font
        self.w, self.h = width, height
        self.enabled = True
        self.hover = self.pressed = self.focused = False
        self.bind("<Enter>", lambda e: self._set(hover=True))
        self.bind("<Leave>", lambda e: self._set(hover=False, pressed=False))
        self.bind("<ButtonPress-1>", lambda e: self._set(pressed=True))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<FocusIn>", lambda e: self._set(focused=True))
        self.bind("<FocusOut>", lambda e: self._set(focused=False))
        self.bind("<Key-Return>", lambda e: self._activate())
        self.bind("<Key-space>", lambda e: self._activate())
        self._draw()

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def _set(self, **state: bool) -> None:
        for k, v in state.items():
            setattr(self, k, v)
        self._draw()

    def _release(self, event: tk.Event) -> None:
        inside = 0 <= event.x <= self.w and 0 <= event.y <= self.h
        self._set(pressed=False)
        if inside:
            self._activate()

    def _activate(self) -> str:
        if self.enabled:
            self.command()
        return "break"

    def _draw(self) -> None:
        self.delete("all")
        v = self.VARIANTS[self.variant]
        if not self.enabled:
            fill, text, outline = C["disabled"], C["disabled_text"], ""
        else:
            fill = v["hover"] if (self.hover or self.pressed) else v["fill"]
            text, outline = v["text"], v["outline"]
        inset = 1.5 if self.pressed else 0
        if self.focused:
            rounded_rect(self, 1, 1, self.w - 1, self.h - 1, 11, fill="", outline=C["accent"], width=2)
        rounded_rect(self, 4 + inset, 4 + inset, self.w - 4 - inset, self.h - 4 - inset, 8,
                     fill=fill, outline=outline, width=1 if outline else 0)
        # label + key hint, centred together
        tw = self.font.measure(self.text)
        kw = self.hint_font.measure(self.hint) + 10 if self.hint else 0
        gap = 9 if self.hint else 0
        x = (self.w - (tw + gap + kw)) / 2
        cy = self.h / 2
        self.create_text(x, cy, text=self.text, anchor="w", font=self.font, fill=text)
        if self.hint:
            kx = x + tw + gap
            key_bg = _blend(text, fill, 0.18)
            rounded_rect(self, kx, cy - 9, kx + kw, cy + 9, 4, fill=key_bg, outline="")
            self.create_text(kx + kw / 2, cy, text=self.hint, font=self.hint_font, fill=text)


class Toggle(tk.Canvas):
    """A small on/off switch."""

    def __init__(self, parent: tk.Misc, *, bg: str, on_change: Callable[[bool], None]) -> None:
        super().__init__(parent, width=40, height=24, bg=bg, highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self.value = False
        self.focused = False
        self.on_change = on_change
        self.bind("<ButtonRelease-1>", lambda e: self.toggle())
        self.bind("<Key-space>", lambda e: (self.toggle(), "break")[1])
        self.bind("<Key-Return>", lambda e: (self.toggle(), "break")[1])
        self.bind("<FocusIn>", lambda e: self._focus(True))
        self.bind("<FocusOut>", lambda e: self._focus(False))
        self._draw()

    def toggle(self) -> None:
        self.value = not self.value
        self._draw()
        self.on_change(self.value)

    def _focus(self, on: bool) -> None:
        self.focused = on
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        if self.focused:
            rounded_rect(self, 0.5, 0.5, 39.5, 23.5, 12, fill="", outline=C["accent"], width=2)
        track = C["accent"] if self.value else C["border"]
        rounded_rect(self, 3, 4, 37, 20, 8, fill=track, outline="")
        x = 29 if self.value else 11
        self.create_oval(x - 6, 6, x + 6, 18, fill=C["window"] if self.value else C["muted"], outline="")


class Badge(tk.Canvas):
    """Pill-shaped label."""

    def __init__(self, parent: tk.Misc, *, text: str, color: str, bg: str, font: tkfont.Font) -> None:
        w = font.measure(text) + 22
        super().__init__(parent, width=w, height=24, bg=bg, highlightthickness=0, bd=0)
        rounded_rect(self, 0, 0, w, 24, 12, fill=_blend(color, bg, 0.16), outline=_blend(color, bg, 0.5))
        self.create_text(w / 2, 12, text=text, font=font, fill=color)


class RoundedPanel(tk.Canvas):
    """
    A fixed-width panel with rounded corners: Tk frames can't be rounded,
    so the panel is a canvas that draws the background and hosts `.body`.
    Call finalize() once the body's children are packed.
    """

    def __init__(self, parent: tk.Misc, *, width: int, bg: str, fill: str, outline: str,
                 radius: int = 12, padx: int = 16, pady: int = 14) -> None:
        super().__init__(parent, width=width, height=10, bg=bg, highlightthickness=0, bd=0)
        self.w, self.fill, self.outline, self.radius = width, fill, outline, radius
        self.padx, self.pady = padx, pady
        self.body = tk.Frame(self, bg=fill)
        self.create_window(padx, pady, window=self.body, anchor="nw", width=width - 2 * padx)

    def finalize(self) -> None:
        self.body.update_idletasks()
        h = self.body.winfo_reqheight() + 2 * self.pady
        self.configure(height=h)
        self.delete("panel")
        rounded_rect(self, 0.5, 0.5, self.w - 0.5, h - 0.5, self.radius,
                     fill=self.fill, outline=self.outline, width=1, tags="panel")
        self.tag_lower("panel")


class CountdownBar(tk.Canvas):
    def __init__(self, parent: tk.Misc, *, width: int, bg: str) -> None:
        super().__init__(parent, width=width, height=6, bg=bg, highlightthickness=0, bd=0)
        self.w = width

    def set(self, fraction: float, color: str) -> None:
        self.delete("all")
        rounded_rect(self, 0, 0, self.w, 6, 3, fill=C["border"], outline="")
        fill_w = max(0.0, min(1.0, fraction)) * self.w
        if fill_w >= 6:
            rounded_rect(self, 0, 0, fill_w, 6, 3, fill=color, outline="")


def _shield(canvas: tk.Canvas, color: str, bg: str, glyph: str, font: tkfont.Font) -> None:
    rounded_rect(canvas, 0, 0, 40, 40, 11, fill=_blend(color, bg, 0.16), outline="")
    # a small shield outline
    pts = [20, 8, 30, 12, 30, 21, 20, 32, 10, 21, 10, 12]
    canvas.create_polygon(pts, smooth=True, fill="", outline=color, width=2)
    canvas.create_text(20, 20, text=glyph, font=font, fill=color)


# -- the window ---------------------------------------------------------------------


class PopupWindow:
    """Builds the approval window for one request and records the decision."""

    def __init__(
        self,
        request: InterceptedRequest,
        result: Any,
        *,
        timeout: float = 0,
        queue_position: int = 0,
        queue_total: int = 0,
        arm_delay_ms: int = ARM_DELAY_MS,
    ) -> None:
        self.request = request
        self.result = result
        self.timeout = float(timeout or 0)
        self.closed = False
        self.armed = False
        self.remember = False
        self.risk: Risk = classify(request.tool_name, getattr(request, "annotations", None))

        root = self.root = tk.Tk()
        root.withdraw()
        root.title(f"tutut — approve {request.tool_name}?")
        root.configure(bg=C["window"])
        root.resizable(False, False)
        try:
            root.attributes("-topmost", True)
        except tk.TclError:
            pass
        try:
            root.attributes("-type", "dialog")  # X11: let the WM treat it as a dialog
        except tk.TclError:
            pass

        ui = _pick_family(root, UI_FONTS, "Helvetica")
        mono = _pick_family(root, MONO_FONTS, "Courier")
        self.f = {
            "title": tkfont.Font(root, family=ui, size=15, weight="bold"),
            "body": tkfont.Font(root, family=ui, size=11),
            "bold": tkfont.Font(root, family=ui, size=11, weight="bold"),
            "small": tkfont.Font(root, family=ui, size=10),
            "badge": tkfont.Font(root, family=ui, size=10, weight="bold"),
            "tool": tkfont.Font(root, family=mono, size=16, weight="bold"),
            "mono": tkfont.Font(root, family=mono, size=11),
            "button": tkfont.Font(root, family=ui, size=11, weight="bold"),
            "key": tkfont.Font(root, family=mono, size=9, weight="bold"),
            "glyph": tkfont.Font(root, family=ui, size=12, weight="bold"),
        }

        self._build(queue_position, queue_total)
        self._bind_keys()
        self._place()
        self.started = time.monotonic()
        root.protocol("WM_DELETE_WINDOW", lambda: self.decide(Decision.BLOCK, "user"))
        root.after(arm_delay_ms, self._arm)
        root.after(200, self._watch_external)
        if self.timeout > 0:
            root.after(100, self._tick)
        self._fade_in()

    # -- layout --

    def _build(self, queue_position: int, queue_total: int) -> None:
        req, f, root = self.request, self.f, self.root
        risk_color = C[self.risk.level]
        inner = WIDTH - 2 * PAD
        panels: list[RoundedPanel] = []

        # header: shield, title + source, queue position
        head = tk.Frame(root, bg=C["window"])
        head.pack(fill="x", padx=PAD, pady=(PAD, 16))
        icon = tk.Canvas(head, width=40, height=40, bg=C["window"], highlightthickness=0, bd=0)
        glyph = {"high": "!", "medium": "!", "low": "✓"}.get(self.risk.level, "?")
        _shield(icon, risk_color, C["window"], glyph, f["glyph"])
        icon.pack(side="left", anchor="n")
        if queue_total > 1:  # packed before the expanding title column so it isn't squeezed
            Badge(head, text=f"{queue_position} of {queue_total}", color=C["accent"],
                  bg=C["window"], font=f["badge"]).pack(side="right", anchor="n", pady=(8, 0))
        titles = tk.Frame(head, bg=C["window"])
        titles.pack(side="left", fill="x", expand=True, padx=(14, 0))
        tk.Label(titles, text="Approve tool call?", font=f["title"], fg=C["text"], bg=C["window"],
                 anchor="w").pack(fill="x")
        tk.Label(titles, text=f"via {req.source}" if req.source else "Claude wants to run a tool",
                 font=f["small"], fg=C["muted"], bg=C["window"], anchor="w", justify="left",
                 wraplength=inner - 130).pack(fill="x", pady=(2, 0))

        # tool card - its border takes the risk colour when there is a risk
        outline = {"high": _blend(risk_color, C["card"], 0.55),
                   "medium": _blend(risk_color, C["card"], 0.40)}.get(self.risk.level, C["border"])
        card = RoundedPanel(root, width=inner, bg=C["window"], fill=C["card"], outline=outline, radius=14)
        card.pack(padx=PAD)
        panels.append(card)
        top = tk.Frame(card.body, bg=C["card"])
        top.pack(fill="x")
        Badge(top, text=self.risk.label, color=risk_color, bg=C["card"],
              font=f["badge"]).pack(side="right", anchor="n", pady=(3, 0))
        tk.Label(top, text=req.tool_name, font=f["tool"], fg=C["text"], bg=C["card"], anchor="w",
                 justify="left", wraplength=inner - 180).pack(side="left", fill="x")
        tk.Label(card.body, text=f"on {req.server_name}", font=f["body"], fg=C["muted"], bg=C["card"],
                 anchor="w").pack(fill="x", pady=(2, 0))
        why = tk.Frame(card.body, bg=C["card"])
        why.pack(fill="x", pady=(10, 0))
        dot = tk.Canvas(why, width=8, height=8, bg=C["card"], highlightthickness=0, bd=0)
        dot.create_oval(0, 0, 8, 8, fill=risk_color, outline="")
        dot.pack(side="left", padx=(0, 8))
        tk.Label(why, text=self.risk.reason, font=f["small"], fg=C["muted"], bg=C["card"], anchor="w",
                 justify="left", wraplength=inner - 60).pack(side="left", fill="x")

        # arguments
        text, summary = format_arguments(req.arguments)
        ahead = tk.Frame(root, bg=C["window"])
        ahead.pack(fill="x", padx=PAD, pady=(18, 8))
        tk.Label(ahead, text="Arguments", font=f["bold"], fg=C["text"], bg=C["window"]).pack(side="left")
        tk.Label(ahead, text=summary, font=f["small"], fg=C["subtle"], bg=C["window"]).pack(side="right")
        box = RoundedPanel(root, width=inner, bg=C["window"], fill=C["inset"], outline=C["border"],
                           radius=12, padx=4, pady=4)
        box.pack(padx=PAD)
        panels.append(box)
        if text:
            # Size by *displayed* lines: one JSON line holding a long string
            # (e.g. file content with escaped newlines) wraps many times, and
            # without this it would be cut off with no scrollbar.
            usable_px = inner - 8 - 2 * 10 - 14          # panel pad, text pad, scrollbar
            per_line = max(20, usable_px // max(1, f["mono"].measure("0")))
            lines = sum(max(1, -(-len(line) // per_line)) for line in text.split("\n"))
            height = max(2, min(lines, MAX_ARG_LINES))
            args = tk.Text(box.body, height=height, width=1, wrap="word", bg=C["inset"], fg=C["text"],
                           font=f["mono"], relief="flat", bd=0, highlightthickness=0, padx=10, pady=8,
                           insertwidth=0, selectbackground=C["border"], selectforeground=C["text"],
                           cursor="arrow", takefocus=0)
            for kind in ("key", "string", "number", "literal", "punct"):
                args.tag_configure(kind, foreground=C[kind])
            for kind, chunk in json_tokens(text):
                args.insert("end", chunk, kind if kind in ("key", "string", "number", "literal", "punct") else ())
            args.configure(state="disabled")
            if lines > MAX_ARG_LINES:
                bar = tk.Scrollbar(box.body, orient="vertical", command=args.yview, width=10, bd=0,
                                   highlightthickness=0, relief="flat", elementborderwidth=0,
                                   bg=C["border"], activebackground=C["subtle"], troughcolor=C["inset"])
                args.configure(yscrollcommand=bar.set)
                bar.pack(side="right", fill="y")
            args.pack(side="left", fill="both", expand=True)
        else:
            tk.Label(box.body, text="This tool call has no arguments.", font=f["small"], fg=C["subtle"],
                     bg=C["inset"], anchor="w").pack(fill="x", padx=10, pady=8)

        # remember
        rem = tk.Frame(root, bg=C["window"])
        rem.pack(fill="x", padx=PAD, pady=(16, 0))
        self.remember_label = tk.Label(
            rem, text=f"Remember my choice for {req.tool_name} on {req.server_name}",
            font=f["small"], fg=C["muted"], bg=C["window"], anchor="w", justify="left", wraplength=inner - 60)
        self.toggle = Toggle(rem, bg=C["window"], on_change=self._on_remember)
        self.toggle.pack(side="left")
        self.remember_label.pack(side="left", fill="x", padx=(10, 0))
        self.remember_label.bind("<Button-1>", lambda e: self.toggle.toggle())

        # countdown
        if self.timeout > 0:
            cd = tk.Frame(root, bg=C["window"])
            cd.pack(fill="x", padx=PAD, pady=(14, 0))
            self.countdown_label = tk.Label(cd, text="", font=f["small"], fg=C["muted"], bg=C["window"], anchor="w")
            self.countdown_label.pack(fill="x")
            self.countdown = CountdownBar(cd, width=inner, bg=C["window"])
            self.countdown.pack(anchor="w", pady=(6, 0))
            self._render_countdown(self.timeout)

        # footer band
        tk.Frame(root, bg=C["border"], height=1).pack(fill="x", pady=(20, 0))
        foot = tk.Frame(root, bg=C["inset"])
        foot.pack(fill="x")
        row = tk.Frame(foot, bg=C["inset"])
        row.pack(fill="x", padx=PAD - 4, pady=12)
        self.allow_btn = RoundButton(row, text="Allow", hint="Y", variant="primary",
                                     command=lambda: self.decide(Decision.ALLOW, "user"),
                                     font=f["button"], hint_font=f["key"], bg=C["inset"])
        self.block_btn = RoundButton(row, text="Block", hint="N", variant="danger",
                                     command=lambda: self.decide(Decision.BLOCK, "user"),
                                     font=f["button"], hint_font=f["key"], bg=C["inset"])
        self.allow_btn.pack(side="right")
        self.block_btn.pack(side="right", padx=(0, 8))
        self.allow_btn.set_enabled(False)  # armed after a short delay
        self.hint = tk.Label(row, text="Esc blocks", font=f["small"], fg=C["subtle"], bg=C["inset"], anchor="w")
        self.hint.pack(side="left", padx=(4, 0))

        for panel in panels:
            panel.finalize()

    def _place(self) -> None:
        root = self.root
        root.update_idletasks()
        w, h = WIDTH, root.winfo_reqheight()
        x = (root.winfo_screenwidth() - w) // 2
        y = max(40, (root.winfo_screenheight() - h) // 3)  # a bit above centre
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.deiconify()
        try:
            root.lift()
            root.focus_force()
        except tk.TclError:
            pass
        if platform.system() == "Darwin":  # macOS won't raise a background app's window
            try:
                subprocess.Popen(
                    ["osascript", "-e", 'tell application "System Events" to set frontmost of the first '
                     f"process whose unix id is {os.getpid()} to true"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass
        self.block_btn.focus_set()  # the safe action is the keyboard default

    def _fade_in(self, step: int = 0) -> None:
        try:
            self.root.attributes("-alpha", min(1.0, 0.2 + step * 0.2))
        except tk.TclError:
            return
        if step < 4 and not self.closed:
            self.root.after(16, self._fade_in, step + 1)

    # -- behaviour --

    def _bind_keys(self) -> None:
        r = self.root
        for key in ("<Escape>", "<Key-n>", "<Key-N>"):
            r.bind(key, lambda e: self.decide(Decision.BLOCK, "user"))
        for key in ("<Key-y>", "<Key-Y>"):
            r.bind(key, lambda e: self.decide(Decision.ALLOW, "user"))

    def _arm(self) -> None:
        if self.closed:
            return
        self.armed = True
        self.allow_btn.set_enabled(True)
        self.hint.configure(text="Y allow · N or Esc block")

    def _on_remember(self, on: bool) -> None:
        self.remember = on
        self.remember_label.configure(fg=C["text"] if on else C["muted"])

    def _render_countdown(self, remaining: float) -> None:
        frac = remaining / self.timeout if self.timeout else 0
        color = C["accent"] if remaining > 10 else C["medium"] if remaining > 5 else C["high"]
        self.countdown.set(frac, color)
        secs = max(0, int(remaining + 0.999))
        self.countdown_label.configure(
            text=f"Auto-blocks in {secs} s", fg=C["muted"] if remaining > 10 else color)

    def _tick(self) -> None:
        if self.closed:
            return
        remaining = self.timeout - (time.monotonic() - self.started)
        if remaining <= 0:
            self.decide(Decision.BLOCK, "timeout")
            return
        self._render_countdown(remaining)
        self.root.after(100, self._tick)

    def _watch_external(self) -> None:
        # Decided elsewhere (e.g. Claude cancelled the request): close.
        if self.closed:
            return
        if self.result.is_set:
            self._close()
        else:
            self.root.after(200, self._watch_external)

    def decide(self, decision: Decision, reason: str = "user") -> None:
        if self.closed:
            return
        if decision == Decision.ALLOW and not self.armed:
            return  # too soon after the window appeared
        self.result.set(decision, remember=self.remember if reason == "user" else False, reason=reason)
        self._close()

    def _close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.root.destroy()
            except tk.TclError:
                pass

    def run(self) -> None:
        self.root.mainloop()
        # Window gone without a decision (e.g. killed by the window manager).
        self.result.set(Decision.BLOCK, remember=False, reason="user")


# -- preview ------------------------------------------------------------------------

SAMPLES = [
    ("demo-notes", "delete_note", {"title": "secrets"}, {"destructiveHint": True},
     "Claude Desktop → mcp-remote → http://127.0.0.1:8931/mcp"),
    ("filesystem", "write_file", {"path": "/home/me/notes/todo.md", "content": "- ship tutut\n- record the demo\n"},
     None, "Claude Desktop (local server)"),
    ("demo-notes", "list_notes", {}, {"readOnlyHint": True}, "claude.ai / Anthropic cloud (via tunnel)"),
]


def sample_request(i: int) -> InterceptedRequest:
    server, tool, args, ann, source = SAMPLES[i % len(SAMPLES)]
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": i, "method": "tools/call",
                              "params": {"name": tool, "arguments": args}})
    return InterceptedRequest(id=str(i), message=msg, server_name=server, tool_name=tool,
                              arguments=args, source=source, annotations=ann)


if __name__ == "__main__":
    from .gui import PopupResult

    for i in range(len(SAMPLES)):
        res = PopupResult()
        PopupWindow(sample_request(i), res, timeout=45, queue_position=i + 1, queue_total=len(SAMPLES)).run()
        print(f"{SAMPLES[i][1]}: {res.decision.value} (by {res.reason}, remember={res.remember})")
