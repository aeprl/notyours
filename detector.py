import os, sys, time, json, datetime, threading
import subprocess, tkinter as tk
import urllib.request, urllib.error
import engine
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
import pystray
from PIL import Image
from engine import *
from watchers import *
from watchers import _open_files_checker

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_SERVICE = True
except ImportError:
    HAS_SERVICE = False

def vt_lookup(sha256, callback):
    """Look up a SHA256 hash on VirusTotal. Calls callback(result_str)."""
    if not VT_API_KEY:
        callback("⚠ No VT API key set — add yours in Settings")
        return
    def _run():
        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            mal   = stats.get("malicious", 0)
            sus   = stats.get("suspicious", 0)
            total = sum(stats.values())
            if mal > 0:
                callback(f"🔴 MALICIOUS — {mal}/{total} engines flagged")
            elif sus > 0:
                callback(f"🟡 SUSPICIOUS — {sus}/{total} engines flagged")
            else:
                callback(f"🟢 CLEAN — 0/{total} engines flagged")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                callback("⚪ Not found in VirusTotal database")
            else:
                callback(f"VT error: HTTP {e.code}")
        except Exception as ex:
            callback(f"VT error: {ex}")
    threading.Thread(target=_run, daemon=True).start()


def validate_vt_key(key, callback):
    """Ping VirusTotal with the key to confirm it is valid. callback((ok, message))."""
    def _run():
        try:
            url = "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"
            req = urllib.request.Request(url, headers={"x-apikey": key})
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = resp.status == 200
            callback((ok, "✓ key valid" if ok else "✗ invalid key"))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                callback((False, "✗ invalid key"))
            else:
                callback((None, f"can't verify (HTTP {e.code})"))
        except Exception:
            callback((None, "can't verify"))
    threading.Thread(target=_run, daemon=True).start()


_NIN_BALLOONUSERCLICK = 0x0405
try:
    _orig_on_notify = pystray._win32.Icon._on_notify
    def _patched_on_notify(self, wparam, lparam):
        if lparam == _NIN_BALLOONUSERCLICK:
            cb = getattr(self, "_balloon_callback", None)
            if cb:
                try: cb()
                except Exception: pass
        return _orig_on_notify(self, wparam, lparam)
    pystray._win32.Icon._on_notify = _patched_on_notify
except Exception:
    pass

LEVEL_COLORS = {"CRITICAL":"#e8503a","HIGH":"#f5a623","MEDIUM":"#f0c040","INFO":"#6a6a7a"}
PAST_COLOR   = "#444455"
VT_COLORS    = {"safe":"#3ddc84","malicious":"#e8503a","suspicious":"#f5a623",
                "unknown":"#888899","checking":"#aaaacc"}

BG          = "#141414"
CARD_BG    = "#252526"
CARD_BORDER = "#1c1c1c"
HEADER_BG  = "#1e1e1e"
ROW_BG     = "#161616"
ROW_ALT    = "#1a1a1a"
SELECT_BG  = "#2a2a2a"
TEXT       = "#f0f0f0"
DIM        = "#9a9a9a"
DIM2       = "#6a6a6a"
GREEN      = "#3ddc84"
ARC_BG     = "#3a3a3a"

ACTIVE_COLUMNS = [
    {"key":"sel","label":"","width":30,"resizable":False,"minw":30},
    {"key":"level","label":"Level","width":110,"resizable":True,"minw":70},
    {"key":"category","label":"Category","width":150,"resizable":True,"minw":100},
    {"key":"message","label":"Message","width":380,"resizable":True,"minw":150},
    {"key":"vt","label":"VT Result","width":130,"resizable":True,"minw":80},
    {"key":"hash","label":"Hash Check","width":90,"resizable":True,"minw":60},
    {"key":"time","label":"Time","width":90,"resizable":True,"minw":60},
]

CATEGORY_ICON = {
    "Browser Profile Access":"folder",
    "WMI Persistence":"wmi",
    "Scheduled Task":"calendar",
    "Suspicious Network":"process",
    "Clipboard":"clipboard",
    "Registry Run Key":"reg",
    "Startup Folder":"startup",
    "Defender Exclusion":"shield",
    "Archive Staging":"archive",
    "DNS Anomaly":"dns",
    "PowerShell Spawn":"ps",
    "Run-Key Integrity":"integrity",
    "Startup Integrity":"integrity",
    "Browser Extension":"extension",
    "Executable Drop":"drop",
    "TypeLib Hijack":"typelib",
    "Wallet Access":"wallet",
    "Screenshot Capture":"screen",
    "AV Kill Attempt":"av",
}

def _resolve_logo_path():
    candidates = []
    if getattr(sys, "frozen", False):
        _exe_dir = os.path.dirname(sys.executable)
        _meipass = getattr(sys, "_MEIPASS", None)
        for base in (_meipass, _exe_dir, os.path.join(_exe_dir, "_internal")):
            if base:
                candidates.append(os.path.join(base, "notyours.ico"))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "notyours.ico"))
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return candidates[-1]

LOGO_PATH = _resolve_logo_path()

def load_logo(size):
    if not os.path.exists(LOGO_PATH):
        return None
    try:
        from PIL import Image, ImageTk
        img = Image.open(LOGO_PATH).convert("RGBA")
        img = img.resize((size, size), Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        try:
            img = tk.PhotoImage(file=LOGO_PATH)
            f = max(1, img.width() // size)
            return img.subsample(f, f)
        except Exception:
            return None

def draw_icon(c, kind, color, angle=0):
    c.delete("all")
    w = 1.4
    if kind == "folder":
        c.create_polygon(2,5, 6,5, 8,3, 14,3, 14,13, 2,13, outline=color, fill="", width=w)
    elif kind == "wmi":
        import math
        cx, cy = 8, 8
        c.create_oval(5,5,11,11, outline=color, width=w)
        for a in range(0,360,45):
            r = math.radians(a)
            c.create_line(cx, cy, cx+math.cos(r)*6, cy+math.sin(r)*6, fill=color, width=w)
    elif kind == "calendar":
        c.create_rectangle(3,4,13,13, outline=color, width=w)
        c.create_line(3,6,13,6, fill=color, width=w)
        c.create_line(5,2,5,4, fill=color, width=w)
        c.create_line(11,2,11,4, fill=color, width=w)
    elif kind == "process":
        c.create_oval(4,3,9,8, outline=color, width=w)
        c.create_arc(3,7,11,15, start=180, extent=180, style="arc", outline=color, width=w)
        c.create_oval(10,9,14,13, outline=color, width=w)
        c.create_line(14,13,16,15, fill=color, width=w)
    elif kind == "clipboard":
        c.create_rectangle(4,5,12,14, outline=color, width=w)
        c.create_rectangle(6,3,10,5, outline=color, width=w)
        c.create_line(6,8,10,8, fill=color, width=1)
        c.create_line(6,11,10,11, fill=color, width=1)
    elif kind == "gear":
        import math
        cx, cy = 7, 7
        c.create_oval(4,4,10,10, outline=color, width=w)
        for a in range(0,360,45):
            r = math.radians(a + angle)
            c.create_line(cx+math.cos(r)*5, cy+math.sin(r)*5,
                          cx+math.cos(r)*7, cy+math.sin(r)*7, fill=color, width=w)
    elif kind == "reg":
        c.create_rectangle(3,4,12,14, outline=color, width=w)
        c.create_line(3,7,12,7, fill=color, width=w)
        c.create_line(7,4,7,14, fill=color, width=w)
        c.create_oval(11,9,15,13, outline=color, width=w)
    elif kind == "startup":
        c.create_polygon(2,5, 6,5, 8,3, 14,3, 14,13, 2,13,
                         outline=color, fill="", width=w)
        c.create_line(8,4,8,10, fill=color, width=w)
        c.create_line(5,7,11,7, fill=color, width=w)
    elif kind == "shield":
        c.create_polygon(8,2, 14,5, 14,10, 8,15, 2,10, 2,5,
                         outline=color, width=w)
        c.create_line(8,5,8,11, fill=color, width=w)
    elif kind == "archive":
        c.create_rectangle(3,4,13,14, outline=color, width=w)
        c.create_line(3,8,13,8, fill=color, width=w)
        c.create_line(6,4,6,14, fill=color, width=w)
        c.create_line(10,4,10,14, fill=color, width=w)
    elif kind == "dns":
        c.create_oval(3,3,13,13, outline=color, width=w)
        c.create_line(8,3,8,13, fill=color, width=w)
        c.create_line(3,8,13,8, fill=color, width=w)
        c.create_line(4,5,12,11, fill=color, width=w)
        c.create_line(4,11,12,5, fill=color, width=w)
    elif kind == "ps":
        c.create_rectangle(3,3,13,13, outline=color, width=w)
        c.create_line(5,7,9,7, fill=color, width=w)
        c.create_line(9,10,12,13, fill=color, width=w)
    elif kind == "integrity":
        c.create_rectangle(3,4,13,13, outline=color, width=w)
        c.create_line(5,8,8,11, fill=color, width=w)
        c.create_line(8,11,12,5, fill=color, width=w)
    elif kind == "extension":
        c.create_rectangle(4,4,12,12, outline=color, width=w)
        c.create_rectangle(10,2,14,6, outline=color, width=w)
        c.create_rectangle(2,10,6,14, outline=color, width=w)
    elif kind == "drop":
        c.create_line(8,2,8,11, fill=color, width=w)
        c.create_line(4,8,8,12, fill=color, width=w)
        c.create_line(12,8,8,12, fill=color, width=w)
        c.create_line(4,13,12,13, fill=color, width=w)
    elif kind == "typelib":
        c.create_rectangle(3,3,13,13, outline=color, width=w)
        c.create_line(5,6,11,6, fill=color, width=1)
        c.create_line(5,9,11,9, fill=color, width=1)
        c.create_line(5,12,9,12, fill=color, width=1)
    elif kind == "wallet":
        c.create_oval(3,3,13,13, outline=color, width=w)
        c.create_line(8,5,8,11, fill=color, width=w)
        c.create_line(5,8,11,8, fill=color, width=w)
    elif kind == "screen":
        c.create_rectangle(3,3,13,12, outline=color, width=w)
        c.create_line(6,12,10,12, fill=color, width=w)
        c.create_line(8,12,8,14, fill=color, width=w)
    elif kind == "av":
        c.create_polygon(8,2, 14,5, 14,10, 8,15, 2,10, 2,5,
                         outline=color, width=w)
        c.create_line(5,5,11,11, fill=color, width=w)
        c.create_line(11,5,5,11, fill=color, width=w)


_ICON_PHOTOS = {}

def _cached_icon(kind, color="#bdbdbd"):
    key = (kind, color)
    if key in _ICON_PHOTOS:
        return _ICON_PHOTOS[key]
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        def r(x1,y1,x2,y2): return d.rectangle((x1,y1,x2,y2), outline=color, width=1)
        def l(x1,y1,x2,y2): return d.line((x1,y1,x2,y2), fill=color, width=1)
        def o(x1,y1,x2,y2): return d.ellipse((x1,y1,x2,y2), outline=color, width=1)
        def p(*pts): return d.polygon(pts, outline=color, width=1)
        def a(x1,y1,x2,y2,s,e): return d.arc((x1,y1,x2,y2), s, e, fill=color, width=1)
        if kind == "folder":
            p((2,5,6,5,8,3,14,3,14,13,2,13))
        elif kind == "wmi":
            o(5,5,11,11)
            for a_ in range(0,360,45): import math as m; cx=cy=8; r_=m.radians(a_); l(cx,cy,cx+m.cos(r_)*6,cy+m.sin(r_)*6)
        elif kind == "calendar":
            r(3,4,13,13); l(3,6,13,6); l(5,2,5,4); l(11,2,11,4)
        elif kind == "process":
            o(4,3,9,8); a(3,7,11,15,180,180); o(10,9,14,13); l(14,13,16,15)
        elif kind == "clipboard":
            r(4,5,12,14); r(6,3,10,5); l(6,8,10,8); l(6,11,10,11)
        elif kind == "reg":
            r(3,4,12,14); l(3,7,12,7); l(7,4,7,14); o(11,9,15,13)
        elif kind == "startup":
            p((2,5,6,5,8,3,14,3,14,13,2,13)); l(8,4,8,10); l(5,7,11,7)
        elif kind == "shield":
            p((8,2,14,5,14,10,8,15,2,10,2,5)); l(8,5,8,11)
        elif kind == "archive":
            r(3,4,13,14); l(3,8,13,8); l(6,4,6,14); l(10,4,10,14)
        elif kind == "dns":
            o(3,3,13,13); l(8,3,8,13); l(3,8,13,8); l(4,5,12,11); l(4,11,12,5)
        elif kind == "ps":
            r(3,3,13,13); l(5,7,9,7); l(9,10,12,13)
        elif kind == "integrity":
            r(3,4,13,13); l(5,8,8,11); l(8,11,12,5)
        elif kind == "extension":
            r(4,4,12,12); r(10,2,14,6); r(2,10,6,14)
        elif kind == "drop":
            l(8,2,8,11); l(4,8,8,12); l(12,8,8,12); l(4,13,12,13)
        elif kind == "typelib":
            r(3,3,13,13); l(5,6,11,6); l(5,9,11,9); l(5,12,9,12)
        elif kind == "wallet":
            o(3,3,13,13); l(8,5,8,11); l(5,8,11,8)
        elif kind == "screen":
            r(3,3,13,12); l(6,12,10,12); l(8,12,8,14)
        elif kind == "av":
            p((8,2,14,5,14,10,8,15,2,10,2,5)); l(5,5,11,11); l(11,5,5,11)
        photo = ImageTk.PhotoImage(img)
        _ICON_PHOTOS[key] = photo
        return photo
    except Exception:
        return None


class AlertTable:
    """Resizable, custom-drawn alert table (Level shows a colored dot, rows turn
    vibrant blue when selected)."""
    _style_done = False
    def __init__(self, parent, app, columns):
        self.app = app
        self.parent = parent
        self.columns = columns
        self.rows = []
        self.row_by_id = {}
        self.frame_map = {}
        self._dsx = 0; self._dsw = 0
        self._relayout_job = None
        self._last_msg_width = sum(c["width"] for c in columns if c["key"] == "message")
        self._build()

    def _build(self):
        if not AlertTable._style_done:
            s = ttk.Style()
            try: s.theme_use("clam")
            except Exception: pass
            s.configure("Dark.Vertical.TScrollbar", background="#3a3a3a",
                        troughcolor="#1b1b1b", bordercolor="#1b1b1b",
                        arrowcolor="#9a9a9a", gripcount=0, width=11)
            s.map("Dark.Vertical.TScrollbar", background=[("active","#4a4a4a")])
            AlertTable._style_done = True
        self.outer = tk.Frame(self.parent, bg=BG)
        self.header = tk.Frame(self.outer, bg=HEADER_BG, height=26)
        self.header.pack(fill="x")
        self._build_header()
        self.canvas = tk.Canvas(self.outer, bg=ROW_BG, highlightthickness=0)
        self.sb = ttk.Scrollbar(self.outer, orient="vertical", style="Dark.Vertical.TScrollbar",
                                command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.body = tk.Frame(self.canvas, bg=ROW_BG)
        self.body.configure(width=self._total())
        self.body.pack_propagate(False)
        self.canvas.create_window((0,0), window=self.body, anchor="nw")
        self.canvas.pack(side="left", fill="both", expand=True)

        self._scroll_job = None
        self.canvas.bind("<Configure>", lambda e: self._schedule_scroll())

    def _total(self):
        return sum(c["width"] for c in self.columns)

    def _build_header(self):
        for ch in list(self.header.children.values()): ch.destroy()
        self._hdr = []
        x = 0
        for i, c in enumerate(self.columns):
            lbl = tk.Label(self.header, text=c["label"], bg=HEADER_BG, fg="#9a9a9a",
                           font=("Segoe UI",8), anchor="w")
            lbl.place(x=x+6, y=0, width=max(1, c["width"]-6), height=26)
            sep = None
            if c.get("resizable"):
                sep = tk.Frame(self.header, bg="#333333", cursor="sb_h_double_arrow", width=6)
                sep.place(x=x+c["width"]-3, y=4, width=6, height=18)
                sep.bind("<ButtonPress-1>", lambda e, idx=i: self._start_drag(e, idx))
                sep.bind("<B1-Motion>", lambda e, idx=i: self._do_drag(e, idx))
                sep.bind("<Enter>", lambda e, s=sep: s.config(bg="#555555"))
                sep.bind("<Leave>", lambda e, s=sep: s.config(bg="#333333"))
            self._hdr.append((c, lbl, sep))
            x += c["width"]
        self.header.configure(width=self._total())

    def _start_drag(self, e, idx):
        self._dsx = e.x_root; self._dsw = self.columns[idx]["width"]

    def _do_drag(self, e, idx):
        dw = e.x_root - self._dsx
        self.columns[idx]["width"] = max(self.columns[idx]["minw"], self._dsw + dw)
        self._deferred_relayout()

    def _deferred_relayout(self):
        if self._relayout_job is not None:
            self.app.after_cancel(self._relayout_job)
        self._relayout_job = self.app.after(50, self._relayout)

    def _relayout(self):
        self._relayout_job = None
        self.body.configure(width=self._total())
        self.body.configure(height=max(1, len(self.rows) * 26))

        x = 0
        for c, lbl, sep in getattr(self, "_hdr", []):
            lbl.place(x=x+6, y=0, width=max(1, c["width"]-6), height=26)
            if sep is not None:
                sep.place(x=x+c["width"]-3, y=4, width=6, height=18)
            x += c["width"]
        for r in self.rows:
            self._position_row(r)
        msg_w = sum(c["width"] for c in self.columns if c["key"] == "message")
        if msg_w != self._last_msg_width:
            self._last_msg_width = msg_w
            for r in self.rows:
                self._fit_message(r)
        self._update_scrollbar()

    def _schedule_scroll(self):
        if self._scroll_job is not None:
            self.app.after_cancel(self._scroll_job)
        self._scroll_job = self.app.after(40, self._update_scrollbar)

    def _update_scrollbar(self):
        try:
            content_h = len(self.rows) * 26

            self.body.configure(height=content_h)
            view = self.canvas.winfo_height()
            self.canvas.configure(scrollregion=(0, 0, self._total(), content_h))
            if content_h > view + 1:
                if not self.sb.winfo_ismapped():
                    self.sb.pack(side="right", fill="y")
            else:

                self.canvas.yview_moveto(0.0)
                if self.sb.winfo_ismapped():
                    self.sb.pack_forget()
        except Exception:
            return

    def add_row(self, entry, past=False):
        frame = tk.Frame(self.body, bg=ROW_BG, height=26)
        frame.pack(fill="x")
        row = {"entry":entry,"frame":frame,"cells":{},"bgw":[frame],"icons":[],"selected":False}
        self.frame_map[id(frame)] = row
        sel = tk.Label(frame, text="☐", bg=ROW_BG, fg=TEXT, font=("Segoe UI",9), cursor="hand2")
        row["cells"]["sel"] = sel
        lf = tk.Frame(frame, bg=ROW_BG)
        color = LEVEL_COLORS.get(entry["level"], "#aaaaaa")
        dot = tk.Label(lf, text="●", bg=ROW_BG, fg=color, font=("Segoe UI",9))
        lt = tk.Label(lf, text=entry["level"], bg=ROW_BG, fg=TEXT, font=("Segoe UI",8,"bold"))
        dot.pack(side="left", padx=(2,3)); lt.pack(side="left")
        row["cells"]["level"] = lf
        row["bgw"] += [lf, dot, lt]
        cf = tk.Frame(frame, bg=ROW_BG)
        kind = CATEGORY_ICON.get(entry["category"], "folder")
        icon_photo = _cached_icon(kind)
        if icon_photo:
            ic = tk.Label(cf, image=icon_photo, bg=ROW_BG)
        else:
            ic = tk.Canvas(cf, width=16, height=16, bg=ROW_BG, highlightthickness=0)
            draw_icon(ic, kind, "#bdbdbd")
        ic.pack(side="left", padx=(2,4))
        cat = tk.Label(cf, text=entry["category"], bg=ROW_BG, fg="#cfcfcf", font=("Segoe UI",8))
        cat.pack(side="left")
        row["cells"]["category"] = cf
        row["bgw"] += [cf, ic]
        m = tk.Label(frame, text=entry["message"], bg=ROW_BG, fg=TEXT, font=("Segoe UI",8), anchor="w")
        row["cells"]["message"] = m; row["bgw"].append(m)
        def _on_row_double(e, r=row):
            cat = r["entry"].get("category", "")
            rp = r["entry"].get("reg_path")
            dd = r["entry"].get("drop_dir")
            if rp:
                self.app._open_regedit(rp)
            elif dd:
                self.app._open_folder(dd)
        frame.bind("<Double-1>", _on_row_double)
        m.bind("<Double-1>", _on_row_double)
        def _on_enter(e, r=row): self._show_tip(r, e)
        def _on_leave(e): self._hide_tip()
        frame.bind("<Enter>", _on_enter)
        frame.bind("<Leave>", _on_leave)
        vt = tk.Label(frame, text=entry.get("vt_status") or "–", bg=ROW_BG, fg=DIM, font=("Segoe UI",8))
        row["cells"]["vt"] = vt; row["bgw"].append(vt)

        exe_path = entry.get("exe_path")
        is_exe_process = (entry.get("category") == "Suspicious Processes"
                          and exe_path and os.path.isfile(exe_path))
        if is_exe_process:
            hb = tk.Button(frame, text="Check", bg="#222230", fg="#9a9ad0", font=("Segoe UI",7),
                           relief="flat", padx=4, command=lambda e=entry: self.app._vt_click(e))
            row["cells"]["hash"] = hb; row["bgw"].append(hb)
        else:
            hb = tk.Button(frame, text="Check", bg="#1b1b1f", fg="#4a4a4a", font=("Segoe UI",7),
                           relief="flat", padx=4, state="disabled", cursor="arrow")
            row["cells"]["hash"] = hb; row["bgw"].append(hb)
        if past:
            status = "dismissed" if entry.get("dismissed") else "auto-resolved"
            t = tk.Label(frame, text=f"✓ {status}", bg=ROW_BG, fg="#7fcf9a", font=("Segoe UI",8))
        else:
            t = tk.Label(frame, text=entry["time"], bg=ROW_BG, fg=DIM, font=("Segoe UI",8))
        row["cells"]["time"] = t; row["bgw"].append(t)
        def _on_row_click(e, r=row):
            self._toggle(r)

        row["cells"]["sel"].bind("<Button-1>", _on_row_click)
        for w in row["cells"].values():
            try:
                if isinstance(w, tk.Button):
                    continue
            except Exception:
                pass
        self.rows.append(row)
        self.row_by_id[entry["id"]] = row
        self._position_row(row)
        self._fit_message(row)
        self.body.configure(height=max(1, len(self.rows) * 26))
        self.app.after(0, self._update_scrollbar)
        parity = len(self.rows) % 2
        self._set_row_bg(row, ROW_ALT if parity else ROW_BG)

    def _position_row(self, row):
        x = 0
        for c in self.columns:
            widget = row["cells"].get(c["key"])
            if widget:
                widget.place(x=x, y=0, width=c["width"], height=26)
            x += c["width"]

    def _fit_message(self, row):
        w = next((c["width"] for c in self.columns if c["key"] == "message"), 380)
        maxc = max(4, (w - 12) // 6)
        msg = row["entry"]["message"]
        if len(msg) > maxc:
            row["cells"]["message"].config(text=msg[:maxc-1] + "…")
        else:
            row["cells"]["message"].config(text=msg)

    def _show_tip(self, row, e):
        self._hide_tip()
        entry = row["entry"]
        text = entry["message"]
        if entry.get("detail"):
            text = text + "\n\n" + entry["detail"]
        tl = tk.Toplevel(self.outer)
        tl.wm_overrideredirect(True)
        tl.wm_geometry(f"+{e.x_root+14}+{e.y_root+14}")
        tk.Label(tl, text=text, bg="#1e1e1e", fg="#e8e8e8", font=("Segoe UI",8),
                 justify="left", padx=8, pady=6, wraplength=440).pack()
        self._tip = tl

    def _hide_tip(self):
        tl = getattr(self, "_tip", None)
        if tl:
            try: tl.destroy()
            except Exception: pass
            self._tip = None

    def _set_row_bg(self, row, color):
        for w in row["bgw"]:
            try:
                if isinstance(w, tk.Canvas):
                    w.config(bg=color)
                else:
                    w.config(bg=color)
            except Exception:
                pass

    def _toggle(self, row):
        self._set_selected(row, not row["selected"])
        self.app._on_selection_changed()

    def _set_selected(self, row, val):
        row["selected"] = val
        row["cells"]["sel"].config(text="☑" if val else "☐")
        parity = (self.rows.index(row) % 2)
        color = SELECT_BG if val else (ROW_ALT if parity else ROW_BG)
        self._set_row_bg(row, color)

    def select_all(self, val):
        for r in self.rows:
            self._set_selected(r, val)

    def get_selected(self):
        return [r["entry"] for r in self.rows if r["selected"]]

    def remove_row(self, entry):
        r = self.row_by_id.pop(entry["id"], None)
        if not r: return
        r["frame"].destroy()
        if r in self.rows: self.rows.remove(r)
        self.frame_map.pop(id(r["frame"]), None)
        self.body.configure(height=max(1, len(self.rows) * 26))
        self.app.after(0, self._update_scrollbar)

    def update_vt(self, entry):
        r = self.row_by_id.get(entry["id"])
        if r:
            r["cells"]["vt"].config(text=(entry.get("vt") or "–")[:40])

def _dark_titlebar(win):

    if sys.platform != "win32":
        return
    try:
        import ctypes
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi
        hwnd = int(win.winfo_id())

        try:
            root = user32.GetAncestor(hwnd, 2)
            if root: hwnd = root
        except Exception:
            pass

        try:
            uxtheme = ctypes.windll.uxtheme
            if hasattr(uxtheme, "SetPreferredAppMode"):
                uxtheme.SetPreferredAppMode(2)
            if hasattr(uxtheme, "AllowDarkModeForWindow"):
                uxtheme.AllowDarkModeForWindow(hwnd, True)
        except Exception:
            pass
        val = ctypes.c_int(1)
        for attr in (20, 19):
            try:
                dwmapi.DwmSetWindowAttribute(hwnd, attr,
                                             ctypes.byref(val), ctypes.sizeof(val))
            except Exception:
                pass
    except Exception:
        pass


class DetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("notyours")
        self.geometry("1060x720")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._apply_dark_titlebar()
        self.bind("<Map>", lambda e: self._apply_dark_titlebar())

        self.alert_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"INFO":0}
        self.past_counts  = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"INFO":0}
        self.showing_past = False
        self.stat_cards   = {}
        self.monitor_vars = {k: tk.BooleanVar(value=MONITOR_ENABLED[k]) for k in MONITOR_ENABLED}
        self.notif_var = tk.BooleanVar(value=NOTIFICATIONS_ENABLED)
        self._cog_anim    = None
        self._settings_win = None
        self.logo_img = load_logo(34)
        if self.logo_img:
            try: self.iconphoto(True, self.logo_img)
            except Exception: pass

        self._build_ui()
        engine.alert_callback = self._on_alert_event

        self.tray_icon     = None
        self._in_tray      = False
        self._notif_times  = []
        self._spam_notified = False
        self._setup_tray()
        self.protocol("WM_DELETE_WINDOW", self._hide_to_tray)
        self.bind("<Unmap>", self._on_unmap)

    def _apply_dark_titlebar(self):
        _dark_titlebar(self)

    def _setup_tray(self):
        try:
            if os.path.exists(LOGO_PATH):
                img = Image.open(LOGO_PATH).convert("RGBA").resize((64, 64), Image.LANCZOS)
            else:
                img = Image.new("RGBA", (64, 64), (61, 220, 132, 255))
            menu = pystray.Menu(
                pystray.MenuItem("Show", lambda: self.after(0, self._restore)),
                pystray.MenuItem("Exit", lambda: self.after(0, self._quit)),
            )
            self.tray_icon = pystray.Icon(
                "notyours", img, "notyours", menu
            )
            self.tray_icon.on_click = lambda icon, event: self.after(0, self._restore)
            self.tray_icon._balloon_callback = lambda: self.after(0, self._restore)
            self.tray_icon.run_detached()
        except Exception:
            self.tray_icon = None

    def _on_unmap(self, event):
        if not self._in_tray and self.state() == "iconic":
            self._hide_to_tray()

    def _hide_to_tray(self):
        self._in_tray = True
        self.withdraw()

    def _restore(self):
        self._in_tray = False
        self.deiconify()
        self.lift()
        self._apply_dark_titlebar()

    def _quit(self):
        for obs in getattr(self, "observers", []):
            try:
                obs.stop()
            except Exception:
                pass
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.destroy()

    def _open_regedit(self, key_path):

        try:
            try:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit") as k:
                    winreg.SetValueEx(k, "LastKey", 0, winreg.REG_SZ, key_path)
            except Exception:
                pass
            params = (r'/c taskkill /f /im regedit.exe >nul 2>&1'
                      r' & timeout /t 1 /nobreak >nul & regedit.exe')
            shell32 = ctypes.windll.shell32
            shell32.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                             ctypes.c_wchar_p, ctypes.c_wchar_p,
                                             ctypes.c_wchar_p, ctypes.c_int]
            shell32.ShellExecuteW.restype = ctypes.c_int
            r = shell32.ShellExecuteW(0, "runas", "cmd.exe", params, None, 1)
            if r <= 32:

                subprocess.Popen(["regedit.exe"], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass

    def _open_folder(self, folder_path):
        try:
            shell32 = ctypes.windll.shell32
            shell32.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                             ctypes.c_wchar_p, ctypes.c_wchar_p,
                                             ctypes.c_wchar_p, ctypes.c_int]
            shell32.ShellExecuteW.restype = ctypes.c_int
            shell32.ShellExecuteW(0, "open", folder_path, None, None, 1)
        except Exception:
            pass

    def _notify(self, entry):
        if not engine.NOTIFICATIONS_ENABLED:
            return
        if entry.get("level") == "INFO":
            return
        if self.tray_icon is None:
            return
        now = time.time()
        self._notif_times = [t for t in self._notif_times if now - t < 60]
        if len(self._notif_times) < 5:
            self._notif_times.append(now)
            self._spam_notified = False
            try:
                self.tray_icon.notify(
                    f"{entry['level']} · {entry['category']}: {entry['message']}",
                    "notyours alert",
                )
            except Exception:
                pass
        else:
            if not self._spam_notified:
                self._spam_notified = True
                try:
                    self.tray_icon.notify(
                        "You have many alerts — open the app to review.",
                        "notyours",
                    )
                except Exception:
                    pass
        if not self._notif_times:
            self._spam_notified = False

    def _build_ui(self):

        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=20, pady=(14,0))
        if self.logo_img:
            tk.Label(hdr, image=self.logo_img, bg=BG).pack(side="left", padx=(0,8))
        tk.Label(hdr, text="notyours", font=("Segoe UI",18,"bold"),
                 fg=TEXT, bg=BG).pack(side="left")
        tk.Label(hdr, text="  Session Stealer Detector", font=("Segoe UI",10),
                 fg=DIM, bg=BG).pack(side="left", pady=(3,0))
        self._all_monitoring = True
        self.status_dot = tk.Label(hdr, text="● MONITORING", font=("Segoe UI",9,"bold"),
                                   fg=GREEN, bg=BG, cursor="hand2")
        self.status_dot.pack(side="right")
        self.status_dot.bind("<Button-1>", lambda e: self._toggle_all_monitors())
        self.cog_canvas = tk.Canvas(hdr, width=16, height=16, bg=BG,
                                    highlightthickness=0, cursor="hand2")
        draw_icon(self.cog_canvas, "gear", "#9a9a9a")
        self.cog_canvas.pack(side="right", padx=(10,0))
        self.cog_canvas.bind("<Button-1>", lambda e: self._open_settings())

        cards = tk.Frame(self, bg=BG)
        cards.pack(fill="x", padx=20, pady=12)
        for lvl, color in [("CRITICAL","#e8503a"),("HIGH","#f5a623"),("MEDIUM","#f0c040")]:
            c = self._make_stat_card(cards, lvl, color)
            c.pack(side="left", padx=(0,14), fill="x", expand=True)

        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=20, pady=(8,0))
        self.tab_active_btn = tk.Button(top, text="Active Alerts",
            command=lambda: self._switch_tab(False), bg="#1e1e1e", fg=TEXT,
            relief="flat", font=("Segoe UI",9,"bold"), padx=14, pady=5)
        self.tab_active_btn.pack(side="left")
        self.tab_past_btn = tk.Button(top, text="Past Alerts",
            command=lambda: self._switch_tab(True), bg="#161616", fg=DIM,
            relief="flat", font=("Segoe UI",9), padx=14, pady=5)
        self.tab_past_btn.pack(side="left")

        self.select_all_var = tk.BooleanVar(value=False)
        self.select_all_cb = tk.Checkbutton(top, text="Select All", variable=self.select_all_var,
                                            command=self._toggle_select_all, bg=BG, fg=DIM,
                                            selectcolor="#1a1a1e", activebackground=BG,
                                            font=("Segoe UI",8))
        self.select_all_cb.pack(side="right", padx=(0,8))
        self.dismiss_btn = tk.Button(top, text="Dismiss Selected", command=self._dismiss_selected,
            bg="#1e1e1e", fg="#cfcfcf", relief="flat", font=("Segoe UI",8),
            padx=10, pady=4, state="disabled")
        self.dismiss_btn.pack(side="right", padx=(0,6))

        self._table_container = tk.Frame(self, bg=BG)
        self._table_container.pack(fill="both", expand=True, padx=20, pady=(6,0))

        self.active_table = AlertTable(self._table_container, self, ACTIVE_COLUMNS)
        self.past_table   = AlertTable(self._table_container, self, ACTIVE_COLUMNS)
        self.active_table.outer.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.past_table.outer.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.active_table.outer.lift()

        bar = tk.Frame(self, bg="#161616", pady=6)
        bar.pack(fill="x", side="bottom")
        tk.Button(bar, text="↑ Export Alerts", command=self._export, bg="#1e1e1e",
                  fg="#cfcfcf", relief="flat", font=("Segoe UI",8), padx=12).pack(side="left", padx=14)
        vtf = tk.Frame(bar, bg="#1e1e1e", highlightbackground="#333333", highlightthickness=1)
        vtf.pack(side="left", padx=10)
        vc = tk.Canvas(vtf, width=14, height=14, bg="#1e1e1e", highlightthickness=0)
        draw_icon(vc, "gear", "#8a8a8a"); vc.pack(side="left", padx=(4,0))
        self.vt_entry = tk.Entry(vtf, bg="#1e1e1e", fg="#8a8a8a", relief="flat",
                                 insertbackground="#cfcfcf", font=("Segoe UI",8), width=16,
                                 highlightthickness=0, bd=0)
        self.vt_entry.insert(0, VT_API_KEY if VT_API_KEY else "VT API Key")
        self.vt_entry.pack(side="left", padx=(2,6), ipady=3)
        self.vt_entry.bind("<FocusIn>", self._vt_focus_in)
        self.vt_entry.bind("<FocusOut>", self._vt_focus_out)
        self.vt_entry.bind("<Return>", self._vt_save)
        self.vt_status = tk.Label(bar, text="", font=("Segoe UI",8), bg="#161616", fg=DIM)
        self.vt_status.pack(side="left", padx=(2,10))
        self.whitelist_var = tk.BooleanVar(value=WHITELIST_BUILTIN_TASKS)
        tk.Checkbutton(bar, text="Whitelist Built-in Tasks", variable=self.whitelist_var,
                       command=self._toggle_whitelist, bg="#161616", fg="#cfcfcf",
                       selectcolor="#1a1a1e", activebackground="#161616",
                       font=("Segoe UI",8)).pack(side="right", padx=14)
        self.sel_count_lbl = tk.Label(bar, text="", font=("Segoe UI",8), fg=DIM, bg="#161616")
        self.sel_count_lbl.pack(side="right", padx=14)

        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-1>", self._clear_api_selection)

    def _make_stat_card(self, parent, level, color):
        card = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER, highlightthickness=1)
        tk.Label(card, text=level, fg=color, bg=CARD_BG, font=("Segoe UI",10,"bold")).pack(pady=(14,2))
        active = tk.Label(card, text="0", fg=color, bg=CARD_BG, font=("Segoe UI",30,"bold"))
        active.pack()
        tk.Label(card, text="ACTIVE ALERTS", fg=DIM2, bg=CARD_BG, font=("Segoe UI",7)).pack()
        past = tk.Label(card, text="PAST 0", fg=DIM, bg=CARD_BG, font=("Segoe UI",8))
        past.pack(pady=(8,14))
        self.stat_cards[level] = (active, past)
        return card

    def _refresh_cards(self):
        for lvl in ("CRITICAL","HIGH","MEDIUM"):
            act, past = self.stat_cards[lvl]
            act.config(text=str(self.alert_counts.get(lvl,0)))
            past.config(text="PAST " + str(self.past_counts.get(lvl,0)))

    def _open_settings(self):
        self._spin_cog()
        if getattr(self, "_settings_win", None) and self._settings_win.winfo_exists():
            self._settings_win.lift()
            return
        win = tk.Toplevel(self)
        win.title("Settings")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self)
        _dark_titlebar(win)
        win.bind("<Map>", lambda e: _dark_titlebar(win))
        self._settings_win = win
        tk.Label(win, text="Monitoring Categories", bg=BG, fg=TEXT,
                 font=("Segoe UI",11,"bold")).pack(padx=16, pady=(14,4))
        for key, label in MONITOR_CATEGORIES:
            tk.Checkbutton(win, text=label, variable=self.monitor_vars[key],
                           command=lambda k=key: self._set_monitor(k),
                           bg=BG, fg=DIM, selectcolor=CARD_BG, activebackground=BG,
                           activeforeground=TEXT, font=("Segoe UI",9)).pack(anchor="w", padx=16, pady=3)
        tk.Label(win, text="Disable a category to stop its alerts.",
                 bg=BG, fg=DIM2, font=("Segoe UI",8)).pack(padx=16, pady=(8,14))
        tk.Label(win, text="Notifications", bg=BG, fg=TEXT,
                 font=("Segoe UI",11,"bold")).pack(padx=16, pady=(4,2))
        tk.Checkbutton(win, text="Show tray notifications on alert",
                       variable=self.notif_var,
                       command=self._set_notifications,
                       bg=BG, fg=DIM, selectcolor=CARD_BG, activebackground=BG,
                       activeforeground=TEXT, font=("Segoe UI",9)).pack(anchor="w", padx=16, pady=3)
        def _on_settings_close():
            if self._cog_anim is not None:
                try: self.after_cancel(self._cog_anim)
                except Exception: pass
                self._cog_anim = None
            draw_icon(self.cog_canvas, "gear", "#9a9a9a", 0)
            win.destroy()
            self._settings_win = None
        win.protocol("WM_DELETE_WINDOW", _on_settings_close)

    def _set_monitor(self, key):
        MONITOR_ENABLED[key] = self.monitor_vars[key].get()
        save_config()

    def _set_notifications(self):
        engine.NOTIFICATIONS_ENABLED = self.notif_var.get()
        save_config()

    def _spin_cog(self, angle=0):
        if self._cog_anim is not None:
            try: self.after_cancel(self._cog_anim)
            except Exception: pass
            self._cog_anim = None
        draw_icon(self.cog_canvas, "gear", "#9a9a9a", angle)
        if angle < 360:
            self._cog_anim = self.after(40, self._spin_cog, angle + 20)
        else:
            self._cog_anim = None
            draw_icon(self.cog_canvas, "gear", "#9a9a9a", 0)

    def _vt_focus_in(self, e):
        if self.vt_entry.get() == "VT API Key":
            self.vt_entry.delete(0,"end"); self.vt_entry.config(fg="#cfcfcf")

    def _clear_api_selection(self, e):

        w = e.widget
        try:
            if w is self.vt_entry or str(w).startswith(str(self.vt_entry) + "."):
                return
        except Exception:
            pass
        self.vt_entry.selection_clear()
        try: self.vt_entry.icursor("end")
        except Exception: pass
    def _vt_focus_out(self, e):
        self.vt_entry.selection_clear()
        self.vt_entry.icursor("end")
        if not self.vt_entry.get().strip():
            self.vt_entry.insert(0,"VT API Key"); self.vt_entry.config(fg="#8a8a8a")
            self.vt_status.config(text="", fg=DIM)
        else:
            self._vt_commit()

    def _vt_commit(self):
        global VT_API_KEY
        VT_API_KEY = self.vt_entry.get().strip()
        save_config()

    def _vt_save(self, e):

        self._vt_commit()
        if VT_API_KEY:
            self.vt_status.config(text="checking…", fg=DIM)
            def cb(res):
                ok, msg = res
                color = "#3ddc84" if ok else ("#e8503a" if ok is False else DIM)
                self.after(0, lambda: self.vt_status.config(text=msg, fg=color))
            validate_vt_key(VT_API_KEY, cb)
        else:
            self.vt_status.config(text="", fg=DIM)

    def _current_table(self):
        return self.past_table if self.showing_past else self.active_table

    def _on_wheel(self, event):
        self._current_table().canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"

    def _toggle_all_monitors(self):
        """Master kill switch — pauses or resumes ALL monitors at once."""
        self._all_monitoring = not self._all_monitoring
        for key in MONITOR_ENABLED:
            MONITOR_ENABLED[key] = self._all_monitoring
        for key, var in self.monitor_vars.items():
            var.set(self._all_monitoring)
        save_config()
        if self._all_monitoring:
            self.status_dot.config(text="● MONITORING", fg=GREEN)
        else:
            self.status_dot.config(text="○ PAUSED", fg="#e8503a")

    def _switch_tab(self, show_past):
        self.showing_past = show_past
        if show_past:
            self.past_table.outer.lift()
            self.tab_active_btn.config(bg="#161616", fg=DIM, font=("Segoe UI",9))
            self.tab_past_btn.config(bg="#1e1e1e", fg=TEXT, font=("Segoe UI",9,"bold"))
        else:
            self.active_table.outer.lift()
            self.tab_active_btn.config(bg="#1e1e1e", fg=TEXT, font=("Segoe UI",9,"bold"))
            self.tab_past_btn.config(bg="#161616", fg=DIM, font=("Segoe UI",9))
        self._update_toolbar()

    def _on_selection_changed(self):
        self._update_toolbar()

    def _update_toolbar(self):
        t = self._current_table()
        count = len(t.get_selected())
        self.sel_count_lbl.config(text=f"{count} selected" if count else "")
        self.dismiss_btn.config(state="normal" if (count and not self.showing_past) else "disabled")
        self.select_all_var.set(count == len(t.rows) and count > 0)

    def _toggle_select_all(self):
        self._current_table().select_all(self.select_all_var.get())
        self._update_toolbar()

    def _dismiss_selected(self):
        if self.showing_past:
            return
        t = self.active_table
        for entry in list(t.get_selected()):
            entry["resolved"] = True
            entry["resolved_time"] = datetime.datetime.now().strftime("%H:%M:%S")
            entry["dismissed"] = True
            past_alerts.append(entry)
            lvl = entry["level"]
            self.alert_counts[lvl] = max(0, self.alert_counts.get(lvl,0)-1)
            self.past_counts[lvl]  = self.past_counts.get(lvl,0)+1
            t.remove_row(entry)
            self.past_table.add_row(entry, past=True)
        self._refresh_cards()
        self._update_toolbar()
        self.select_all_var.set(False)

    def _vt_click(self, entry):
        if entry["category"] == "Registry Run Key":
            val = entry.get("run_value")
            if not val:
                entry["vt"] = "no data"; entry["vt_status"] = "no data"
                self._refresh_row_vt(entry); return
            verdict, rep = check_run_entry(val)
            label = VERDICT_LABEL[verdict]
            entry["vt"] = label
            entry["vt_status"] = label
            entry["detail"] = (entry.get("detail","").split("\n[Reputation]")[0]
                                 + f"\n[Reputation] {rep}")
            self._refresh_row_vt(entry)
            return
        sha = entry.get("hash")
        if not sha:
            entry["vt"] = "no hash"; self._refresh_row_vt(entry); return
        if not VT_API_KEY:
            entry["vt"] = "no key"; self._refresh_row_vt(entry); return
        entry["vt"] = "checking…"; self._refresh_row_vt(entry)
        def cb(result):
            self.after(0, self._refresh_row_vt, entry, result)
        vt_lookup(sha, cb)

    def _refresh_row_vt(self, entry, result=None):
        if result is not None:
            entry["vt"] = result
        self.active_table.update_vt(entry)
        self.past_table.update_vt(entry)

    def _on_alert_event(self, event_type, entry):
        self.after(0, lambda: self._handle_alert(event_type, entry))

    def _handle_alert(self, event_type, entry):
        _log_alert_entry(event_type, entry)
        level = entry["level"]
        if event_type == "new":
            self.alert_counts[level] = self.alert_counts.get(level, 0) + 1
            self.active_table.add_row(entry)
            self._refresh_cards()
            self._update_toolbar()
            self._notify(entry)
        elif event_type == "resolved":
            in_active = entry["id"] in self.active_table.row_by_id
            in_past   = entry["id"] in self.past_table.row_by_id
            if in_active:
                self.alert_counts[level] = max(0, self.alert_counts.get(level, 0) - 1)
                self.past_counts[level]  = self.past_counts.get(level, 0) + 1
                self.active_table.remove_row(entry)
                if not in_past:
                    self.past_table.add_row(entry, past=True)
                self._refresh_cards()
                self._update_toolbar()

    def _toggle_whitelist(self):
        global WHITELIST_BUILTIN_TASKS
        WHITELIST_BUILTIN_TASKS = self.whitelist_var.get()
        save_config()
        if WHITELIST_BUILTIN_TASKS:

            builtin_entries = [
                e for e in list(active_alerts.values())
                if e["category"] == "Scheduled Task" and e["level"] == "INFO"
            ]
            for entry in builtin_entries:

                resolve_alert("Scheduled Task", entry["message"])

    def _export(self):
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        exports_dir = os.path.join(base, "exports")
        os.makedirs(exports_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        active_path = os.path.join(exports_dir, f"ACTIVE_{ts}.json")
        past_path   = os.path.join(exports_dir, f"PAST_{ts}.json")
        with open(active_path, "w") as f:
            json.dump(list(active_alerts.values()), f, indent=2)
        with open(past_path, "w") as f:
            json.dump(past_alerts, f, indent=2)
        messagebox.showinfo("Exported",
            f"Saved to:\n{active_path}\n{past_path}")

    def start_monitors(self):
        _log_session_start("GUI")
        self.observers = start_file_watchers()
        start_wmi_process_monitor()
        start_registry_monitors()
        threading.Thread(target=_open_files_checker, daemon=True).start()
        threading.Thread(target=self_defense, daemon=True).start()
        for fn in [wmi_monitor, task_monitor, dns_monitor]:
            threading.Thread(target=fn, daemon=True).start()
        threading.Thread(target=clipboard_monitor, args=(self,), daemon=True).start()

    def on_close(self):
        self._quit()


_SERVICE_STOP = threading.Event()
_SESSION_ID = os.urandom(4).hex()
_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notyours.log")

_LOGO = r"""
                                    
                                    
         .......................     
       ..........................    
     .............................   
    ......=-........................
    :....-  :......................::
    :...:   -.....................:::
    :...-    :...................::::
    :..:     =..................:::::
    :..=      -................::::::
    :.-        :..............:::::::
    ::         -.............::::::::
    ==          ================-::::
                              ..:::::
                            ..::::::-
                         ..:::::::::=
                      ...::::::::::=
                    ...::::::::::==
                   =============
                                    
                                    
"""

def _log_session_start(mode):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[new session] {ts} [{_SESSION_ID}] - {mode}"
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def _log_alert_entry(event_type, entry):
    ts = entry["time"]
    line = f"[{ts}] [{_SESSION_ID}] [{entry['level']}] {entry['category']}: {entry['message']}"
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def _headless_callback(event_type, entry):
    _log_alert_entry(event_type, entry)
    ts = entry["time"]
    line = f"[{ts}] [{_SESSION_ID}] [{entry['level']}] {entry['category']}: {entry['message']}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, 0, (line, ""))
    except Exception:
        pass

def run_headless(mode="headless (service)"):
    """Start all monitors without Tkinter GUI. Blocks until stop signal."""
    _log_session_start(mode)
    try:
        print(_LOGO)
    except Exception:
        pass
    print(f"notyours - session stealer detector ({mode})")
    print(f"Session: {_SESSION_ID}")
    print(f"Logging to: {_LOG_PATH}")
    print("-" * 50)
    print()
    engine.alert_callback = _headless_callback
    observers = start_file_watchers()
    start_wmi_process_monitor()
    start_registry_monitors()
    threading.Thread(target=_open_files_checker, daemon=True).start()
    threading.Thread(target=self_defense, daemon=True).start()
    for fn in [wmi_monitor, task_monitor, dns_monitor]:
        threading.Thread(target=fn, daemon=True).start()
    threading.Thread(target=clipboard_monitor, args=(None,), daemon=True).start()
    print("Monitoring started. Press Ctrl+C to stop.\n")
    try:
        _SERVICE_STOP.wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
        _SERVICE_STOP.set()
    for obs in observers:
        try: obs.stop()
        except Exception: pass
    for obs in observers:
        try: obs.join()
        except Exception: pass
    print("Stopped.")


if HAS_SERVICE:
    class NotYoursService(win32serviceutil.ServiceFramework):
        _svc_name_ = "NotYoursEDR"
        _svc_display_name_ = "NotYours EDR Service"
        _svc_description_ = "Event-driven endpoint detection & response with risk scoring and active response."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._hWaitStop = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._hWaitStop)
            _SERVICE_STOP.set()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            try:
                run_headless()
            except Exception as exc:
                servicemanager.LogErrorMsg(str(exc))
                raise

if __name__ == "__main__":
    if HAS_SERVICE and len(sys.argv) > 1 and sys.argv[1] in ("install", "start", "stop", "remove", "restart", "debug"):
        win32serviceutil.HandleCommandLine(NotYoursService)
    elif len(sys.argv) > 1 and sys.argv[1] == "cli":
        run_headless(mode="CLI")
    else:
        app = DetectorApp()
        app.start_monitors()
        app.mainloop()

