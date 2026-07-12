import os
import sys
import time
import json
import re
import hashlib
import psutil
import datetime
import threading
import subprocess

# Suppress the console window spawned by the powershell subprocess calls below
# (Windows-only; falls back to 0 on other platforms).
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
import ctypes
import shutil
import tempfile
import winreg
import urllib.request
import urllib.error
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image

# pystray forwards tray-icon clicks to on_click, but never reports clicks on the
# notification balloon. Patch _on_notify so a balloon click also fires a callback.
# NIN_BALLOONUSERCLICK == WM_USER + 5 (stable Win32 value).
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

# ─── CONFIG ───────────────────────────────────────────────────────────────────

BROWSER_PROFILE_PATHS = {
    "Chrome":  Path(os.environ.get("LOCALAPPDATA","")) / "Google/Chrome/User Data/Default",
    "Brave":   Path(os.environ.get("LOCALAPPDATA","")) / "BraveSoftware/Brave-Browser/User Data/Default",
    "Edge":    Path(os.environ.get("LOCALAPPDATA","")) / "Microsoft/Edge/User Data/Default",
    "Firefox": Path(os.environ.get("APPDATA",""))      / "Mozilla/Firefox/Profiles",
}
SENSITIVE_FILES = ["Cookies","Login Data","Web Data","Local State","sessions.sqlite","key4.db","logins.json"]
TRUSTED_BROWSER_EXES = {"chrome.exe","brave.exe","msedge.exe","firefox.exe"}
SUSPICIOUS_OUTBOUND_PROCESSES = {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe"}
WMI_POLL_INTERVAL  = 30
TASK_POLL_INTERVAL = 60

# ── NEW MONITORS: persistence / staging / anomaly ──────────────────────────
REG_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, "HKCU",
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, "HKCU",
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, "HKCU",
     r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_CURRENT_USER, "HKCU",
     r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
]
REG_ROOT_NAMES = {
    "HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE",
    "HKU": "HKEY_USERS", "HKCR": "HKEY_CLASSES_ROOT",
    "HKCC": "HKEY_CURRENT_CONFIG",
}
DEFENDER_EXCL_KEY = (winreg.HKEY_LOCAL_MACHINE, "HKLM",
                      r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")

def _startup_folders():
    dirs = []
    ap = os.environ.get("APPDATA")
    if ap:
        dirs.append(os.path.join(ap, "Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
    pd = os.environ.get("PROGRAMDATA")
    if pd:
        dirs.append(os.path.join(pd, "Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
    return [d for d in dirs if os.path.isdir(d)]

STARTUP_FOLDERS = _startup_folders()
ARCHIVE_EXTS   = {".zip", ".rar", ".7z"}
ARCHIVER_EXES  = {"winrar.exe", "rar.exe", "7z.exe", "7za.exe", "7zr.exe",
                    "winzip.exe", "peazip.exe", "bandizip.exe", "izarc.exe"}
TEMP_WATCH_DIRS = [d for d in [
    tempfile.gettempdir(),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
] if d and os.path.isdir(d)]

REG_POLL_INTERVAL    = 30
DEFENDER_POLL_INTERVAL = 30
DNS_POLL_INTERVAL    = 30
DNS_SPIKE_MIN    = 15    # absolute floor before a spike can fire
DNS_SPIKE_FACTOR = 2.5   # current >= baseline * factor => spike

# ── PowerShell-spawn heuristic (#6) ───────────────────────────────────────
# Parents that should NEVER spawn PowerShell. Covers the fake-CAPTCHA /
# macro-delivery chain (Office / browser / mshta spawning powershell).
PSPAWN_SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
    "iexplore.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "wmiprvse.exe", "rundll32.exe", "regsvr32.exe", "acrord32.exe",
    "foxitreader.exe", "javaw.exe", "python.exe", "pythonw.exe",
    "node.exe", "hh.exe", "certutil.exe",
}

# ── Browser extension directories (#8) ───────────────────────────────────────
def _extension_dirs():
    dirs = []
    la = os.environ.get("LOCALAPPDATA")
    if la:
        for sub in [
            r"Google\Chrome\User Data\Default\Extensions",
            r"Microsoft\Edge\User Data\Default\Extensions",
            r"Google\Chrome Beta\User Data\Default\Extensions",
            r"Google\Chrome Dev\User Data\Default\Extensions",
        ]:
            d = os.path.join(la, sub)
            if os.path.isdir(d):
                dirs.append(d)
    return dirs
EXTENSION_DIRS = _extension_dirs()

# ── Executable-drop heuristic (#9) ──────────────────────────────────────────
DROP_EXTS = {".exe", ".dll", ".bat", ".vbs", ".ps1", ".js", ".jse",
             ".scr", ".com", ".cmd"}
DROP_WATCH_DIRS = []
for d in list(TEMP_WATCH_DIRS) + [
    os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")]:
    if d and os.path.isdir(d) and d.lower() not in [x.lower() for x in DROP_WATCH_DIRS]:
        DROP_WATCH_DIRS.append(d)
INSTALLER_EXES = {"setup.exe", "install.exe", "uninst.exe", "msiexec.exe",
                    "nsis.exe", "innoextract.exe", "spoon.exe"} | ARCHIVER_EXES

# ── TypeLib hijack (#10) ────────────────────────────────────────────────
TYPELIB_KEY = (winreg.HKEY_CURRENT_USER, "HKCU",
                 r"Software\Classes\TypeLib")

# ── Integrity baseline (#7) ───────────────────────────────────────────────
BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
if getattr(sys, "frozen", False):
    BASELINE_PATH = os.path.join(os.path.dirname(sys.executable), "baseline.json")

# ── Crypto-wallet access (#11) ────────────────────────────────
# watchdog can only see create/modify/delete, not reads; so watch reads via
# psutil open_files() for non-browser processes touching wallet files.
# Matching is kept tight: an EXACT wallet filename, or a file inside a known
# wallet DIRECTORY. Generic substrings ("vault", "seed", "key") were removed
# because unrelated apps (Adobe CC "vault", GitHub, Steam) triggered them.
WALLET_FILES = {"wallet.dat", "wallet.json", "wallet.wallet", ".wallet",
                 "wallet_keys.json", "mnemonic.txt", "seed.txt", "keystore"}
WALLET_DIRS = ("bitcoin", "litecoin", "dogecoin", "dash", "monero", "zcash",
                "electrum", "exodus", "atomic wallet", "guarda", "jaxx",
                "coinomi", "wasabi", "samourai", "multibit", "armory",
                "ethereum", "keystore", "ledger live",
                "trezor", "crypto wallets", "crypto-wallets")
# Narrow path-substring markers (MetaMask's dir is a hash ID, so match by name/id).
WALLET_PATH_INCLUDES = ("metamask",
                          "nkbihfbeogaeaoehlefnkodbefgpgknn",
                          "localextensionsettings")
WALLET_BENIGN = {"chrome.exe","msedge.exe","firefox.exe","brave.exe",
                  "opera.exe","electron.exe","msiexec.exe","explorer.exe",
                  "dllhost.exe","svchost.exe","searchui.exe",
                  "shellexperiencehost.exe","runtimebroker.exe",
                  "applicationframehost.exe","onedrive.exe","dropbox.exe",
                  "discord.exe"}
WALLET_OPEN_POLL = 15

def _is_wallet_path(path):
    low = path.lower()
    if os.path.basename(low) in WALLET_FILES:
        return True
    parts = [p.lower() for p in Path(low).parts]
    if any(d in parts for d in WALLET_DIRS):
        return True
    return any(s in low for s in WALLET_PATH_INCLUDES)

# ── Screenshot-capture (#12) ──────────────────────────────────
SCREEN_EXTS = {".png",".bmp",".jpg",".jpeg",".gif",".tif",".tiff"}
SCREEN_TOOLS = {"snippingtool.exe","sharex.exe","greenshot.exe","snagit.exe",
                "lightshot.exe","picpick.exe","screenpresso.exe","obs.exe",
                "obs64.exe","onedrive.exe","dropbox.exe","discord.exe"}
SCREEN_MIN_BYTES = 15000

# ── AV / security-tool kill (#13) ─────────────────────────────
# Self-termination of notyours cannot be caught post-mortem (the process is
# already dead); instead we watch security/analysis tools vanishing.
AV_TOOLS = {"avastui.exe","avastsvc.exe","afwserv.exe","wireshark.exe",
            "ngui.exe","mbam.exe","mbamservice.exe","msmpeng.exe","msmpsvc.exe",
            "nortonsecurity.exe","mcshield.exe","bdagent.exe","kaspersky.exe",
            "f-secure.exe","ekrn.exe","avgui.exe","sophosui.exe","defender.exe",
            "securityhealthsystray.exe"}
AV_POLL = 10

# User-toggleable: when True, known Windows built-in scheduled tasks are suppressed.
WHITELIST_BUILTIN_TASKS = True

# Per-category monitoring switches (toggleable from the settings cog).
MONITOR_ENABLED = {"browser": True, "wmi": True, "tasks": True,
                   "process": True, "clipboard": True,
                   "registry": True, "startup": True, "defender": True,
                   "archive": True, "dns": True,
                   "pspawn": True, "integrity": True, "extension": True,
                   "drop": True, "typelib": True,
                   "wallet": True, "screenshot": True, "avkill": True}
MONITOR_CATEGORIES = [
    ("browser",   "Browser Profiles"),
    ("wmi",       "WMI Subscriptions"),
    ("tasks",     "Scheduled Tasks"),
    ("process",   "Suspicious Processes"),
    ("clipboard", "Clipboard"),
    ("registry",  "Registry Run Keys"),
    ("startup",   "Startup Folder"),
    ("defender",  "Defender Exclusions"),
    ("archive",   "Archive Staging"),
    ("dns",       "DNS Anomaly"),
    ("pspawn",    "PowerShell Spawn"),
    ("integrity", "Run/Startup Integrity"),
    ("extension",  "Browser Extension"),
    ("drop",      "Executable Drop"),
    ("typelib",  "TypeLib Hijack"),
    ("wallet",   "Crypto Wallet"),
    ("screenshot", "Screenshot Capture"),
    ("avkill",   "AV Kill Attempt"),
]

# VirusTotal API key (user can set this)
VT_API_KEY = ""

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
if getattr(sys, "frozen", False):
    CONFIG_PATH = os.path.join(os.path.dirname(sys.executable), "config.json")

def load_config():
    global VT_API_KEY, WHITELIST_BUILTIN_TASKS, MONITOR_ENABLED
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if cfg.get("vt_api_key"):
            VT_API_KEY = cfg["vt_api_key"]
        if "whitelist_builtin_tasks" in cfg:
            WHITELIST_BUILTIN_TASKS = bool(cfg["whitelist_builtin_tasks"])
        if "monitor_enabled" in cfg and isinstance(cfg["monitor_enabled"], dict):
            for k in MONITOR_ENABLED:
                if k in cfg["monitor_enabled"]:
                    MONITOR_ENABLED[k] = bool(cfg["monitor_enabled"][k])
    except Exception:
        pass

def save_config():
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({"vt_api_key": VT_API_KEY,
                       "whitelist_builtin_tasks": WHITELIST_BUILTIN_TASKS,
                       "monitor_enabled": dict(MONITOR_ENABLED)}, f)
    except Exception:
        pass

load_config()


# Known-safe Windows built-in scheduled task names (whitelist)
WINDOWS_BUILTIN_TASKS = {
    "appuriverifierinstall","microsoft-windows-diskdiagnosticdatacollector",
    "storage tiers management initialization","usagedatareceiver","remotepensyncdata available",
    "directxdatabaseupdater","wifitask","refreshcache","startupapptask",
    "remotetouchpadsyncdata available","logon","printercleanuptask","hybriddriveacheprepopulate",
    "localusersyncdata available","device install group policy","windows defender verification",
    "dssvcleanup","initialization","spaceagenttask","upnphostconfig","moprofilemanagement",
    "processmemorydiagnosticevents","hybriddriveacherebalance","synchronizetimezone",
    "logon synchronization","diagnostics","monitoring","updatelibrry","restoredevice",
    "interactive","sustainabilitytelemetry","svcrestarttasklogon","runfullmemorydiagnostic",
    "verifiedpublishercertstorecheck","setuprecoverydatatask","usbceip","eduprintprov",
    "reconcilefeatures","microsoft-windows-diskdiagnosticresolver","bitlocker mdm policy refresh",
    "edp app launch task",".net framework ngen v4.0.30319 64",".net framework ngen v4.0.30319",
    "onedrive reporting task","remotepensyncdata available","spaceagent",
    # add more as needed
}

def is_builtin_task(name):
    return name.lower().strip() in WINDOWS_BUILTIN_TASKS or \
           any(name.lower().startswith(p) for p in [
               "onedrive","microsoft-windows","windows defender",".net framework",
               "adobe","nvidia","intel","amd","realtek"
           ])

# ─── ALERT STORE ──────────────────────────────────────────────────────────────

alert_lock    = threading.Lock()
active_alerts = {}
past_alerts   = []
alert_id_counter = [0]
alert_callback   = None

def _new_id():
    alert_id_counter[0] += 1
    return alert_id_counter[0]

def _make_key(category, message):
    return f"{category}::{message}"

def raise_alert(level, category, message, detail="", exe_path=None, vt=None, extra=None):
    key = _make_key(category, message)
    with alert_lock:
        if key in active_alerts:
            return
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    aid = _new_id()
    h = hash_file(exe_path) if exe_path else None
    entry = {
        "id": aid, "time": ts, "level": level, "category": category,
        "message": message, "detail": detail, "key": key,
        "resolved": False, "exe_path": exe_path,
        "hash": h,
        "hash_check": ("hash: " + h[:12]) if h else "no file",
        "vt": vt or "–", "vt_status": vt,
        "selected": False
    }
    if extra:
        entry.update(extra)
    with alert_lock:
        active_alerts[key] = entry
    if alert_callback:
        alert_callback("new", entry)

def resolve_alert(category, message):
    key = _make_key(category, message)
    with alert_lock:
        if key not in active_alerts:
            return
        entry = active_alerts.pop(key)
    entry["resolved"] = True
    entry["resolved_time"] = datetime.datetime.now().strftime("%H:%M:%S")
    past_alerts.append(entry)
    if alert_callback:
        alert_callback("resolved", entry)

# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

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

# ─── FILE WATCHER ─────────────────────────────────────────────────────────────

class BrowserProfileHandler(FileSystemEventHandler):
    def __init__(self, browser_name):
        self.browser_name = browser_name
    def on_modified(self, event):
        if event.is_directory: return
        if Path(event.src_path).name in SENSITIVE_FILES:
            self._check(event.src_path)
    def _check(self, filepath):
        if not MONITOR_ENABLED["browser"]:
            return
        try:
            for proc in psutil.process_iter(['pid','name','exe','open_files']):
                try:
                    pname = (proc.info['name'] or "").lower()
                    if pname in TRUSTED_BROWSER_EXES: continue
                    for f in proc.open_files():
                        if filepath.lower() in f.path.lower():
                            raise_alert("HIGH","Browser Profile Access",
                                f"{proc.info['name']} (PID {proc.pid}) reading {Path(filepath).name}",
                                f"Browser: {self.browser_name} | EXE: {proc.info.get('exe','unknown')}",
                                exe_path=proc.info.get('exe'))
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        except Exception: pass

def start_file_watchers():
    observers = []
    for browser, path in BROWSER_PROFILE_PATHS.items():
        watch_path = path if browser != "Firefox" else path.parent
        if watch_path.exists():
            observer = Observer()
            observer.schedule(BrowserProfileHandler(browser), str(watch_path), recursive=True)
            observer.start()
            observers.append(observer)
    handler = PersistenceHandler()
    for folder in STARTUP_FOLDERS:
        observer = Observer()
        observer.schedule(handler, folder, recursive=False)
        observer.start()
        observers.append(observer)
    for folder in TEMP_WATCH_DIRS:
        observer = Observer()
        observer.schedule(handler, folder, recursive=True)
        observer.start()
        observers.append(observer)
    # Browser-extension directory watch (#8)
    ext_handler = ExtensionHandler()
    for folder in EXTENSION_DIRS:
        observer = Observer()
        observer.schedule(ext_handler, folder, recursive=False)
        observer.start()
        observers.append(observer)
    # Executable / script drop watch (#9)
    drop_handler = DropHandler()
    for folder in DROP_WATCH_DIRS:
        observer = Observer()
        observer.schedule(drop_handler, folder, recursive=True)
        observer.start()
        observers.append(observer)
    # Screenshot-capture watch (#12)
    screen_handler = ScreenshotHandler()
    for folder in TEMP_WATCH_DIRS:
        observer = Observer()
        observer.schedule(screen_handler, folder, recursive=True)
        observer.start()
        observers.append(observer)
    return observers

# ─── WMI MONITOR ──────────────────────────────────────────────────────────────

def get_wmi_subscriptions():
    found = set()
    try:
        r = subprocess.run(["powershell","-NoProfile","-Command",
            "Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        for line in r.stdout.strip().splitlines():
            n = line.strip()
            if n and n != "SCM Event Log Filter":
                found.add(n)
    except Exception: pass
    return found

def wmi_monitor():
    known = get_wmi_subscriptions()
    if MONITOR_ENABLED["wmi"]:
        for name in known:
            raise_alert("CRITICAL","WMI Persistence",f"WMI subscription active: '{name}'",
                        "WMI subscriptions are a known malware persistence technique.")
    while True:
        time.sleep(WMI_POLL_INTERVAL)
        if not MONITOR_ENABLED["wmi"]:
            known = get_wmi_subscriptions()
            continue
        current = get_wmi_subscriptions()
        for name in current - known:
            raise_alert("CRITICAL","WMI Persistence",f"WMI subscription active: '{name}'",
                        "WMI subscriptions are a known malware persistence technique.")
        for name in known - current:
            resolve_alert("WMI Persistence",f"WMI subscription active: '{name}'")
        known = current

# ─── TASK MONITOR ─────────────────────────────────────────────────────────────

def get_scheduled_tasks():
    tasks = set()
    try:
        r = subprocess.run(["powershell","-NoProfile","-Command",
            "Get-ScheduledTask | Select-Object -ExpandProperty TaskName"],
            capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
        for line in r.stdout.strip().splitlines():
            t = line.strip()
            if t: tasks.add(t)
    except Exception: pass
    return tasks

def task_monitor():
    known = get_scheduled_tasks()
    while True:
        time.sleep(TASK_POLL_INTERVAL)
        if not MONITOR_ENABLED["tasks"]:
            known = get_scheduled_tasks()
            continue
        current = get_scheduled_tasks()
        for task in current - known:
            builtin = is_builtin_task(task)
            if builtin and WHITELIST_BUILTIN_TASKS:
                continue
            level = "INFO" if builtin else "HIGH"
            detail = "Malware often installs scheduled tasks for persistence."
            if builtin:
                detail += " (Windows built-in — whitelist disabled, shown for visibility)"
            raise_alert(level, "Scheduled Task", f"New scheduled task: '{task}'", detail)
        for task in known - current:
            resolve_alert("Scheduled Task", f"New scheduled task: '{task}'")
        known = current

# ─── PROCESS MONITOR ──────────────────────────────────────────────────────────

def process_monitor():
    seen = set()
    while True:
        if MONITOR_ENABLED["process"]:
            try:
                active_now = set()
                for proc in psutil.process_iter(['pid','name','exe']):
                    try:
                        pname = (proc.info['name'] or "").lower()
                        if pname not in SUSPICIOUS_OUTBOUND_PROCESSES: continue
                        try:
                            conns = proc.net_connections(kind='inet')
                        except Exception:
                            conns = []
                        for conn in conns:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                key = (proc.pid, conn.raddr.ip, conn.raddr.port)
                                active_now.add(key)
                                if key not in seen:
                                    seen.add(key)
                                    raise_alert("HIGH","Suspicious Network",
                                        f"{proc.info['name']} (PID {proc.pid}) → {conn.raddr.ip}:{conn.raddr.port}",
                                        "Suspicious process making outbound connection.",
                                        exe_path=proc.info.get('exe'))
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                for key in seen - active_now:
                    pid, ip, port = key
                    resolve_alert("Suspicious Network", f"PID {pid} → {ip}:{port}")
                seen = active_now
            except Exception: pass
        time.sleep(5)

# ─── CLIPBOARD MONITOR ────────────────────────────────────────────────────────

CRYPTO_PATTERNS = ["1A1z","3J98","bc1q","0x","T9yD","r3GYT"]

def clipboard_monitor(root):
    last = ""; flagged = False
    while True:
        if MONITOR_ENABLED["clipboard"]:
            try:
                current = root.clipboard_get()
                if current != last:
                    last = current
                    is_crypto = any(current.startswith(p) and len(current)>25 for p in CRYPTO_PATTERNS)
                    if is_crypto and not flagged:
                        flagged = True
                        raise_alert("MEDIUM","Clipboard",
                            "Possible crypto address in clipboard — verify it hasn't been swapped",
                            f"Value starts with: {current[:20]}...")
                    elif not is_crypto and flagged:
                        flagged = False
                        resolve_alert("Clipboard","Possible crypto address in clipboard — verify it hasn't been swapped")
            except Exception: pass
        time.sleep(2)

# ─── REGISTRY RUN-KEY MONITOR ───────────────────────────────────────────────

def get_reg_run_entries():
    found = {}
    for hive, label, subkey in REG_RUN_KEYS:
        try:
            with winreg.OpenKey(hive, subkey) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    found[(label, subkey, name)] = value
                    i += 1
        except FileNotFoundError:
            pass
        except Exception:
            pass
    return found

def registry_run_monitor():
    known = get_reg_run_entries()
    if MONITOR_ENABLED["registry"]:
        for (label, subkey, name), value in known.items():
            raise_reg_run(label, subkey, name, value)
    while True:
        time.sleep(REG_POLL_INTERVAL)
        if not MONITOR_ENABLED["registry"]:
            known = get_reg_run_entries()
            continue
        current = get_reg_run_entries()
        for key, value in current.items():
            if key not in known:
                label, subkey, name = key
                raise_reg_run(label, subkey, name, value)
        for key in list(known):
            if key not in current:
                label, subkey, name = key
                resolve_alert("Registry Run Key",
                             f"Run-key entry '{name}' in {label}\\{subkey}")
        known = current

# ─── RUN-KEY REPUTATION CHECKER ──────────────────────────────────────
# Auto-classifies each Registry Run-key entry as Legit / Review / Suspicious /
# Unknown so genuine software doesn't bury real persistence alerts.

KNOWN_GOOD_RUN = {  # substrings (lowercase) of common, legitimate Run entries
    "onedrive", "discord", "steam", "spotify", "adobe", "googleupdate",
    "google update", "googledrivesync", "skype", "teams", "slack", "dropbox",
    "boxsync", "whatsapp", "signal", "telegram", "itunes", "epicgameslauncher",
    "battle.net", "origin", "eadesktop", "ccleaner", "malwarebytes", "nvidia",
    "realtek", "intel", "amd", "pushbullet", "flux", "greenshot", "obs",
    "vlc", "brave", "microsoftedge", "chrome", "firefox", "bandizip", "peazip",
    "logitech", "razer", "corsair", "autohotkey", "everything", "powertoys",
}

VERDICT_LEVEL = {"legit": "INFO", "review": "HIGH", "suspicious": "CRITICAL",
                 "unknown": "HIGH"}
VERDICT_LABEL = {"legit": "🟢 Legit", "review": "🟡 Review",
                  "suspicious": "🔴 Suspicious", "unknown": "⚪ Unknown"}

def _trusted_dirs():
    dirs = {}
    pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    win = os.environ.get("WINDIR", r"C:\Windows")
    dirs["system"] = [os.path.normcase(os.path.join(win, "System32")),
                         os.path.normcase(os.path.join(win, "SysWOW64")),
                         os.path.normcase(win)]
    dirs["programfiles"] = [os.path.normcase(pf), os.path.normcase(pf86)]
    dirs["temp"] = [os.path.normcase(tempfile.gettempdir())]
    dirs["user"] = [os.path.normcase(os.environ.get("LOCALAPPDATA", "")),
                     os.path.normcase(os.environ.get("APPDATA", "")),
                     os.path.normcase(os.environ.get("USERPROFILE", ""))]
    return dirs

def classify_location(path):
    try:
        p = os.path.normcase(os.path.abspath(path))
    except Exception:
        return ("other", "unknown location")
    for kind, ddirs in _trusted_dirs().items():
        for d in ddirs:
            if d and (p == d or p.startswith(d + os.sep)):
                labels = {"system": "Windows system dir",
                          "programfiles": "Program Files",
                          "temp": "a temp directory",
                          "user": "a user-profile directory"}
                return (kind, labels[kind])
    return ("other", "another location")

def parse_run_target(value):
    """Return (exe_path, script_host) for a Run-key command value."""
    value = (value or "").strip()
    if not value:
        return (None, None)
    low = value.lower()
    script_host = None
    for h in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
               "mshta.exe", "rundll32.exe", "regsvr32.exe"):
        if h in low:
            script_host = h
            break
    if value.startswith('"'):
        end = value.find('"', 1)
        cand = value[1:end] if end != -1 else value[1:]
    else:
        parts = value.split()
        cand = None
        for i in range(len(parts), 0, -1):
            p = " ".join(parts[:i])
            if os.path.exists(p):
                cand = p
                break
        if cand is None:
            cand = parts[0] if parts else value
    exe = cand
    if script_host == "rundll32.exe":
        m = re.search(r'"([^"]+\.dll)"|\b([^\s]+\.dll)\b', value)
        if m:
            exe = m.group(1) or m.group(2)
    return (exe, script_host)

def verify_signature(path):
    """Authenticode check via WinVerifyTrust. Returns 'Valid' / 'NotSigned' /
    'Unverified' / 'Error', or None if unavailable."""
    try:
        wintrust = ctypes.windll.wintrust
    except Exception:
        return None
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.c_ulong),
                     ("pcwszFilePath", ctypes.c_wchar_p),
                     ("hFile", ctypes.c_void_p),
                     ("pgKnownSubject", ctypes.c_void_p)]
    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.c_ulong),
                     ("pPolicyCallbackData", ctypes.c_void_p),
                     ("pSIPClientData", ctypes.c_void_p),
                     ("dwUIChoice", ctypes.c_ulong),
                     ("fdwRevocationChecks", ctypes.c_ulong),
                     ("dwUnionChoice", ctypes.c_ulong),
                     ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                     ("pCatalog", ctypes.c_void_p),
                     ("pBlob", ctypes.c_void_p),
                     ("pSponsor", ctypes.c_void_p),
                     ("pWinPEntry", ctypes.c_void_p),
                     ("dwStateAction", ctypes.c_ulong),
                     ("hWVTStateData", ctypes.c_void_p),
                     ("pwszURLReference", ctypes.c_wchar_p),
                     ("dwProvFlags", ctypes.c_ulong),
                     ("dwUIContext", ctypes.c_ulong),
                     ("pSignatureSettings", ctypes.c_void_p)]
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                  (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    fi = WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    fi.pcwszFilePath = ctypes.c_wchar_p(path)
    fi.hFile = None
    fi.pgKnownSubject = None
    wtd = WINTRUST_DATA()
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = 2          # WTD_UI_NONE
    wtd.fdwRevocationChecks = 0
    wtd.dwUnionChoice = 1         # WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(fi)
    wtd.dwStateAction = 0
    wtd.dwUIContext = 0
    try:
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = wintypes.LONG
        rc = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wtd))
    except Exception:
        return None
    if rc == 0:
        return "Valid"
    if (rc & 0xFFFFFFFF) == 0x800B0100:   # TRUST_E_NOSIGNATURE
        return "NotSigned"
    return "Unverified"

def check_run_entry(value):
    """Return (verdict, detail) for a Run-key command value."""
    exe, host = parse_run_target(value)
    if host and (not exe or not os.path.exists(exe)):
        # bare command name (e.g. powershell.exe /cmd.exe) — resolve via PATH
        resolved = shutil.which(exe) if exe else None
        if resolved:
            exe = resolved
    if host:
        return ("suspicious", f"{host} launched from Run key: {value[:60]}")
    # Windows App Execution Aliases (Store apps like Teams) point at a 0-byte
    # stub under Microsoft\WindowsApps that isn't a real exe — always benign.
    if exe and "microsoft\\windowsapps" in os.path.normcase(exe):
        return ("legit", "Windows App Execution Alias (Store app)")
    if not exe or not os.path.exists(exe):
        return ("unknown", f"target not found: {(value or '')[:60]}")
    name = os.path.basename(exe).lower()
    if any(k in name for k in KNOWN_GOOD_RUN):
        return ("legit", f"known-good app: {os.path.basename(exe)}")
    kind, loc = classify_location(exe)
    sig = verify_signature(exe)
    if sig == "Valid":
        return ("legit", f"Authenticode-valid, in {loc}")
    if sig in ("NotSigned", "Error", None):
        if kind in ("system", "programfiles"):
            return ("review", f"unsigned but in {loc}")
        return ("suspicious", f"unsigned executable in {loc}")
    return ("suspicious", f"signature status '{sig}' in {loc}")

def raise_reg_run(label, subkey, name, value):
    verdict, rep = check_run_entry(value)
    level = VERDICT_LEVEL[verdict]
    msg = f"Run-key entry '{name}' in {label}\\{subkey}"
    detail = f"Value: {value}\n[Reputation] {rep}"
    exe, _ = parse_run_target(value)
    root = REG_ROOT_NAMES.get(label, label)
    reg_path = f"Computer\\{root}\\{subkey}"
    raise_alert(level, "Registry Run Key", msg, detail,
                  exe_path=exe, vt=VERDICT_LABEL[verdict],
                  extra={"run_value": value, "reg_path": reg_path, "reg_value": name})

# ─── DEFENDER EXCLUSION MONITOR ────────────────────────────────────────────

def get_defender_exclusions():
    found = {}
    try:
        hive, label, subkey = DEFENDER_EXCL_KEY
        with winreg.OpenKey(hive, subkey) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                found[name] = value
                i += 1
    except FileNotFoundError:
        pass
    except Exception:
        # Reading HKLM Defender exclusions usually requires admin; silently skip.
        pass
    return found

def defender_exclusion_monitor():
    known = get_defender_exclusions()
    while True:
        time.sleep(DEFENDER_POLL_INTERVAL)
        if not MONITOR_ENABLED["defender"]:
            known = get_defender_exclusions()
            continue
        current = get_defender_exclusions()
        for name, value in current.items():
            if name not in known:
                raise_alert("CRITICAL", "Defender Exclusion",
                            f"New Defender exclusion path: {name}",
                            f"Value: {value} (malware adds exclusions to evade scanning)")
        for name in list(known):
            if name not in current:
                resolve_alert("Defender Exclusion",
                             f"New Defender exclusion path: {name}")
        known = current

# ─── STARTUP FOLDER + ARCHIVE STAGING MONITOR (watchdog) ──────────────────

def archiver_running():
    try:
        for proc in psutil.process_iter(['name']):
            if (proc.info['name'] or "").lower() in ARCHIVER_EXES:
                return True
    except Exception:
        pass
    return False

class PersistenceHandler(FileSystemEventHandler):
    def _classify(self, path):
        try:
            p = Path(path)
            folder = os.path.dirname(path)
            ext = p.suffix.lower()
            if MONITOR_ENABLED["startup"] and p.is_file():
                for sf in STARTUP_FOLDERS:
                    if os.path.abspath(folder).lower().startswith(os.path.abspath(sf).lower()):
                        return ("startup", p.name, folder)
            if MONITOR_ENABLED["archive"] and ext in ARCHIVE_EXTS:
                if not archiver_running():
                    return ("archive", p.name, folder)
        except Exception:
            pass
        return None

    def on_created(self, event):
        if event.is_directory:
            return
        info = self._classify(event.src_path)
        if not info:
            return
        kind, name, folder = info
        if kind == "startup":
            raise_alert("HIGH", "Startup Folder",
                        f"New startup item: {name}", f"Location: {folder}")
        else:
            raise_alert("HIGH", "Archive Staging",
                        f"Archive created in {os.path.basename(folder)}: {name}",
                        "Archive creation in a temp/user dir may indicate data staging before exfiltration.")

    def on_deleted(self, event):
        if event.is_directory:
            return
        try:
            p = Path(event.src_path)
            folder = os.path.dirname(event.src_path)
            ext = p.suffix.lower()
            if MONITOR_ENABLED["startup"] and p.is_file():
                for sf in STARTUP_FOLDERS:
                    if os.path.abspath(folder).lower().startswith(os.path.abspath(sf).lower()):
                        resolve_alert("Startup Folder", f"New startup item: {p.name}")
                        return
            if MONITOR_ENABLED["archive"] and ext in ARCHIVE_EXTS:
                resolve_alert("Archive Staging",
                             f"Archive created in {os.path.basename(folder)}: {p.name}")
        except Exception:
            pass

# ─── DNS TXT SPIKE MONITOR ──────────────────────────────────────────────────

DNS_MSG = "DNS TXT-record query volume spike"

def get_dns_txt_count():
    try:
        r = subprocess.run(["ipconfig", "/displaydns"],
                           capture_output=True, text=True, timeout=10,
                           creationflags=CREATE_NO_WINDOW)
        return r.stdout.lower().count("txt")
    except Exception:
        return 0

def dns_monitor():
    samples = []
    alerted = False
    while True:
        time.sleep(DNS_POLL_INTERVAL)
        if not MONITOR_ENABLED["dns"]:
            samples.clear(); alerted = False
            continue
        count = get_dns_txt_count()
        samples.append(count)
        if len(samples) > 12:
            samples.pop(0)
        if len(samples) < 4:
            continue
        baseline = sum(samples[:-1]) / max(1, len(samples) - 1)
        if not alerted and count >= DNS_SPIKE_MIN and count >= baseline * DNS_SPIKE_FACTOR:
            alerted = True
            raise_alert("HIGH", "DNS Anomaly", DNS_MSG,
                        f"{count} TXT records cached (baseline ~{int(baseline)}); "
                        f"may indicate in-memory payload delivery via DNS.")
        elif alerted and count < baseline * 1.5:
            alerted = False
            resolve_alert("DNS Anomaly", DNS_MSG)

# ─── POWERSHELL-SPAWN MONITOR (#6) ──────────────────────────────

def powershell_spawn_monitor():
    # Flag PowerShell/pwsh whose PARENT is a process that should never
    # launch a shell (Office / browser / mshta / wmiprvse …) — the
    # fake-CAPTCHA / macro-delivery chain.
    seen = set()
    while True:
        time.sleep(5)
        if not MONITOR_ENABLED["pspawn"]:
            seen.clear()
            continue
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if (proc.info['name'] or "").lower() not in ("powershell.exe", "pwsh.exe"):
                        continue
                    ppid = proc.ppid()
                    parent = psutil.Process(ppid) if ppid else None
                    pname = (parent.name().lower() if parent else "")
                    if pname in PSPAWN_SUSPICIOUS_PARENTS:
                        key = (proc.pid, pname)
                        if key in seen:
                            continue
                        seen.add(key)
                        raise_alert("HIGH", "PowerShell Spawn",
                                    f"PowerShell (PID {proc.pid}) spawned by {pname}",
                                    "Office/browser/mshta spawning PowerShell is a classic "
                                    "fake-CAPTCHA / macro delivery chain.")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                    pass
        except Exception:
            pass
        alive = {p.pid for p in psutil.process_iter(['pid'])}
        seen = {(pid, p) for (pid, p) in seen if pid in alive}

# ─── INTEGRITY BASELINE (#7) ───────────────────────────────────────

def _snapshot_integrity():
    snap = {"run": {}, "startup": {}, "typelib": []}
    for rk, value in get_reg_run_entries().items():
        label, subkey, name = rk
        snap["run"][f"{label}\\{subkey}::{name}"] = value
    for folder in STARTUP_FOLDERS:
        try:
            for fn in os.listdir(folder):
                fp = os.path.join(folder, fn)
                if os.path.isfile(fp):
                    snap["startup"][os.path.abspath(fp).lower()] = hash_file(fp)
        except Exception:
            pass
    # Carry the TypeLib section too so the two baseline writers never
    # clobber each other's data in the shared baseline file.
    snap["typelib"] = list(get_typelib_entries().keys())
    return snap

def load_baseline():
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_baseline(snap):
    try:
        with open(BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(snap, f)
    except Exception:
        pass

def integrity_monitor():
    # First launch (or missing baseline): snapshot and learn current
    # Run-key values + startup files, then alert only on CHANGES to
    # existing entries (stealers often overwrite a legit entry to masquerade).
    baseline = load_baseline()
    if baseline is None:
        save_baseline(_snapshot_integrity())
        baseline = load_baseline() or {"run": {}, "startup": {}}
    while True:
        time.sleep(REG_POLL_INTERVAL)
        if not MONITOR_ENABLED["integrity"]:
            baseline = _snapshot_integrity()
            continue
        current = _snapshot_integrity()
        for rk, val in current["run"].items():
            if rk in baseline["run"] and baseline["run"][rk] != val:
                raise_alert("HIGH", "Run-Key Integrity",
                            f"Run-key value changed: {rk}",
                            f"Old: {baseline['run'][rk]}\nNew: {val}\n"
                            "A stealer may have overwritten an existing entry to masquerade.")
        for sf, h in current["startup"].items():
            if sf in baseline["startup"] and baseline["startup"][sf] != h:
                raise_alert("HIGH", "Startup Integrity",
                            f"Startup item modified: {os.path.basename(sf)}",
                            f"Hash changed (old {baseline['startup'][sf][:12]} → "
                            f"new {h[:12]}) — possible tampering.")
        baseline = current
        save_baseline(baseline)

# ─── BROWSER-EXTENSION MONITOR (#8) ───────────────────────────────

class ExtensionHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            return
        if not MONITOR_ENABLED["extension"]:
            return
        try:
            d = event.src_path
            parent = os.path.basename(os.path.dirname(d)).lower()
            browser = {"extensions": "browser", "default": "browser"}.get(parent, parent)
            raise_alert("HIGH", "Browser Extension",
                        f"New extension folder dropped: {os.path.basename(d)}",
                        f"Location: {d}\nMalicious extensions (cookie "
                        f"grabbers) are sometimes compiled on the fly into the "
                        f"extensions directory.")
        except Exception:
            pass

# ─── EXECUTABLE-DROP MONITOR (#9) ──────────────────────────────────

def installer_running():
    try:
        for proc in psutil.process_iter(['name']):
            if (proc.info['name'] or "").lower() in INSTALLER_EXES:
                return True
    except Exception:
        pass
    return False

class DropHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if not MONITOR_ENABLED["drop"]:
            return
        try:
            p = Path(event.src_path)
            if p.suffix.lower() not in DROP_EXTS:
                return
            # PowerShell's own policy-probe file, auto-created+deleted in Temp.
            if p.name.startswith("__PSScriptPolicyTest_"):
                return
            if installer_running() or archiver_running():
                return
            folder = os.path.basename(os.path.dirname(p))
            raise_alert("HIGH", "Executable Drop",
                        f"New {p.suffix.lower()} in {folder}: {p.name}",
                        "Unexpected executable/script dropped into a temp/user "
                        "directory by a non-installer process.")
        except Exception:
            pass

# ─── TYPELIB-HIJACK MONITOR (#10) ──────────────────────────────────

def get_typelib_entries():
    found = {}
    try:
        with winreg.OpenKey(TYPELIB_KEY[0], TYPELIB_KEY[2]) as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i); i += 1
                except OSError:
                    break
                found[name] = name
    except Exception:
        pass
    return found

def typelib_monitor():
    baseline = load_baseline() or {}
    tl_base = baseline.get("typelib")
    if tl_base is None:
        tl_base = list(get_typelib_entries().keys())
        baseline["typelib"] = tl_base
        save_baseline(baseline)
    known = set(tl_base)
    while True:
        time.sleep(DEFENDER_POLL_INTERVAL)
        if not MONITOR_ENABLED["typelib"]:
            known = set(get_typelib_entries().keys())
            continue
        current = set(get_typelib_entries().keys())
        for name in current - known:
            raise_alert("HIGH", "TypeLib Hijack",
                        f"New TypeLib entry: {name}",
                        "HKCU\\Software\\Classes\\TypeLib modification is an "
                        "emerging infostealer persistence / hijack technique.")
        known = current
        baseline = load_baseline() or {}
        baseline["typelib"] = list(known)
        save_baseline(baseline)

# ─── CRYPTO-WALLET ACCESS MONITOR (#11) ──────────────────────
# Catch non-browser processes reading/holding wallet files (watchdog can't
# see reads, so we poll psutil open_files()).

def wallet_monitor():
    seen_open = set()
    while True:
        time.sleep(WALLET_OPEN_POLL)
        if not MONITOR_ENABLED["wallet"]:
            seen_open.clear(); continue
        try:
            open_now = set()
            for proc in psutil.process_iter(['pid','name']):
                try:
                    pname = (proc.info['name'] or "").lower()
                    if pname in WALLET_BENIGN:
                        continue
                    for of in proc.open_files():
                        if _is_wallet_path(of.path):
                            open_now.add((proc.info['pid'], pname, of.path))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                    pass
            for key in open_now - seen_open:
                pid, pname, fp = key
                raise_alert("HIGH", "Wallet Access",
                            f"{pname} (PID {pid}) opened wallet file: "
                            f"{os.path.basename(fp)}",
                            "Crypto wallet data should only be touched by the "
                            "browser/extension it belongs to. A non-browser "
                            "process reading it is a classic stealer behavior.")
            seen_open = open_now
        except Exception:
            pass

# ─── SCREENSHOT-CAPTURE MONITOR (#12) ─────────────────────────

def _proc_running(names):
    try:
        for proc in psutil.process_iter(['name']):
            if (proc.info['name'] or "").lower() in names:
                return True
    except Exception:
        pass
    return False

class ScreenshotHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if not MONITOR_ENABLED["screenshot"]:
            return
        try:
            p = Path(event.src_path)
            if p.suffix.lower() not in SCREEN_EXTS:
                return
            if installer_running() or archiver_running():
                return
            if _proc_running(SCREEN_TOOLS):
                return
            try:
                if os.path.getsize(p) < SCREEN_MIN_BYTES:
                    return
            except Exception:
                return
            folder = os.path.basename(os.path.dirname(p))
            raise_alert("MEDIUM", "Screenshot Capture",
                        f"Bitmap captured in {folder}: {p.name}",
                        "Infostealers (Salat/Micro) screenshot sensitive "
                        "windows; unexpected bitmaps in temp may indicate theft.")
        except Exception:
            pass

# ─── AV / SECURITY-TOOL KILL MONITOR (#13) ───────────────────
# We can't detect our own process being terminated (post-mortem), so we watch
# security / analysis tools vanishing from the process list instead.

def avkill_monitor():
    seen = {}
    while True:
        time.sleep(AV_POLL)
        if not MONITOR_ENABLED["avkill"]:
            seen.clear(); continue
        try:
            current = {}
            for proc in psutil.process_iter(['pid','name']):
                try:
                    n = (proc.info['name'] or "").lower()
                    if n in AV_TOOLS:
                        current.setdefault(n, set()).add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.Error):
                    pass
            for name in set(seen) - set(current):
                raise_alert("HIGH", "AV Kill Attempt",
                            f"Security/analysis tool disappeared: {name}",
                            "Snake and similar stealers terminate AV / analysis "
                            "tools (avastui.exe, wireshark.exe, …) to evade "
                            "detection.")
            seen = current
        except Exception:
            pass

# ─── GUI ──────────────────────────────────────────────────────────────────────

LEVEL_COLORS = {"CRITICAL":"#e8503a","HIGH":"#f5a623","MEDIUM":"#f0c040","INFO":"#6a6a7a"}
PAST_COLOR   = "#444455"
VT_COLORS    = {"safe":"#3ddc84","malicious":"#e8503a","suspicious":"#f5a623",
                "unknown":"#888899","checking":"#aaaacc"}

# ── UI Theme / Layout constants ───────────────────────────────────────────────
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
                candidates.append(os.path.join(base, "notyours2.png"))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "notyours2.png"))
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
        # Resizing fires <Configure> dozens of times per drag; debounce the
        # scrollbar/scrollregion recompute so we don't thrash the UI thread.
        self._scroll_job = None
        self.body.bind("<Configure>", lambda e: self._schedule_scroll())
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
        self._relayout()

    def _relayout(self):
        self.body.configure(width=self._total())
        self.body.configure(height=max(1, len(self.rows) * 26))
        # Reposition header widgets in place (do NOT rebuild, or an active drag's
        # separator would be destroyed mid-drag and the drag would die after a pixel).
        x = 0
        for c, lbl, sep in getattr(self, "_hdr", []):
            lbl.place(x=x+6, y=0, width=max(1, c["width"]-6), height=26)
            if sep is not None:
                sep.place(x=x+c["width"]-3, y=4, width=6, height=18)
            x += c["width"]
        for r in self.rows:
            self._position_row(r)
        self._update_scrollbar()

    def _schedule_scroll(self):
        if self._scroll_job is not None:
            self.app.after_cancel(self._scroll_job)
        self._scroll_job = self.app.after(40, self._update_scrollbar)

    def _update_scrollbar(self):
        try:
            content_h = len(self.rows) * 26
            # Size the body exactly to its rows and base the scroll region on
            # that, so there is never empty space to scroll into (no scrolling
            # above the first alert or below the last one).
            self.body.configure(height=content_h)
            self.canvas.update_idletasks()
            view = self.canvas.winfo_height()
            self.canvas.configure(scrollregion=(0, 0, self._total(), content_h))
            if content_h > view + 1:
                if not self.sb.winfo_ismapped():
                    self.sb.pack(side="right", fill="y")
            else:
                # Everything fits: no scrollbar, pinned to the top.
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
        ic = tk.Canvas(cf, width=16, height=16, bg=ROW_BG, highlightthickness=0)
        draw_icon(ic, kind, "#bdbdbd"); ic.pack(side="left", padx=(2,4))
        cat = tk.Label(cf, text=entry["category"], bg=ROW_BG, fg="#cfcfcf", font=("Segoe UI",8))
        cat.pack(side="left")
        row["cells"]["category"] = cf
        row["bgw"] += [cf, ic]; row["icons"].append(ic)
        m = tk.Label(frame, text=entry["message"], bg=ROW_BG, fg=TEXT, font=("Segoe UI",8), anchor="w")
        row["cells"]["message"] = m; row["bgw"].append(m)
        def _on_row_double(e, r=row):
            rp = r["entry"].get("reg_path")
            if rp: self.app._open_regedit(rp)
        frame.bind("<Double-1>", _on_row_double)
        m.bind("<Double-1>", _on_row_double)
        def _on_enter(e, r=row): self._show_tip(r, e)
        def _on_leave(e): self._hide_tip()
        frame.bind("<Enter>", _on_enter)
        frame.bind("<Leave>", _on_leave)
        vt = tk.Label(frame, text=entry.get("vt_status") or "–", bg=ROW_BG, fg=DIM, font=("Segoe UI",8))
        row["cells"]["vt"] = vt; row["bgw"].append(vt)
        # VirusTotal hashes FILES, so the Check button is only meaningful for actual
        # executable processes. Everything else (registry run keys, scripts, clipboard,
        # etc.) gets a greyed/disabled button.
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
        # Selection only toggles via the checkbox cell — clicking elsewhere on the
        # row (e.g. the message) must not select it.
        row["cells"]["sel"].bind("<Button-1>", _on_row_click)
        for w in row["cells"].values():
            try:
                if isinstance(w, tk.Button):
                    continue   # "Check" button keeps its own action
            except Exception:
                pass
        self.rows.append(row)
        self.row_by_id[entry["id"]] = row
        self._position_row(row)
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
        self._fit_message(row)

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
            try: w.config(bg=color)
            except Exception: pass
        for ic in row["icons"]:
            try: ic.config(bg=color)
            except Exception: pass

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
    # Tkinter cannot style the OS title bar natively; on Windows we opt into the
    # immersive dark title bar via the DWM/uxtheme APIs. Works on any Toplevel.
    # No-op on other platforms.
    if sys.platform != "win32":
        return
    try:
        import ctypes
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi
        hwnd = int(win.winfo_id())
        # Climb to the actual top-level window that owns the title bar.
        try:
            root = user32.GetAncestor(hwnd, 2)
            if root: hwnd = root
        except Exception:
            pass
        # Opt the window into dark mode (undocumented uxtheme exports).
        try:
            uxtheme = ctypes.windll.uxtheme
            if hasattr(uxtheme, "SetPreferredAppMode"):
                uxtheme.SetPreferredAppMode(2)  # AllowDark
            if hasattr(uxtheme, "AllowDarkModeForWindow"):
                uxtheme.AllowDarkModeForWindow(hwnd, True)
        except Exception:
            pass
        val = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (20H1+, then pre-20H1)
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
        self._cog_anim    = None
        self._settings_win = None
        self.logo_img = load_logo(34)
        if self.logo_img:
            try: self.iconphoto(True, self.logo_img)
            except Exception: pass

        self._build_ui()
        global alert_callback
        alert_callback = self._on_alert_event

        # ── TRAY / NOTIFICATION STATE ──
        self.tray_icon     = None
        self._in_tray      = False
        self._notif_times  = []
        self._spam_notified = False
        self._setup_tray()
        self.protocol("WM_DELETE_WINDOW", self._hide_to_tray)
        self.bind("<Unmap>", self._on_unmap)

    def _apply_dark_titlebar(self):
        _dark_titlebar(self)

    # ── SYSTEM TRAY ───────────────────────────────────────────────────────────

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
                "notyours", img, "notyours — Session Stealer Detector", menu
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

    # ── REGEDIT JUMP ─────────────────────────────────────────────────────────────

    def _open_regedit(self, key_path):
        # regedit requires elevation here, so a plain Popen fails (WinError 740) and
        # silently does nothing. We write the target into LastKey, then launch an
        # ELEVATED cmd that closes any open regedit and starts a fresh (elevated)
        # instance — which reads LastKey and jumps straight to the exact key.
        # A single UAC prompt appears; if regedit is already closed this still works.
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
                # Fallback for machines where regedit does NOT need elevation.
                subprocess.Popen(["regedit.exe"], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
    # ── NOTIFICATIONS ──────────────────────────────────────────────────────────

    def _notify(self, entry):
        # INFO-level alerts (e.g. legit registry Run keys, built-in tasks) are
        # just informational — never raise a toast for them.
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

    # ── BUILD ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=20, pady=(14,0))
        if self.logo_img:
            tk.Label(hdr, image=self.logo_img, bg=BG).pack(side="left", padx=(0,8))
        tk.Label(hdr, text="notyours", font=("Segoe UI",18,"bold"),
                 fg=TEXT, bg=BG).pack(side="left")
        tk.Label(hdr, text="  Session Stealer Detector", font=("Segoe UI",10),
                 fg=DIM, bg=BG).pack(side="left", pady=(3,0))
        self.status_dot = tk.Label(hdr, text="● MONITORING", font=("Segoe UI",9,"bold"),
                                   fg=GREEN, bg=BG)
        self.status_dot.pack(side="right")
        self.cog_canvas = tk.Canvas(hdr, width=16, height=16, bg=BG,
                                    highlightthickness=0, cursor="hand2")
        draw_icon(self.cog_canvas, "gear", "#9a9a9a")
        self.cog_canvas.pack(side="right", padx=(10,0))
        self.cog_canvas.bind("<Button-1>", lambda e: self._open_settings())

        # Stat cards
        cards = tk.Frame(self, bg=BG)
        cards.pack(fill="x", padx=20, pady=12)
        for lvl, color in [("CRITICAL","#e8503a"),("HIGH","#f5a623"),("MEDIUM","#f0c040")]:
            c = self._make_stat_card(cards, lvl, color)
            c.pack(side="left", padx=(0,14), fill="x", expand=True)

        # Tabs + toolbar
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

        # Tables
        self.active_table = AlertTable(self, self, ACTIVE_COLUMNS)
        self.past_table  = AlertTable(self, self, ACTIVE_COLUMNS)
        self.active_table.outer.pack(fill="both", expand=True, padx=20, pady=(6,0))
        self.past_table.outer.pack_forget()

        # Footer
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

    # ── HELPERS ───────────────────────────────────────────────────────────────

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

    # ── SETTINGS (cog) ─────────────────────────────────────────────────────────

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
        win.grab_set()
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
        win.protocol("WM_DELETE_WINDOW", lambda: (win.destroy(), setattr(self, "_settings_win", None)))

    def _set_monitor(self, key):
        MONITOR_ENABLED[key] = self.monitor_vars[key].get()
        save_config()

    def _spin_cog(self, angle=0):
        if self._cog_anim is not None:
            try: self.after_cancel(self._cog_anim)
            except Exception: pass
        draw_icon(self.cog_canvas, "gear", "#9a9a9a", angle)
        if angle < 360:
            self._cog_anim = self.after(18, self._spin_cog, angle + 18)
        else:
            self._cog_anim = None

    def _vt_focus_in(self, e):
        if self.vt_entry.get() == "VT API Key":
            self.vt_entry.delete(0,"end"); self.vt_entry.config(fg="#cfcfcf")

    def _clear_api_selection(self, e):
        # Clicking anywhere outside the API key field clears its text selection.
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
            self._vt_commit()   # remember the key locally, but do NOT re-ping

    def _vt_commit(self):
        global VT_API_KEY
        VT_API_KEY = self.vt_entry.get().strip()
        save_config()

    def _vt_save(self, e):
        # Called only on Enter: remember the key AND ping once to confirm it works.
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

    def _switch_tab(self, show_past):
        self.showing_past = show_past
        if show_past:
            self.active_table.outer.pack_forget()
            self.past_table.outer.pack(fill="both", expand=True, padx=20, pady=(6,0))
            self.tab_active_btn.config(bg="#161616", fg=DIM, font=("Segoe UI",9))
            self.tab_past_btn.config(bg="#1e1e1e", fg=TEXT, font=("Segoe UI",9,"bold"))
        else:
            self.past_table.outer.pack_forget()
            self.active_table.outer.pack(fill="both", expand=True, padx=20, pady=(6,0))
            self.tab_active_btn.config(bg="#1e1e1e", fg=TEXT, font=("Segoe UI",9,"bold"))
            self.tab_past_btn.config(bg="#161616", fg=DIM, font=("Segoe UI",9))
        self._update_toolbar()

    # ── SELECTION ─────────────────────────────────────────────────────────────

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

    # ── VT ────────────────────────────────────────────────────────────────────

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

    # ── ALERT EVENTS ──────────────────────────────────────────────────────────

    def _on_alert_event(self, event_type, entry):
        self.after(0, lambda: self._handle_alert(event_type, entry))

    def _handle_alert(self, event_type, entry):
        level = entry["level"]
        if event_type == "new":
            self.alert_counts[level] = self.alert_counts.get(level, 0) + 1
            self.active_table.add_row(entry)
            self._refresh_cards()
            self._update_toolbar()
            self._notify(entry)
        elif event_type == "resolved":
            if entry["id"] in self.active_table.row_by_id:
                self.alert_counts[level] = max(0, self.alert_counts.get(level, 0) - 1)
                self.past_counts[level]  = self.past_counts.get(level, 0) + 1
                self.active_table.remove_row(entry)
                self.past_table.add_row(entry, past=True)
                self._refresh_cards()
                self._update_toolbar()

    # ── WHITELIST TOGGLE ──────────────────────────────────────────────────────

    def _toggle_whitelist(self):
        global WHITELIST_BUILTIN_TASKS
        WHITELIST_BUILTIN_TASKS = self.whitelist_var.get()
        save_config()
        if WHITELIST_BUILTIN_TASKS:
            # When re-enabling, resolve any currently-shown built-in (INFO) task alerts.
            # Take a snapshot first so we don't mutate the dict while iterating it.
            builtin_entries = [
                e for e in list(active_alerts.values())
                if e["category"] == "Scheduled Task" and e["level"] == "INFO"
            ]
            for entry in builtin_entries:
                # resolve_alert already checks if the key still exists, so this is safe
                # even if the alert was dismissed between the snapshot and now.
                resolve_alert("Scheduled Task", entry["message"])

    # ── EXPORT ────────────────────────────────────────────────────────────────

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
        self.observers = start_file_watchers()
        for fn in [wmi_monitor, task_monitor, process_monitor,
                   registry_run_monitor, defender_exclusion_monitor, dns_monitor,
                   powershell_spawn_monitor, integrity_monitor,
                   typelib_monitor, wallet_monitor, avkill_monitor]:
            threading.Thread(target=fn, daemon=True).start()
        threading.Thread(target=clipboard_monitor, args=(self,), daemon=True).start()

    def on_close(self):
        self._quit()

# ─── ENTRY ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = DetectorApp()
    app.start_monitors()
    app.mainloop()