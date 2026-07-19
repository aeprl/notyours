import os, sys, time, json, hashlib, datetime, threading, ctypes, subprocess
import logging
from logging.handlers import RotatingFileHandler
from ctypes import wintypes
import psutil

_engine_dir = os.path.dirname(os.path.abspath(__file__))
_error_log_path = os.path.join(_engine_dir, "notyours_error.log")
_handler = RotatingFileHandler(_error_log_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(_handler)
logging.getLogger().setLevel(logging.WARNING)

def log_error(source, msg):
    logging.getLogger(source).error(msg, exc_info=True)

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

RISK_WEIGHTS = {
    "file_drop_appdata":     10,  "unsigned_binary":       30,
    "suspicious_parent":     25,  "registry_persistence":  20,
    "browser_file_access":   15,  "outbound_connection":   35,
    "clipboard_crypto":      20,  "wmi_subscription":      25,
    "defender_exclusion":    30,  "process_from_temp":     20,
    "dns_anomaly":           15,  "powershell_spawn":      25,
    "screenshot_capture":    10,  "typelib_hijack":        20,
    "wallet_access":         25,  "extension_added":       15,
    "archive_staging":       10,  "integrity_violation":   30,
    "self_defense_trigger":  50,  "exe_drop":              10,
    "unsigned_drop":         25,  "registry_run_key":      20,
    "shadow_copy_deletion":  50,
}
ALERT_THRESHOLD = 0
SCORE_DECAY_SECONDS = 300

TRUSTED_PARENTS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "explorer.exe", "svchost.exe", "services.exe", "winlogon.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "system", "system idle process",
    "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
    "shellexperiencehost.exe", "applicationframehost.exe",
    "windowsinternal.composableshell.experiences.textinput.inputapp.exe",
    "searchapp.exe", "searchui.exe", "startmenuexperiencehost.exe",
    "dllhost.exe", "rundll32.exe",
    "unsecapp.exe", "mmc.exe", "wmic.exe",
}

PSPAWN_SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
    "iexplore.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "wmiprvse.exe", "rundll32.exe", "regsvr32.exe", "acrord32.exe",
    "foxitreader.exe", "javaw.exe",
    "node.exe", "hh.exe", "certutil.exe",
    "python.exe", "pythonw.exe",
}

MONITOR_ENABLED = {"browser": True, "wmi": True, "tasks": True,
    "process": True, "clipboard": True,
    "registry": True, "startup": True, "defender": True,
    "archive": True, "dns": True,
    "pspawn": True, "integrity": True, "extension": True,
    "drop": True, "typelib": True,
    "wallet": True, "screenshot": True, "avkill": True}

MONITOR_CATEGORIES = [
    ("browser",   "Browser Profiles"), ("wmi", "WMI Subscriptions"),
    ("tasks", "Scheduled Tasks"), ("process", "Suspicious Processes"),
    ("clipboard", "Clipboard"), ("registry", "Registry Run Keys"),
    ("startup", "Startup Folder"), ("defender", "Defender Exclusions"),
    ("archive", "Archive Staging"), ("dns", "DNS Anomaly"),
    ("pspawn", "PowerShell Spawn"), ("integrity", "Run/Startup Integrity"),
    ("extension", "Browser Extension"), ("drop", "Executable Drop"),
    ("typelib", "TypeLib Hijack"), ("wallet", "Crypto Wallet"),
    ("screenshot", "Screenshot Capture"), ("avkill", "AV Kill Attempt"),
]

VERDICT_LEVEL = {"legit": "INFO", "review": "HIGH", "suspicious": "CRITICAL", "unknown": "HIGH"}
VERDICT_LABEL = {"legit": "\U0001f7e2 Legit", "review": "\U0001f7e1 Review",
                  "suspicious": "\U0001f534 Suspicious", "unknown": "\u26aa Unknown"}


class ScoreTracker:
    def __init__(self, decay=300):
        self._lock = threading.Lock()
        self._scores = {}
        self._decay = decay

    def add(self, key, indicator, points, metadata=None):
        with self._lock:
            now = time.time()
            self._prune(now)
            entry = self._scores.get(key)
            if entry is None:
                entry = {"score": 0, "indicators": {}, "updated": now, "metadata": {}}
                self._scores[key] = entry
            if indicator not in entry["indicators"]:
                entry["indicators"][indicator] = now
                entry["score"] += points
                entry["updated"] = now
                if metadata:
                    entry["metadata"].update(metadata)
            return entry["score"]

    def _prune(self, now):
        expired = [k for k, v in self._scores.items() if now - v.get("updated", 0) > self._decay]
        for k in expired:
            del self._scores[k]

    def get(self, key):
        with self._lock:
            entry = self._scores.get(key)
            return entry["score"] if entry else 0

    def clear(self, key):
        with self._lock:
            self._scores.pop(key, None)

    def snapshot(self, key):
        with self._lock:
            entry = self._scores.get(key)
            if entry:
                return dict(entry["metadata"]), list(entry["indicators"].keys())
            return {}, []


score_tracker = ScoreTracker(decay=SCORE_DECAY_SECONDS)
_responded_pids = set()
_response_lock = threading.Lock()

_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
_ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

_OpenProcess = _kernel32.OpenProcess
_OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_OpenProcess.restype = wintypes.HANDLE
_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL
_TerminateProcess = _kernel32.TerminateProcess
_TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_TerminateProcess.restype = wintypes.BOOL
_NtSuspendProcess = _ntdll.NtSuspendProcess
_NtSuspendProcess.argtypes = [wintypes.HANDLE]
_NtSuspendProcess.restype = wintypes.LONG
_NtResumeProcess = _ntdll.NtResumeProcess
_NtResumeProcess.argtypes = [wintypes.HANDLE]
_NtResumeProcess.restype = wintypes.LONG

PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400


def _get_pid_from_path(exe_path):
    if not exe_path:
        return None
    target = os.path.normpath(exe_path).lower()
    try:
        for proc in psutil.process_iter(["pid", "exe"]):
            try:
                if proc.exe() and os.path.normpath(proc.exe()).lower() == target:
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return None


def suspend_process(pid):
    h = _OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False
    try:
        return _NtSuspendProcess(h) >= 0
    finally:
        _CloseHandle(h)


def resume_process(pid):
    h = _OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False
    try:
        return _NtResumeProcess(h) >= 0
    finally:
        _CloseHandle(h)


def kill_process(pid):
    h = _OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False
    try:
        return _TerminateProcess(h, 1)
    finally:
        _CloseHandle(h)


def block_ip_firewall(ip, rule_name=None):
    if not rule_name:
        rule_name = f"NotYours Block {ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return True
    except Exception:
        return False


def _active_response(total, indicator, exe_path, extra):
    if not exe_path:
        return
    pid = _get_pid_from_path(exe_path)
    if pid is None:
        return
    mypid = os.getpid()
    if pid == mypid:
        return
    with _response_lock:
        if pid in _responded_pids:
            return
    actions = []
    if total >= 100:
        if kill_process(pid):
            actions.append("killed")
            with _response_lock:
                _responded_pids.add(pid)
    elif total >= 80:
        if suspend_process(pid):
            actions.append("suspended")
            with _response_lock:
                _responded_pids.add(pid)
    if indicator == "outbound_connection" and total >= 80 and extra:
        ip = extra.get("ip", "")
        if ip and block_ip_firewall(ip):
            actions.append(f"blocked_ip:{ip}")
    if actions:
        try:
            raise_alert("ACTION", "Active Response",
                        f"Auto-response: {', '.join(actions)} on PID {pid}",
                        f"Path: {exe_path}\nScore: {total}\nIndicator: {indicator}",
                        exe_path)
        except Exception:
            pass


def process_lineage_check(exe_path):
    if not exe_path:
        return 0
    target = os.path.normpath(exe_path).lower()
    try:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if proc.exe() and os.path.normpath(proc.exe()).lower() == target:
                    parent = proc.parent()
                    if parent is None:
                        return 0
                    pname = parent.name().lower()
                    pexe = parent.exe().lower() if parent.exe() else ""
                    if pname in TRUSTED_PARENTS:
                        return -20
                    if pname in PSPAWN_SUSPICIOUS_PARENTS:
                        return 25
                    if pexe and verify_signature(pexe) != "Valid":
                        return 15
                    return 5
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return 0


def score_event(indicator, category, message, exe_path=None, detail="", extra=None):
    weight = RISK_WEIGHTS.get(indicator, 10)
    lineage = 0
    if exe_path:
        lineage = process_lineage_check(exe_path)
    net = weight + max(lineage, -weight)
    entity_key = exe_path or _make_key(category, message)
    meta = {"category": category, "message": message, "detail": detail, "exe_path": exe_path, "extra": extra}
    total = score_tracker.add(entity_key, indicator, net, meta)
    _active_response(total, indicator, exe_path, extra)
    if total >= ALERT_THRESHOLD:
        if total >= 100:
            level = "CRITICAL"
        elif total >= 60:
            level = "HIGH"
        else:
            level = "MEDIUM"
        md, inds = score_tracker.snapshot(entity_key)
        ind_lines = "\n".join(f"  +{RISK_WEIGHTS.get(i,10)} [{i}]" for i in inds)
        merged = detail
        if ind_lines:
            merged += "\n\nScore Breakdown:\n" + ind_lines
        if extra is None:
            extra = {"score_total": total, "indicators": inds, "lineage_score": lineage}
        else:
            extra.update({"score_total": total, "indicators": inds, "lineage_score": lineage})
        raise_alert(level, category, message, merged, exe_path, extra=extra)
        score_tracker.clear(entity_key)


alert_lock = threading.Lock()
active_alerts = {}
past_alerts = []
alert_id_counter = [0]
alert_callback = None


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
        "vt": vt or "\u2013", "vt_status": vt,
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


def verify_signature(path):
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
    wtd.dwUIChoice = 2
    wtd.fdwRevocationChecks = 0
    wtd.dwUnionChoice = 1
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
    if (rc & 0xFFFFFFFF) == 0x800B0100:
        return "NotSigned"
    return "Unverified"


def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None
