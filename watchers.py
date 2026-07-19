import os, sys, time, json, re, threading, subprocess
import shutil, tempfile, winreg
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine import *

try:
    import win32clipboard
    _HAS_CLIPBOARD = True
except ImportError:
    _HAS_CLIPBOARD = False

BROWSER_PROFILE_PATHS = {
    "Chrome":  Path(os.environ.get("LOCALAPPDATA","")) / "Google/Chrome/User Data/Default",
    "Brave":   Path(os.environ.get("LOCALAPPDATA","")) / "BraveSoftware/Brave-Browser/User Data/Default",
    "Edge":    Path(os.environ.get("LOCALAPPDATA","")) / "Microsoft/Edge/User Data/Default",
    "Firefox": Path(os.environ.get("APPDATA",""))      / "Mozilla/Firefox/Profiles",
}
SENSITIVE_FILES = ["Cookies","Login Data","Web Data","Local State","sessions.sqlite","key4.db","logins.json"]
TRUSTED_BROWSER_EXES = {"chrome.exe","brave.exe","msedge.exe","firefox.exe"}
SUSPICIOUS_OUTBOUND_PROCESSES = {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","msiexec.exe","curl.exe","finger.exe","forfiles.exe","nltest.exe"}
WMI_POLL_INTERVAL  = 30
TASK_POLL_INTERVAL = 60

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

DNS_POLL_INTERVAL    = 120
DNS_SPIKE_MIN    = 15
DNS_SPIKE_FACTOR = 2.5

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

DROP_EXTS = {".exe", ".dll", ".bat", ".vbs", ".ps1", ".js", ".jse",
             ".scr", ".com", ".cmd", ".iso"}
DROP_WATCH_DIRS = []
for d in list(TEMP_WATCH_DIRS) + [
    os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")]:
    if d and os.path.isdir(d) and d.lower() not in [x.lower() for x in DROP_WATCH_DIRS]:
        DROP_WATCH_DIRS.append(d)
INSTALLER_EXES = {"setup.exe", "install.exe", "uninst.exe", "msiexec.exe",
                    "nsis.exe", "innoextract.exe", "spoon.exe"} | ARCHIVER_EXES

TYPELIB_KEY = (winreg.HKEY_CURRENT_USER, "HKCU",
                 r"Software\Classes\TypeLib")

BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
if getattr(sys, "frozen", False):
    BASELINE_PATH = os.path.join(os.path.dirname(sys.executable), "baseline.json")

WALLET_FILES = {"wallet.dat", "wallet.json", "wallet.wallet", ".wallet",
                 "wallet_keys.json", "mnemonic.txt", "seed.txt", "keystore"}
WALLET_DIRS = ("bitcoin", "litecoin", "dogecoin", "dash", "monero", "zcash",
                "electrum", "exodus", "atomic wallet", "guarda", "jaxx",
                "coinomi", "wasabi", "samourai", "multibit", "armory",
                "ethereum", "keystore", "ledger live",
                "trezor", "crypto wallets", "crypto-wallets")

WALLET_PATH_INCLUDES = ("metamask",
                          "nkbihfbeogaeaoehlefnkodbefgpgknn",
                          "localextensionsettings")
WALLET_BENIGN = {"chrome.exe","msedge.exe","firefox.exe","brave.exe",
                  "opera.exe","electron.exe","msiexec.exe","explorer.exe",
                  "dllhost.exe","svchost.exe","searchui.exe",
                  "shellexperiencehost.exe","runtimebroker.exe",
                  "applicationframehost.exe","onedrive.exe","dropbox.exe",
                   "discord.exe"}

def _is_wallet_path(path):
    low = path.lower()
    if os.path.basename(low) in WALLET_FILES:
        return True
    parts = [p.lower() for p in Path(low).parts]
    if any(d in parts for d in WALLET_DIRS):
        return True
    return any(s in low for s in WALLET_PATH_INCLUDES)

SCREEN_EXTS = {".png",".bmp",".jpg",".jpeg",".gif",".tif",".tiff"}
SCREEN_TOOLS = {"snippingtool.exe","sharex.exe","greenshot.exe","snagit.exe",
                "lightshot.exe","picpick.exe","screenpresso.exe","obs.exe",
                "obs64.exe","onedrive.exe","dropbox.exe","discord.exe"}
SCREEN_MIN_BYTES = 15000

AV_TOOLS = {"avastui.exe","avastsvc.exe","afwserv.exe","wireshark.exe",
            "ngui.exe","mbam.exe","mbamservice.exe","msmpeng.exe","msmpsvc.exe",
            "nortonsecurity.exe","mcshield.exe","bdagent.exe","kaspersky.exe",
            "f-secure.exe","ekrn.exe","avgui.exe","sophosui.exe","defender.exe",
            "securityhealthsystray.exe"}

WHITELIST_BUILTIN_TASKS = True

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

}

def is_builtin_task(name):
    return name.lower().strip() in WINDOWS_BUILTIN_TASKS or \
           any(name.lower().startswith(p) for p in [
               "onedrive","microsoft-windows","windows defender",".net framework",
               "adobe","nvidia","intel","amd","realtek"
           ])

PROCESS_QUERY_INFORMATION = 0x0400

_open_files_queue = []
_open_files_lock  = threading.Lock()

def _open_files_checker():
    """Background thread: drain _open_files_queue and do the expensive open_files() check."""
    while True:
        time.sleep(1)  
        with _open_files_lock:
            items = list(_open_files_queue)
            _open_files_queue.clear()
        if not items or not MONITOR_ENABLED["browser"]:
            continue
        seen_paths = set()
        for filepath, browser_name in items:
            fp_low = filepath.lower()
            if fp_low in seen_paths:
                continue
            seen_paths.add(fp_low)
            try:
                for proc in psutil.process_iter(['pid','name','exe']):
                    try:
                        pname = (proc.info['name'] or "").lower()
                        if pname in TRUSTED_BROWSER_EXES:
                            continue
                        for f in proc.open_files():
                            if fp_low in f.path.lower():
                                raise_alert("HIGH","Browser Profile Access",
                                    f"{proc.info['name']} (PID {proc.pid}) reading {Path(filepath).name}",
                                    f"Browser: {browser_name} | EXE: {proc.info.get('exe','unknown')}",
                                    exe_path=proc.info.get('exe'))
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                try: log_error("watchers", "_open_files_checker failed")
                except Exception: pass

class BrowserProfileHandler(FileSystemEventHandler):
    def __init__(self, browser_name):
        self.browser_name = browser_name
    def on_modified(self, event):
        if event.is_directory: return
        if Path(event.src_path).name in SENSITIVE_FILES:
            with _open_files_lock:
                _open_files_queue.append((event.src_path, self.browser_name))

def start_file_watchers():
    observers = []

    browser_obs = Observer()
    for browser, path in BROWSER_PROFILE_PATHS.items():
        watch_path = path if browser != "Firefox" else path.parent
        if watch_path.exists():
            browser_obs.schedule(BrowserProfileHandler(browser), str(watch_path), recursive=True)
    browser_obs.start()
    observers.append(browser_obs)

    persistence_obs = Observer()
    handler = PersistenceHandler()
    seen_persistence = set()
    for folder in STARTUP_FOLDERS + TEMP_WATCH_DIRS:
        key = os.path.normcase(folder)
        if key not in seen_persistence and os.path.isdir(folder):
            seen_persistence.add(key)
            recursive = folder not in STARTUP_FOLDERS
            persistence_obs.schedule(handler, folder, recursive=recursive)
    persistence_obs.start()
    observers.append(persistence_obs)

    if EXTENSION_DIRS:
        ext_obs = Observer()
        ext_handler = ExtensionHandler()
        for folder in EXTENSION_DIRS:
            ext_obs.schedule(ext_handler, folder, recursive=False)
        ext_obs.start()
        observers.append(ext_obs)

    if DROP_WATCH_DIRS:
        drop_obs = Observer()
        drop_handler = DropHandler()
        seen_drop = set()
        for folder in DROP_WATCH_DIRS:
            key = os.path.normcase(folder)
            if key not in seen_drop and os.path.isdir(folder):
                seen_drop.add(key)
                drop_obs.schedule(drop_handler, folder, recursive=True)
        drop_obs.start()
        observers.append(drop_obs)

    if TEMP_WATCH_DIRS:
        screen_obs = Observer()
        screen_handler = ScreenshotHandler()
        seen_screen = set()
        for folder in TEMP_WATCH_DIRS:
            key = os.path.normcase(folder)
            if key not in seen_screen and os.path.isdir(folder):
                seen_screen.add(key)
                screen_obs.schedule(screen_handler, folder, recursive=True)
        screen_obs.start()
        observers.append(screen_obs)

    return observers

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

PYTHON_EXE_NAMES = ("python.exe", "pythonw.exe", "python3.exe", "python38.exe",
                   "python39.exe", "python310.exe", "python311.exe",
                   "python312.exe", "python313.exe", "python314.exe",
                   "pythonservice.exe", "pypy.exe", "pypy3.exe")

def _python_good_roots():
    roots = [r"C:\Python", r"C:\Program Files\Python",
             r"C:\Program Files (x86)\Python"]
    la = os.environ.get("LOCALAPPDATA", "")
    if la:
        roots.append(os.path.join(la, "Programs", "Python"))
    up = os.environ.get("USERPROFILE", "")
    if up:
        roots.append(os.path.join(up, "AppData", "Local", "Microsoft", "WindowsApps"))
    return [r.rstrip("\\").lower() for r in roots]

PYTHON_GOOD_ROOTS = _python_good_roots()

def _user_writable_dirs():
    dirs = []
    for v in ("APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE"):
        d = os.environ.get(v, "")
        if d:
            dirs.append(d.rstrip("\\").lower())
            if v == "USERPROFILE":
                dirs.append(os.path.join(d, "Downloads").lower())
    return dirs

def _is_exe_from_user_writable(exe_path):
    if not exe_path:
        return False
    pl = exe_path.lower()
    for d in _user_writable_dirs():
        if pl.startswith(d):
            return True
    return False

_PUP_MARKERS = ("setup.exe", "install.exe", "uninst.exe", "nsis", "innoextract",
                "spoon", "pc app store", "bit guardian", "pdf", "launcher",
                "getsoftware", "update.exe")

def _is_suspicious_python(pname, pexe):
    if pname not in PYTHON_EXE_NAMES:
        return False
    if not pexe:
        return True
    pl = pexe.lower()
    for r in PYTHON_GOOD_ROOTS:
        if pl.startswith(r):
            return False
    for d in _user_writable_dirs():
        if pl.startswith(d):
            return True
    return False

def _python_alert_level(parent_name, pexe):
    pn = (parent_name or "").lower()
    if any(m in pn for m in _PUP_MARKERS):
        return "CRITICAL", (
            f"Python interpreter launched by likely PUP/installer '{pn}'. "
            "PyInstaller/PyArmor stealer payloads (e.g. Amber Albatross) "
            "are delivered this way via PUAs like PC App Store / Bit Guardian.")
    return "HIGH", (
        "Unexpected Python interpreter running from a user-writable path "
        f"({pexe}). PyInstaller/PyArmor stealer payloads commonly appear "
        "as python.exe under AppData/Temp.")

def self_defense():
    exe = sys.executable
    backup = exe + ".bak"
    if getattr(sys, "frozen", False):
        try:
            if not os.path.exists(backup):
                shutil.copy2(exe, backup)
        except Exception:
            pass
    while True:
        time.sleep(15)
        if not os.path.exists(exe):
            raise_alert("CRITICAL", "AV Kill Attempt",
                        f"notyours executable deleted: {exe}",
                        "Malware may have deleted notyours to evade detection.")
            try:
                if os.path.exists(backup):
                    subprocess.Popen([backup], creationflags=CREATE_NO_WINDOW)
            except Exception:
                pass
            break

def _check_wmi_new_process(p):
    """Handle a WMI Win32_Process creation event."""
    try:
        pid = p.ProcessId
        name = p.Name
        exe_path = p.ExecutablePath
        cmdline = p.CommandLine or ""
        ppid = p.ParentProcessId
        if not name or not exe_path:
            return
        nl = name.lower()
        el = exe_path.lower()
        if nl in ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe"):
            try:
                parent = psutil.Process(ppid) if ppid else None
                if parent and parent.name().lower() in PSPAWN_SUSPICIOUS_PARENTS:
                    score_event("powershell_spawn","PowerShell Spawn",
                        f"{name} spawned by {parent.name()}",
                        exe_path=exe_path,
                        detail=f"Script host launched from suspicious parent: {parent.name()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if nl in ("python.exe","python3.exe","py.exe"):
            if _is_suspicious_python(name, exe_path):
                pn = ""
                try:
                    parent = psutil.Process(ppid) if ppid else None
                    pn = parent.name() if parent else ""
                except Exception:
                    pass
                level, reason = _python_alert_level(pn, exe_path)
                score_event("process_from_temp","Suspicious Processes",
                    f"Python '{name}' running from {exe_path}",
                    exe_path=exe_path, detail=f"Reason: {reason}")
        if nl == "msiexec.exe" and ("://" in cmdline or "\\\\" in cmdline):
            score_event("outbound_connection","Suspicious Network",
                f"msiexec remote MSI: {cmdline[:100]}",
                exe_path=exe_path,
                detail="msiexec.exe installing from remote URL — possible lateral movement.")
        if nl == "curl.exe":
            score_event("process_from_temp","Suspicious Network",
                f"curl.exe: {cmdline[:100]}",
                exe_path=exe_path,
                detail="curl.exe running — possible script download.")
        if nl == "nltest.exe":
            score_event("dns_anomaly","Suspicious Network",
                "nltest.exe running — domain reconnaissance",
                exe_path=exe_path)
        if nl == "rundll32.exe":
            cmdline = cmdline or ""
            parts = cmdline.split()
            for part in parts:
                clean = part.strip('"\'')
                if clean.lower().endswith(".dll") and _is_exe_from_user_writable(clean):
                    score_event("process_from_temp","Suspicious Processes",
                        f"rundll32.exe loading DLL from user-writable path: {clean[:60]}",
                        exe_path=exe_path,
                        detail="rundll32 loading a DLL from AppData/Temp indicates CleanUpLoader DLL sideloading.")
                    break
        if nl in ("vssadmin.exe",):
            if "delete shadows" in cmdline.lower():
                score_event("shadow_copy_deletion","Ransomware",
                    f"vssadmin.exe deleting shadow copies: {cmdline[:100]}",
                    exe_path=exe_path,
                    detail="Shadow copy deletion is a hallmark ransomware precursor.")
        if nl in ("wmic.exe",):
            cl = cmdline.lower()
            if "shadowcopy" in cl and "delete" in cl:
                score_event("shadow_copy_deletion","Ransomware",
                    f"wmic.exe deleting shadow copies: {cmdline[:100]}",
                    exe_path=exe_path,
                    detail="WMIC shadow copy deletion is a hallmark ransomware precursor.")
        if nl in ("diskshadow.exe",):
            score_event("shadow_copy_deletion","Ransomware",
                f"diskshadow.exe running: {cmdline[:100]}",
                exe_path=exe_path,
                detail="diskshadow execution may indicate ransomware (manipulates Volume Shadow Copies).")
        _check_wallet_on_process(nl, el, pid)
    except Exception:
        try: log_error("watchers", "WMI process callback failed")
        except Exception: pass

def _check_wmi_deleted_process(p):
    """Handle a WMI Win32_Process deletion event — AV kill detection."""
    try:
        name = p.Name.lower() if p.Name else ""
        if name in AV_TOOLS:
            score_event("self_defense_trigger","AV Kill Attempt",
                f"AV process terminated: {p.Name}",
                detail="An antimalware or analysis tool process was stopped. "
                       "This may indicate a kill-switch by infostealer malware.")
    except Exception:
        try: log_error("watchers", "WMI deletion callback failed")
        except Exception: pass

def _check_wallet_on_process(name_lower, exe_path, pid):
    """Quick wallet check on process creation — no full file-scan."""
    try:
        if name_lower in ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe"):
            return
        if name_lower in WALLET_BENIGN:
            return
        if any(w in exe_path.lower() for w in ("metamask","nkbihfbeogaeaoehlefnkodbefgpgknn")):
            score_event("wallet_access","Wallet Access",
                f"Unknown process accessing wallet: {name_lower}",
                exe_path=exe_path,
                detail="A non-benign process has wallet-related content in its path.")
    except Exception:
        try: log_error("watchers", "_check_wallet_on_process failed")
        except Exception: pass

def start_wmi_process_monitor():
    """Subscribe to WMI process creation/deletion events. Returns True on success."""
    try:
        import wmi
        c = wmi.WMI()
    except Exception:
        try: log_error("watchers", "WMI import failed — WMI monitoring disabled")
        except Exception: pass
        return False
    def _creation_loop():
        try:
            watcher = c.watch_for(notification_type="Creation",
                                  wmi_class="Win32_Process", delay_secs=1)
            while True:
                _check_wmi_new_process(watcher())
        except Exception:
            try: log_error("watchers", "WMI creation loop crashed — process creation monitoring stopped")
            except Exception: pass
    def _deletion_loop():
        try:
            watcher = c.watch_for(notification_type="Deletion",
                                  wmi_class="Win32_Process", delay_secs=1)
            while True:
                _check_wmi_deleted_process(watcher())
        except Exception:
            try: log_error("watchers", "WMI deletion loop crashed — process deletion monitoring stopped")
            except Exception: pass
    threading.Thread(target=_creation_loop, daemon=True).start()
    threading.Thread(target=_deletion_loop, daemon=True).start()
    return True


CRYPTO_PATTERNS = ["1A1z","3J98","bc1q","0x","T9yD","r3GYT"]

def clipboard_monitor(root):
    last = ""; flagged = False
    while True:
        if MONITOR_ENABLED["clipboard"]:
            try:
                if root is None:
                    if _HAS_CLIPBOARD:
                        try:
                            win32clipboard.OpenClipboard()
                            try:
                                current = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                            except TypeError:
                                current = ""
                            win32clipboard.CloseClipboard()
                        except Exception:
                            current = ""
                    else:
                        current = ""
                else:
                    current = root.clipboard_get()
                if current != last:
                    last = current
                    is_crypto = any(current.startswith(p) and len(current)>25 for p in CRYPTO_PATTERNS)
                    if is_crypto and not flagged:
                        flagged = True
                        score_event("clipboard_crypto", "Clipboard",
                            "Possible crypto address in clipboard — verify it hasn't been swapped",
                                        detail=f"Value starts with: {current[:20]}...")
                    elif not is_crypto and flagged:
                        flagged = False
                        resolve_alert("Clipboard","Possible crypto address in clipboard — verify it hasn't been swapped")
            except Exception:
                try: log_error("watchers", "clipboard_monitor failed")
                except Exception: pass
        time.sleep(2)

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


KNOWN_GOOD_RUN = {
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

def check_run_entry(value):
    """Return (verdict, detail) for a Run-key command value."""
    exe, host = parse_run_target(value)
    if host and (not exe or not os.path.exists(exe)):

        resolved = shutil.which(exe) if exe else None
        if resolved:
            exe = resolved
    if host:
        return ("suspicious", f"{host} launched from Run key: {value[:60]}")

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

        pass
    return found


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

            if p.name.startswith("__PSScriptPolicyTest_"):
                return
            if installer_running() or archiver_running():
                return
            low = str(p).lower()
            if (os.path.basename(low) in ("prefs-1.js", "prefs.js")
                    or "\\mozilla\\" in low or "firefox" in low
                    or "default-release" in low or "defaultagent" in low):
                return
            if verify_signature(event.src_path) == "Valid":
                return
            downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads").lower()
            if downloads and str(p.parent).lower().startswith(downloads):
                return
            folder = os.path.basename(os.path.dirname(p))
            drop_dir = str(p.parent)
            folder_lower = str(p.parent).lower()
            is_appdata = "\\appdata\\" in folder_lower or "\\temp\\" in folder_lower
            score_event("unsigned_drop", "Executable Drop",
                        f"New {p.suffix.lower()} in {folder}: {p.name}",
                        exe_path=str(p),
                        detail="Unexpected unsigned executable/script dropped into a temp/user "
                               "directory by a non-installer process.",
                        extra={"drop_dir": drop_dir})
            if is_appdata:
                score_event("file_drop_appdata", "Executable Drop",
                            f"AppData drop in {folder}: {p.name}",
                            exe_path=str(p))
        except Exception:
            pass

    def on_deleted(self, event):
        if event.is_directory:
            return
        if not MONITOR_ENABLED["drop"]:
            return
        try:
            p = Path(event.src_path)
            if p.suffix.lower() not in DROP_EXTS:
                return
            folder = os.path.basename(os.path.dirname(p))
            resolve_alert("Executable Drop",
                          f"New {p.suffix.lower()} in {folder}: {p.name}")
        except Exception:
            pass

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

def _wait_reg_change(hive, subkey, watch_subtree=True):
    """Block until registry key changes (native RegNotifyChangeKeyValue via ctypes)."""
    from ctypes import WinDLL, wintypes, get_last_error
    _advapi32 = WinDLL('advapi32', use_last_error=True)
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_NOTIFY)
        _filter = winreg.REG_NOTIFY_CHANGE_NAME | winreg.REG_NOTIFY_CHANGE_LAST_SET
        rc = _advapi32.RegNotifyChangeKeyValue(
            int(key), watch_subtree, _filter, None, False
        )
        key.Close()
        return rc == 0
    except Exception:
        return False

def _run_key_check(known):
    """Compare current run-key state to known, emit alerts for changes. Returns new known."""
    current = get_reg_run_entries()
    if not MONITOR_ENABLED["registry"]:
        return current
    for key, value in current.items():
        if key not in known:
            label, subkey, name = key
            raise_reg_run(label, subkey, name, value)
    for key in list(known):
        if key not in current:
            label, subkey, name = key
            resolve_alert("Registry Run Key",
                         f"Run-key entry '{name}' in {label}\\{subkey}")
    return current

def _watch_reg_key_loop(hive, subkey, label, check_fn, poll_ms=5000):
    """Thread: wait for registry change on a single key, call check_fn when triggered."""
    while True:
        if not _wait_reg_change(hive, subkey):
            time.sleep(poll_ms / 1000)
            continue
        check_fn()

def _reg_run_watcher():
    """Event-driven replacement for registry_run_monitor."""
    known = get_reg_run_entries()
    if MONITOR_ENABLED["registry"]:
        for (label, subkey, name), value in known.items():
            try:
                raise_reg_run(label, subkey, name, value)
            except Exception:
                pass
    reg_run_lock = threading.Lock()
    for hive, label, sk in REG_RUN_KEYS:
        def check():
            nonlocal known
            with reg_run_lock:
                known = _run_key_check(known)
        threading.Thread(target=_watch_reg_key_loop,
                         args=(hive, sk, label, check), daemon=True).start()

def _defender_excl_watcher():
    """Event-driven replacement for defender_exclusion_monitor."""
    known = get_defender_exclusions()
    hive, label, sk = DEFENDER_EXCL_KEY
    def check():
        nonlocal known
        if not MONITOR_ENABLED["defender"]:
            known = get_defender_exclusions()
            return
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
    threading.Thread(target=_watch_reg_key_loop,
                     args=(hive, sk, label, check), daemon=True).start()

def _integrity_watcher():
    """Event-driven replacement for integrity_monitor."""
    baseline = load_baseline()
    if baseline is None or "run" not in baseline:
        save_baseline(_snapshot_integrity())
        baseline = load_baseline() or {"run": {}, "startup": {}}
    if "run" not in baseline:
        baseline["run"] = {}
    if "startup" not in baseline:
        baseline["startup"] = {}
    known_run = get_reg_run_entries()
    known_tl = set(get_typelib_entries().keys())
    integrity_lock = threading.Lock()
    def check_run():
        nonlocal baseline, known_run
        with integrity_lock:
            if not MONITOR_ENABLED["integrity"]:
                baseline = _snapshot_integrity()
                known_run = get_reg_run_entries()
                return
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
                                f"Hash changed (old {baseline['startup'][sf][:12]} \u2192 "
                                f"new {h[:12]}) \u2014 possible tampering.")
            baseline = current
            save_baseline(baseline)
        known_run = get_reg_run_entries()
    def check_tl():
        nonlocal baseline, known_tl
        if not MONITOR_ENABLED["integrity"]:
            known_tl = set(get_typelib_entries().keys())
            return
        current_set = set(get_typelib_entries().keys())
        if current_set != known_tl:
            baseline = _snapshot_integrity()
            save_baseline(baseline)
            known_tl = current_set
    for hive, label, sk in REG_RUN_KEYS:
        threading.Thread(target=_watch_reg_key_loop,
                         args=(hive, sk, label, check_run), daemon=True).start()
    hive_tl = TYPELIB_KEY[0]
    sk_tl = TYPELIB_KEY[2]
    threading.Thread(target=_watch_reg_key_loop,
                     args=(hive_tl, sk_tl, "TYPELIB", check_tl), daemon=True).start()

def _typelib_watcher():
    """Event-driven replacement for typelib_monitor."""
    baseline = load_baseline() or {}
    tl_base = baseline.get("typelib")
    if tl_base is None:
        tl_base = list(get_typelib_entries().keys())
        baseline["typelib"] = tl_base
        save_baseline(baseline)
    known = set(tl_base)
    hive, label, sk = TYPELIB_KEY
    def check():
        nonlocal known
        if not MONITOR_ENABLED["typelib"]:
            known = set(get_typelib_entries().keys())
            return
        current = set(get_typelib_entries().keys())
        for name in current - known:
            raise_alert("HIGH", "TypeLib Hijack",
                        f"New TypeLib entry: {name}",
                        "HKCU\\Software\\Classes\\TypeLib modification is an "
                        "emerging infostealer persistence / hijack technique.")
        known = current
        bl = load_baseline() or {}
        bl["typelib"] = list(known)
        save_baseline(bl)
    threading.Thread(target=_watch_reg_key_loop,
                     args=(hive, sk, label, check), daemon=True).start()

def start_registry_monitors():
    """Start event-driven registry watchers. Replaces 4 polling monitors."""
    _reg_run_watcher()
    _defender_excl_watcher()
    _integrity_watcher()
    _typelib_watcher()


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
