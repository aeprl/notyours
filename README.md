# Session Stealer Detector

A real-time Windows security monitor that detects common session stealer tactics.

## What it monitors
- **Browser profile access** — alerts if any non-browser process reads your Chrome/Brave/Edge/Firefox cookies or login data
- **WMI subscriptions** — polls every 30s for new WMI event subscriptions (the exact technique used in your infection)
- **Scheduled tasks** — alerts on any newly created scheduled task
- **Suspicious process network connections** — watches PowerShell, cmd, wscript etc. for outbound connections
- **Clipboard** — detects possible crypto address swapping

## Setup
1. Install Python 3.10+
2. Install dependencies:
   ```
   pip install psutil watchdog
   ```
3. Run as Administrator:
   ```
   python detector.py
   ```

## To build as a standalone .exe
```
pip install pyinstaller
pyinstaller --onefile --windowed --icon=NONE detector.py
```
The .exe will be in the `dist/` folder.

## Notes
- Must be run as Administrator for full WMI and process access
- WMI polling runs every 30 seconds
- Scheduled task polling runs every 60 seconds
- Alerts can be exported to JSON via the Export button
