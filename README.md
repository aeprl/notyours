# notyours

real-time local session stealer detector for windows.

## what does it detect?
- browser profiles
- WMI subscriptions
- scheduled tasks
- suspicious processes
- clipboard (wallet keys)
- registry run keys
- startup folder
- defender exclusions
- archive staging
- DNS anomalies
- powershell spawns
- run / startup integrity
- unknown browser extensions 
- executable drops in TEMP
- TypeLib hijacks
- crypto wallet hijacking
- unrecognized screenshot capture
- antivirus kill attempts

## usage

- notyours is a **DETECTOR**, not an antivirus; it is highly sensitive and may frequently show unrecognized false-positives, especially after using scripts like win11debloat
- for processes, you can place your [virustotal api key ](https://www.virustotal.com/gui/my-apikey) and check hashes of each process to make sure the process is safe
- displays any unusual activity running in the background of your windows installation and prevent session stealers from accessing your computer by acting before of any data leaks
- alerts can be exported and checked manually or by LLMs to ensure whether alerts are critical and must be removed
- useful to use alongside [Farbar Recovery Scan Tool (FRST)](https://www.bleepingcomputer.com/download/farbar-recovery-scan-tool/) to add suspicious processes / registry edits to fixlist
- you can either run it straight through a python compiler or build it as an exe through build.bat

## disclaimer

- notyours does not actively delete ANY detection and is only used for alerts
- no piece of information collected in notyours goes anywhere outside of your computer
- the code is sloppy and heavily vibe coded as i made this quickly being the receiving end of a session hijacking attack

### reminder

- always check the integrity of the executables that you download
- when downloading less-than-legal software, always check that your source is reliable
- never ever do anything a captcha asks you to do outside its own tab, as alot of malware like [LummaC2](https://redcanary.com/threat-detection-report/threats/lummac2/) rely on user error to infect your desktop

## license
MIT
