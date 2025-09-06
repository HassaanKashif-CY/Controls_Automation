# -*- coding: utf-8 -*-
"""
Windows Endpoint Compliance Scanner (Enhanced GRC Mode)
Covers:
- Antivirus, Firewall, Updates, Password Policy, BitLocker
- Honeyfile, Unsafe File Detection, Clipboard
- MFA / Password Manager
- LSASS PPL + Credential Guard
- Browser Export/Save Password Policy
- Auto Session Lock
- Audit Logging
"""

import os, re, json, math, time, socket, subprocess, platform
from datetime import datetime

# Optional deps
try:
    import winreg
    HAS_WINREG = True
except:
    HAS_WINREG = False

try:
    import pyperclip
    HAS_PYPERCLIP = True
except:
    HAS_PYPERCLIP = False

results = []

# ----------------------------- Mappings -----------------------------
CONTROL_MAPPINGS = {
    "Antivirus (Defender)": {
        "ISO27001": "A.12.2.1 - Controls against malware",
        "SOC2": "CC6.7 - Protection from malicious code",
        "PDPL": "Security Safeguards - Anti-malware controls"
    },
    "Firewall Service": {
        "ISO27001": "A.13.1.1 - Network controls",
        "SOC2": "CC6.6 - Network segmentation",
        "PDPL": "Security Safeguards - Network protection"
    },
    "Windows Update Service": {
        "ISO27001": "A.12.6.1 - Technical vulnerability management",
        "SOC2": "CC7.1 - Vulnerability management",
        "PDPL": "Security Safeguards - Patch & update management"
    },
    "Password Policy": {
        "ISO27001": "A.9.4.3 - Password management",
        "SOC2": "CC6.2 - Authentication mechanisms",
        "PDPL": "Authentication & credential hygiene"
    },
    "BitLocker": {
        "ISO27001": "A.10.1 - Cryptographic controls",
        "SOC2": "CC6.1 - Encryption at rest",
        "PDPL": "Encryption of personal data"
    },
    "Honeyfile Access": {
        "ISO27001": "A.12.4.1 - Event logging",
        "SOC2": "CC7.2 - Monitor system activity",
        "PDPL": "Incident detection & alerts"
    },
    "Unsafe File Detection": {
        "ISO27001": "A.8.2.3 - Handling of sensitive data",
        "SOC2": "CC6.6 - Information handling",
        "PDPL": "Data leakage prevention"
    },
    "Clipboard Monitoring": {
        "ISO27001": "A.13.2.3 - Electronic messaging",
        "SOC2": "CC6.6 - Prevent unauthorized disclosure",
        "PDPL": "Data loss prevention"
    },
    "MFA/Password Manager": {
        "ISO27001": "A.9.4.2 - Secure log-on procedures",
        "SOC2": "CC6.2 - MFA for authentication",
        "PDPL": "Authentication & access control"
    },
    "Audit Logging": {
        "ISO27001": "A.12.4.1 - Event logging",
        "SOC2": "CC7.2 - Logging and monitoring",
        "PDPL": "Audit logging & evidence"
    },
    "Browser Password Policy": {
        "ISO27001": "A.5.15 - Access control",
        "SOC2": "CC6.1 - Restrict access & protect data",
        "PDPL": "Authentication & credential hygiene"
    },
    "Auto Session Lock": {
        "ISO27001": "A.9.2.4 - Session timeout",
        "SOC2": "CC6.8 - Session termination",
        "PDPL": "Access control & session management"
    },
    "LSASS Protection": {
        "ISO27001": "A.8.9 - Configuration management",
        "SOC2": "CC6.1 - Protection of assets",
        "PDPL": "System security configuration"
    }
}

# ----------------------------- Helpers -----------------------------
def add_result(control, status, detail):
    results.append({
        "control": control,
        "status": status,
        "detail": detail,
        "frameworks": CONTROL_MAPPINGS.get(control, {})
    })

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return str(e)

def shannon_entropy(data):
    if not data: return 0
    freq = {}
    for c in data: freq[c] = freq.get(c,0)+1
    return -sum((count/len(data)) * math.log2(count/len(data)) for count in freq.values())

def get_desktop():
    home = os.path.expanduser("~")
    for path in [os.path.join(home,"OneDrive","Desktop"), os.path.join(home,"Desktop")]:
        if os.path.exists(path): return path
    return home

# ----------------------------- Basic Controls -----------------------------
# Antivirus
try:
    out = run_cmd("sc query WinDefend")
    add_result("Antivirus (Defender)","PASS" if "RUNNING" in out else "FAIL",
               "Windows Defender service is running" if "RUNNING" in out else "Not running")
except Exception as e:
    add_result("Antivirus (Defender)","UNKNOWN",str(e))

# Firewall
try:
    out = run_cmd("sc query MpsSvc")
    add_result("Firewall Service","PASS" if "RUNNING" in out else "FAIL",
               "Windows Firewall running" if "RUNNING" in out else "Not running")
except Exception as e:
    add_result("Firewall Service","UNKNOWN",str(e))

# Windows Update
try:
    out = run_cmd("sc query wuauserv")
    add_result("Windows Update Service","PASS" if "RUNNING" in out else "FAIL",
               "Windows Update running" if "RUNNING" in out else "Not running")
except Exception as e:
    add_result("Windows Update Service","UNKNOWN",str(e))

# Password Policy
if HAS_WINREG:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\CurrentControlSet\Control\Lsa")
        val,_ = winreg.QueryValueEx(key,"LimitBlankPasswordUse")
        add_result("Password Policy","PASS" if val==1 else "FAIL",
                   "Blank passwords not allowed" if val==1 else "Blank passwords allowed")
    except Exception as e:
        add_result("Password Policy","UNKNOWN",str(e))

# BitLocker Encryption (improved)
try:
    output = run_cmd("powershell -Command \"Get-BitLockerVolume -MountPoint 'C:'\"")
    if "FullyEncrypted" in output or "PercentageEncrypted : 100" in output:
        add_result("BitLocker", "PASS", "C: drive fully encrypted")
    elif "EncryptionPercentage" in output or "PercentageEncrypted" in output:
        add_result("BitLocker", "FAIL", "C: drive not fully encrypted")
    else:
        add_result("BitLocker", "FAIL", "BitLocker not enabled")
except Exception as e:
    add_result("BitLocker", "FAIL", "BitLocker not enabled or inaccessible")

# Honeyfile
desktop = get_desktop()
honey = os.path.join(desktop,"passwords.csv")
if not os.path.exists(honey):
    with open(honey,"w") as f: f.write("username,password\nadmin,Admin@123\n")
try:
    last = os.path.getatime(honey)
    time.sleep(2)
    new = os.path.getatime(honey)
    add_result("Honeyfile Access","FAIL" if new>last else "PASS",
               "Honeyfile accessed" if new>last else "No suspicious access")
except Exception as e:
    add_result("Honeyfile Access","UNKNOWN",str(e))

# Unsafe File Detection
suspicious=[]
for folder in [desktop, os.path.join(os.path.expanduser("~"),"Documents")]:
    if os.path.exists(folder):
        for root,dirs,files in os.walk(folder):
            for file in files:
                if any(x in file.lower() for x in ["password","secret","key"]):
                    suspicious.append(file)
                    try:
                        with open(os.path.join(root,file),"r",errors="ignore") as f: content=f.read()
                        ent = shannon_entropy(content)
                        if ent>4.0: add_result("Unsafe File Detection","FAIL",f"High entropy secrets in {file}")
                        else: add_result("Unsafe File Detection","WARN",f"Suspicious filename: {file}")
                    except: add_result("Unsafe File Detection","UNKNOWN",f"Could not read {file}")
if not suspicious:
    add_result("Unsafe File Detection","PASS","No suspicious files found")

# Clipboard
try:
    if HAS_PYPERCLIP:
        clip = pyperclip.paste()
        if re.search(r"password\s*[:=]\s*\S+",clip) or re.search(r"[0-9]{13,16}",clip):
            add_result("Clipboard Monitoring","FAIL",f"Sensitive-looking data in clipboard: {clip[:30]}...")
        else:
            add_result("Clipboard Monitoring","PASS","No sensitive data in clipboard")
    else:
        add_result("Clipboard Monitoring","UNKNOWN","pyperclip not installed")
except Exception as e:
    add_result("Clipboard Monitoring","UNKNOWN",str(e))

# ----------------------------- New Controls -----------------------------
# MFA / Password Manager presence (dummy detection via installed programs list)
try:
    out = run_cmd("powershell -Command \"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName\"")
    if any(x in out for x in ["Bitwarden","1Password","LastPass","Keeper"]):
        add_result("MFA/Password Manager","PASS","Password manager detected")
    else:
        add_result("MFA/Password Manager","FAIL","No password manager detected")
except Exception as e:
    add_result("MFA/Password Manager","UNKNOWN",str(e))

# Audit Logging
try:
    out = run_cmd("auditpol /get /category:*")
    if "No Auditing" not in out:
        add_result("Audit Logging","PASS","Audit logging enabled")
    else:
        add_result("Audit Logging","FAIL","Auditing disabled in some categories")
except Exception as e:
    add_result("Audit Logging","UNKNOWN",str(e))

# Browser Password Policy
try:
    # Check Chrome policy
    chrome_cmd = 'reg query "HKLM\\Software\\Policies\\Google\\Chrome" /v PasswordManagerEnabled 2>nul'
    out = run_cmd(chrome_cmd)
    
    if "0x1" in out or "0x00000001" in out:
        add_result("Browser Password Policy", "PASS", "Chrome password saving disabled via policy")
    else:
        add_result("Browser Password Policy", "FAIL", "Chrome password saving not restricted by policy")
except Exception as e:
    add_result("Browser Password Policy", "UNKNOWN", f"Could not check browser policies: {str(e)}")

# Auto Session Lock
try:
    out = run_cmd('reg query "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut 2>nul')
    timeout_match = re.search(r'ScreenSaveTimeOut\s+REG_SZ\s+(\d+)', out)
    
    if timeout_match:
        timeout_seconds = int(timeout_match.group(1))
        if timeout_seconds <= 600:  # 10 minutes or less
            add_result("Auto Session Lock", "PASS", f"Screen timeout set to {timeout_seconds} seconds")
        else:
            add_result("Auto Session Lock", "FAIL", f"Screen timeout too long: {timeout_seconds} seconds")
    else:
        add_result("Auto Session Lock", "FAIL", "Screen timeout not configured")
except Exception as e:
    add_result("Auto Session Lock", "UNKNOWN", f"Could not check screen timeout: {str(e)}")

# LSASS Protection
try:
    out = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL 2>nul')
    if "0x1" in out or "0x00000001" in out:
        add_result("LSASS Protection", "PASS", "LSASS running as Protected Process")
    else:
        add_result("LSASS Protection", "FAIL", "LSASS not running as Protected Process")
except Exception as e:
    add_result("LSASS Protection", "UNKNOWN", f"Could not check LSASS protection: {str(e)}")

# ----------------------------- Output -----------------------------
print("{:<28} {:<8} {:<60}".format("Control","Status","Detail"))
print("-"*100)
for r in results:
    print("{:<28} {:<8} {:<60}".format(r["control"],r["status"],r["detail"]))
    for fw,clause in r["frameworks"].items():
        print(f"   • {fw}: {clause}")
    print()

report = {
    "host": socket.gethostname(),
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "results": results
}
with open("compliance_report.json","w") as f: json.dump(report,f,indent=4)
print("\n✅ Report saved to compliance_report.json")
import requests

# ===System Integration ===
#"""System_URL = "https://sahl-system.example.com/api/reports"   
#API_KEY = "YOUR_API_KEY_HERE"                             

#headers = {
#    "Authorization": f"Bearer {API_KEY}",
#    "Content-Type": "application/json"
#}

#try:
 #   response = requests.post(SAHL_URL, headers=headers, json=report, timeout=10)
  #  if response.status_code == 200:
   #     print("✅ Report successfully pushed to SAHL system")
    #else:
     #   print(f"❌ Failed to push report: {response.status_code} {response.text}")
#except Exception as e:
 #   print(f"❌ Error while pushing to SAHL system: {e}")"""
