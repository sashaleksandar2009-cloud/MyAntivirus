import os, subprocess, winreg
from engine import is_whitelisted, verify_windows_signature

def scan_running_processes():
    results = []
    try:
        cmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Csv -NoTypeInformation"'
        out = subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
        for line in out.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 3: continue
            pid, name, path = parts, parts, parts
            if not path or not os.path.exists(path) or is_whitelisted(path): continue
            low = path.lower()
            if "\\appdata\\local\\programs\\" in low or "\\microsoft\\windowsapps\\" in low: continue

            score, reasons = 0, []
            if name.lower() in ("svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe") and "\\windows\\" not in low:
                score += 85; reasons.append(f"Поддельный системный процесс '{name}' вне Windows! (+85)")

            if not verify_windows_signature(path):
                score += 25; reasons.append("Нет цифровой подписи (+25)")
                if any(k in low for k in ("\\temp\\", "\\downloads\\", "\\programdata\\")):
                    score += 55; reasons.append("Запущен из опасной папки Temp/Downloads/ProgramData (+55)")

            if score >= 80:
                results.append((score, "ВЫСОКАЯ ОПАСНОСТЬ", f"[PID {pid}] {name} -> {path}", reasons, pid))
    except Exception:
        pass
    return results

def scan_autorun():
    findings = []
    regs = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    ]
    for hive, subkey, label in regs:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        v_name, v_data, _ = winreg.EnumValue(key, i); i += 1
                        low = str(v_data).lower()
                        score, reasons = 0, []
                        if any(k in low for k in ("powershell", "cmd.exe", "wscript", "mshta", "-enc")):
                            score += 65; reasons.append("Скрытый запуск через командный интерпретатор (+65)")
                        if any(k in low for k in ("\\temp\\", "\\downloads\\", "\\programdata\\")):
                            score += 25; reasons.append("Автозапуск из временной/системной папки (+25)")
                        if score >= 80:
                            findings.append((score, "ПОДОЗРИТЕЛЬНАЯ АВТОЗАГРУЗКА", f"[{label}] {v_name}: {v_data}", reasons))
                    except OSError:
                        break
        except Exception:
            pass
    return findings

def get_active_connections():
    conns = []
    try:
        out = subprocess.check_output("netstat -ano -p TCP", shell=True, text=True, errors="ignore")
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 5 and p == "TCP" and p == "ESTABLISHED":
                if not p.startswith(("127.0.0.1", "0.0.0.0", "[::1]")):
                    conns.append(f"PID {p:<6} | Локальный: {p:<22} -> Внешний: {p}")
    except Exception:
        pass
    return conns
