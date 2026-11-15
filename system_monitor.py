import os
import subprocess
import winreg
from engine import is_whitelisted, verify_windows_signature


def _get_pid_names():
    """Возвращает словарь {pid: 'имя_процесса.exe'} для сетевого монитора."""
    mapping = {}
    try:
        out = subprocess.check_output(
            "tasklist /FO CSV /NH", shell=True, text=True, errors="ignore"
        )
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                mapping[parts] = parts
    except Exception:
        pass
    return mapping


def scan_running_processes():
    results = []
    try:
        cmd = (
            'powershell -NoProfile -Command '
            '"Get-CimInstance Win32_Process | '
            'Select-Object ProcessId,Name,ExecutablePath | '
            'ConvertTo-Csv -NoTypeInformation"'
        )
        out = subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
        for line in out.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 3:
                continue
            pid, name, path = parts, parts, parts
            if not path or not os.path.exists(path) or is_whitelisted(path):
                continue
            low = path.lower()
            if "\\appdata\\local\\programs\\" in low or "\\microsoft\\windowsapps\\" in low:
                continue

            score, reasons = 0, []
            sys_names = ("svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe")
            if name.lower() in sys_names and "\\windows\\" not in low:
                score += 90
                reasons.append(f"Поддельный системный процесс '{name}' вне Windows! (+90)")

            if not verify_windows_signature(path):
                score += 25
                reasons.append("Нет цифровой подписи (+25)")
                if any(k in low for k in ("\\temp\\", "\\downloads\\", "\\programdata\\")):
                    score += 55
                    reasons.append("Запущен из опасной папки Temp/Downloads/ProgramData (+55)")

            if score >= 80:
                results.append((
                    score,
                    "ПРОЦЕСС В ПАМЯТИ",
                    path,
                    reasons + [f"PID: {pid} | Имя: {name}"],
                    {"type": "process", "pid": pid, "path": path},
                ))
    except Exception:
        pass
    return results


def _scan_scheduled_tasks():
    """Проверяет Планировщик заданий Windows на скрытый запуск скриптов и вирусов."""
    findings = []
    try:
        out = subprocess.check_output(
            "schtasks /Query /FO CSV /V /NH", shell=True, text=True, errors="ignore"
        )
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 9:
                continue
            task_name, action = parts, parts
            if not task_name.startswith("\\") or task_name.startswith("\\Microsoft\\"):
                continue
            low = action.lower()
            score, reasons = 0, []
            if any(k in low for k in ("powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "-enc")):
                score += 60
                reasons.append("Задача планировщика запускает скрытый интерпретатор (+60)")
            if any(k in low for k in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\")):
                score += 30
                reasons.append("Запуск из временной/пользовательской папки (+30)")
            if score >= 80:
                findings.append((
                    score,
                    "ПЛАНИРОВЩИК ЗАДАНИЙ",
                    f"{task_name} -> {action}",
                    reasons,
                    {"type": "task", "task_name": task_name},
                ))
    except Exception:
        pass
    return findings


def _scan_hosts_file():
    """Проверяет системный файл hosts на подмену банковских и антивирусных сайтов."""
    findings = []
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    danger_domains = ("kaspersky", "drweb", "malwarebytes", "virustotal", "sberbank", "tinkoff", "vtb", "gosuslugi", "microsoft")
    try:
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    low = clean.lower()
                    if any(d in low for d in danger_domains):
                        findings.append((
                            90,
                            "ПОДМЕНА ФАЙЛА HOSTS",
                            f"{hosts_path} -> {clean}",
                            ["Блокировка или перенаправление важного домена в файле hosts (+90)"],
                            {"type": "hosts", "line": clean},
                        ))
    except Exception:
        pass
    return findings


def scan_autorun():
    findings = []
    regs = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    ]
    for hive, subkey, label in regs:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        v_name, v_data, _ = winreg.EnumValue(key, i)
                        i += 1
                        low = str(v_data).lower()
                        score, reasons = 0, []
                        if any(k in low for k in ("powershell", "cmd.exe", "wscript", "mshta", "rundll32", "-enc")):
                            score += 65
                            reasons.append("Скрытый запуск через командный интерпретатор (+65)")
                        if any(k in low for k in ("\\temp\\", "\\downloads\\", "\\programdata\\", "\\appdata\\")):
                            score += 25
                            reasons.append("Автозапуск из пользовательской/временной папки (+25)")
                        if score >= 80:
                            findings.append((
                                score,
                                "ОБЪЕКТ АВТОЗАПУСКА",
                                f"[{label}] {v_name} -> {v_data}",
                                reasons,
                                {"type": "autorun", "hive": hive, "subkey": subkey, "name": v_name},
                            ))
                    except OSError:
                        break
        except Exception:
            pass

    findings.extend(_scan_scheduled_tasks())
    findings.extend(_scan_hosts_file())
    return findings


def remove_autorun_entry(hive, subkey, value_name) -> bool:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except Exception:
        return False


def kill_process_by_pid(pid: str) -> bool:
    try:
        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def get_active_connections():
    conns = []
    pid_names = _get_pid_names()
    try:
        out = subprocess.check_output(
            "netstat -ano -p TCP", shell=True, text=True, errors="ignore"
        )
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 5 and p == "TCP" and p == "ESTABLISHED":
                local_addr, remote_addr, pid = p, p, p
                if not remote_addr.startswith(("127.0.0.1", "0.0.0.0", "[::1]")):
                    proc_name = pid_names.get(pid, "Неизвестно")
                    conns.append((f"{proc_name} (PID {pid})", local_addr, f"-> {remote_addr}"))
    except Exception:
        pass
    return conns
