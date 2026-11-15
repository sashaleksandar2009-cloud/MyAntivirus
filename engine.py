import base64, ctypes, hashlib, json, math, os, re, sys, zipfile, pefile
from ctypes import wintypes
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
SIG_DB = os.path.join(BASE_DIR, "signatures.json")

PE_EXTS = (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx")
SCRIPT_EXTS = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".vbe", ".hta", ".wsf")
EICAR = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE"

SAFE_NAMES = ("unins000.exe", "unins001.exe", "uninstall.exe", "update.exe", "squirrel.exe", "setup.exe")
LEGIT_MZ = (".mui", ".pyd", ".ocx", ".ax", ".cpl", ".efi", ".drv", ".winmd", ".tlb", ".asi", ".bpl", ".ime", ".acm", ".node", ".tmp", ".msi", ".quarantined")
EXCL_DIRS = (
    "\\microsoft\\windowsapps\\",
    "\\appdata\\local\\programs\\",
    "\\microsoft\\office\\solutionpackages\\",
    "\\code\\user\\history\\",
    "\\_quarantine\\",
    "\\__pycache__\\",
    "\\.git\\",
    "\\roblox\\downloads\\",
)
EXCL_PREF = ("c:\\windows\\", "c:\\$winreagent\\", "c:\\program files\\windowsapps\\")

APIS = {
    b"RtlDecompressBuffer": (20, "Распаковка кода в памяти"),
    b"CryptDecrypt": (15, "Расшифровка данных"),
    b"CryptUnprotectData": (40, "Кража паролей/куки браузеров (DPAPI)"),
    b"CreateProcessW": (10, "Запуск процессов"),
    b"CreateProcessA": (10, "Запуск процессов (ANSI)"),
    b"ShellExecuteExW": (15, "Выполнение внешних команд"),
    b"URLDownloadToFileW": (35, "Скачивание файла из сети"),
    b"URLDownloadToFileA": (35, "Скачивание файла из сети"),
    b"InternetOpenUrlW": (20, "Прямой сетевой запрос к URL"),
    b"WinHttpOpen": (15, "Сетевой стек WinHTTP"),
    b"VirtualAlloc": (15, "Выделение исполняемой памяти"),
    b"VirtualAllocEx": (25, "Выделение памяти в чужом процессе"),
    b"WriteProcessMemory": (35, "Запись в память чужом процессе"),
    b"CreateRemoteThread": (35, "Запуск потока в чужом процессе"),
    b"NtUnmapViewOfSection": (45, "Подмена кода процесса (Process Hollowing)"),
    b"SetThreadContext": (30, "Изменение контекста потока (Injection)"),
    b"SetWindowsHookExW": (30, "Перехват ввода (Кейлоггер)"),
    b"GetAsyncKeyState": (25, "Чтение нажатий клавиш (Кейлоггер)"),
    b"AdjustTokenPrivileges": (25, "Повышение системных привилегий"),
    b"IsDebuggerPresent": (15, "Обнаружение отладчика (Anti-Debug)"),
    b"CheckRemoteDebuggerPresent": (20, "Защита от анализа (Anti-Debug)"),
    b"RegSetValueExW": (15, "Модификация реестра"),
}

API_COMBOS = [
    ({b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"}, 50, "КРИТИЧЕСКАЯ ЦЕПОЧКА: Remote Thread Injection"),
    ({b"NtUnmapViewOfSection", b"WriteProcessMemory", b"SetThreadContext"}, 60, "КРИТИЧЕСКАЯ ЦЕПОЧКА: Process Hollowing"),
    ({b"CryptUnprotectData", b"InternetOpenUrlW"}, 45, "КРИТИЧЕСКАЯ ЦЕПОЧКА: Стиллер (DPAPI + Сеть)"),
    ({b"CryptUnprotectData", b"WinHttpOpen"}, 45, "КРИТИЧЕСКАЯ ЦЕПОЧКА: Стиллер (DPAPI + WinHTTP)"),
    ({b"SetWindowsHookExW", b"GetAsyncKeyState"}, 35, "ЦЕПОЧКА: Перехват нажатий клавиатуры"),
]

SCRIPT_SIGS = [
    ("invoke-webrequest", 35, "Загрузка из сети (PowerShell)"),
    ("invoke-expression", 40, "Динамическое выполнение кода (IEX)"),
    ("iex(", 40, "Скрытый вызов Invoke-Expression"),
    ("downloadstring", 45, "Запуск вредоносного скрипта в памяти"),
    ("downloadfile", 35, "Скачивание файла через .NET"),
    ("certutil -urlcache", 45, "Скачивание через certutil"),
    ("bitsadmin /transfer", 45, "Скрытая загрузка через bitsadmin"),
    ("mshta http", 50, "Запуск удаленного HTA-скрипта"),
    ("powershell -enc", 45, "Зашифрованный запуск PowerShell"),
    ("frombase64string", 30, "Декодирование Base64 нагрузки"),
    ("add-mppreference", 55, "Отключение Защитника Windows"),
    ("set-mppreference", 55, "Изменение настроек Защитника Windows"),
    ("vssadmin delete shadows", 70, "Удаление теневых копий (Шифровальщик)"),
    ("wbadmin delete catalog", 70, "Уничтожение резервных копий (Шифровальщик)"),
    ("bcdedit /set {default} recoveryenabled no", 70, "Блокировка восстановления Windows"),
]

PACKER_SECTIONS = (b"upx", b".vmp", b".enigma", b".aspack", b".petite", b".themida", b".nsp")
_DB, _MT = None, 0.0

def load_db():
    global _DB, _MT
    try:
        mt = os.path.getmtime(SIG_DB)
        if _DB is not None and mt == _MT: return _DB
        with open(SIG_DB, "r", encoding="utf-8") as f:
            _DB, _MT = json.load(f), mt
            return _DB
    except Exception:
        return {"malware_hashes_sha256": {}, "dangerous_strings": [], "whitelist_paths": []}

def add_to_whitelist(p: str):
    db, norm = load_db(), os.path.abspath(p).lower()
    if norm not in db.get("whitelist_paths", []):
        db.setdefault("whitelist_paths", []).append(norm)
        with open(SIG_DB, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)

def is_whitelisted(p: str) -> bool:
    return os.path.abspath(p).lower() in load_db().get("whitelist_paths", [])

def is_excluded(p: str, strict: bool = False) -> bool:
    if strict: return False
    low, base = os.path.abspath(p).lower(), BASE_DIR.lower()
    return low == base or low.startswith(base + os.sep) or low.startswith(EXCL_PREF) or any(x in low for x in EXCL_DIRS)

class WT_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

class WT_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD), ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD), ("pFile", ctypes.POINTER(WT_INFO)), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD)]

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

def verify_windows_signature(p: str) -> bool:
    try:
        fi = WT_INFO(cbStruct=ctypes.sizeof(WT_INFO), pcwszFilePath=p)
        td = WT_DATA(cbStruct=ctypes.sizeof(WT_DATA), dwUIChoice=2, dwUnionChoice=1, pFile=ctypes.pointer(fi))
        g = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        res = ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(g), ctypes.byref(td))
        td.dwStateAction = 2
        ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(g), ctypes.byref(td))
        return res == 0
    except Exception:
        return False

def is_hidden_file(p: str) -> bool:
    try:
        a = ctypes.windll.kernel32.GetFileAttributesW(p)
        return False if a == -1 else bool(a & 0x2)
    except Exception:
        return False

def is_eicar(data: bytes) -> bool:
    return len(data) <= 128 and data.lstrip().startswith(EICAR)

def get_entropy(data: bytes) -> float:
    n = len(data)
    return 0.0 if not n else -sum((c / n) * math.log2(c / n) for b in range(256) if (c := data.count(b)) > 0)

def _check_xor_obfuscation(data: bytes, db: dict):
    sample = data[:524288]
    targets = [it["pattern"].lower().encode() for it in db.get("dangerous_strings", [])] + [b"http://", b"https://", b"powershell", b"cmd.exe"]
    for key in (0x55, 0xAA, 0xFF, 0x13, 0x37, 0x42, 0x69, 0x88, 0x99, 0xCC):
        xored = bytes(b ^ key for b in sample).lower()
        for t in targets:
            if t in xored:
                return 45, f"XOR-зашифрованная строка '{t.decode(errors='ignore')}' (ключ 0x{key:02X}) (+45)"
    return 0, None

def _search_strings_multibyte(data_lower: bytes, db: dict):
    score, reasons = 0, []
    for it in db.get("dangerous_strings", []):
        pat_str = it["pattern"].lower()
        if pat_str.encode("utf-8", errors="ignore") in data_lower or pat_str.encode("utf-16le", errors="ignore") in data_lower:
            score += it["score"]
            reasons.append(f"{it['desc']} (+{it['score']})")
    return score, reasons

def scan_pe(data: bytes, trusted: bool):
    if is_eicar(data): return 100, ["Сигнатура EICAR! (+100)"]
    db = load_db()
    h = hashlib.sha256(data).hexdigest().lower()
    if h in db.get("malware_hashes_sha256", {}):
        return 100, [f"База SHA-256: {db['malware_hashes_sha256'][h]} (+100)"]

    score, reasons = (0, []) if trusted else (15, ["Нет проверенной цифровой подписи (+15)"])
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return (0, []) if trusted else (25, ["Поврежденный или нестандартный заголовок PE (+25)"])

    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0 or ts > 1893456000:
        score += 15; reasons.append("Поддельная метка времени компиляции PE (+15)")

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_in_code = rwx_found = high_entropy_found = False

 
    found_apis = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:

            for imp in e.imports:
                if imp.name in APIS and imp.name not in found_apis:
                    found_apis.add(imp.name)
                    pts, desc = APIS[imp.name]
                    score += pts
                    reasons.append(f"{imp.name.decode()}: {desc} (+{pts})")

    for combo_set, c_pts, c_desc in API_COMBOS:
        if combo_set.issubset(found_apis):
            score += c_pts
            reasons.append(f"{c_desc} (+{c_pts})")

    s_pts, s_reasons = _search_strings_multibyte(data.lower(), db)
    score += s_pts
    reasons.extend(s_reasons)

    if not trusted and score >= 25:
        xor_pts, xor_msg = _check_xor_obfuscation(data, db)
        if xor_pts:
            score += xor_pts
            reasons.append(xor_msg)

    ov = pe.get_overlay_data_start_offset()
    if ov and ov < len(data) and get_entropy(data[ov : ov + 2097152]) > 7.4:
        score += 25
        reasons.append("Скрытый зашифрованный блок в конце файла (+25)")

    if trusted:
        score = max(0, score - 45)
        reasons.append("Подтвержденная цифровая подпись (-45)")

    pe.close()
    return min(100, score), reasons


def scan_script(data: bytes):
    if is_eicar(data):
        return 100, ["Сигнатура EICAR! (+100)"]
    db = load_db()
    score, reasons = 0, []
    raw_txt = data.decode(errors="ignore")
    decoded_extra = ""
    for m in re.findall(r"[a-zA-Z0-9+/=]{40,}", raw_txt)[:6]:
        try:
            raw = base64.b64decode(m)
            decoded_extra += (
                " "
                + raw.decode("utf-16le", errors="ignore").lower()
                + " "
                + raw.decode("utf-8", errors="ignore").lower()
            )
        except Exception:
            pass
    full_txt = raw_txt.lower() + decoded_extra
    for sig, pts, desc in SCRIPT_SIGS:
        if sig in full_txt:
            score += pts
            reasons.append(f"{sig}: {desc} (+{pts})")
    for it in db.get("dangerous_strings", []):
        if it["pattern"].lower() in full_txt:
            score += it["score"]
            reasons.append(f"{it['desc']} (+{it['score']})")
    return min(100, score), reasons


def scan_lnk(data: bytes):
    score, reasons = 0, []
    txt = (
        data.decode("utf-16le", errors="ignore").lower()
        + " "
        + data.decode("latin1", errors="ignore").lower()
    )
    danger_cmds = [
        ("powershell", 45, "Ярлык вызывает PowerShell"),
        ("cmd.exe", 35, "Ярлык вызывает cmd.exe"),
        ("mshta", 55, "Ярлык запускает mshta.exe"),
        ("wscript", 45, "Ярлык запускает WScript"),
        ("cscript", 45, "Ярлык запускает CScript"),
        ("rundll32", 40, "Ярлык вызывает rundll32"),
        ("regsvr32", 45, "Ярлык вызывает regsvr32"),
        ("http://", 35, "В ярлык вшита HTTP-ссылка"),
        ("https://", 30, "В ярлык вшита HTTPS-ссылка"),
    ]
    for cmd, pts, desc in danger_cmds:
        if cmd in txt:
            score += pts
            reasons.append(f"{desc} (+{pts})")
    return min(100, score), reasons


def deep_reverify(cand: tuple):
    score, _, path, reasons = cand
    base = os.path.basename(path.lower())
    if (
        is_whitelisted(path)
        or is_excluded(path)
        or base in SAFE_NAMES
        or base.startswith("libpython")
        or verify_windows_signature(path)
    ):
        return None
    critical = (
        "EICAR",
        "Маскировка",
        "SHA-256",
        "Стиллер",
        "криптомайнер",
        "Защитника",
        "DPAPI",
        "Шифровальщик",
        "КРИТИЧЕСКАЯ ЦЕПОЧКА",
        "XOR-зашифрованная",
        "Двойное расширение",
    )
    if any(k in r for r in reasons for k in critical):
        return (
            max(85, score),
            "ВЫСОКАЯ ОПАСНОСТЬ",
            path,
            reasons + ["[Перепроверено] Критическая угроза"],
        )
    if score < 75:
        return None
    return (
        score,
        "ВЫСОКАЯ ОПАСНОСТЬ",
        path,
        reasons + ["[Перепроверено] Подтверждено"],
    )


def analyze_file_worker(p: str, strict_mode: bool = False):
    try:
        if is_whitelisted(p):
            return (0, "БЕЗОПАСНО", p, ["В Белом списке"]) if strict_mode else None
        if is_excluded(p, strict_mode) or os.path.islink(p):
            return None
        sz = os.path.getsize(p)
        if not strict_mode and sz > 157286400:
            return None

        fname_low = os.path.basename(p).lower()
        ext = os.path.splitext(p)[1].lower()
        hid = is_hidden_file(p)
        low = p.lower()
        score, reasons = 0, []

        fake_exts = (
            ".pdf.",
            ".doc.",
            ".docx.",
            ".xls.",
            ".xlsx.",
            ".jpg.",
            ".png.",
            ".txt.",
            ".mp4.",
        )
        if ext in PE_EXTS + SCRIPT_EXTS and any(fe in fname_low for fe in fake_exts):
            score += 55
            reasons.append("Двойное расширение файла — маскировка под документ (+55)")

        if ext in PE_EXTS:
            if sz == 0:
                return None
            tr = verify_windows_signature(p)
            if tr and not strict_mode:
                return None
            with open(p, "rb") as f:
                pe_score, pe_reasons = scan_pe(f.read(), tr)
            score = min(100, score + pe_score)
            reasons.extend(pe_reasons)
            if not tr and any(
                k in low for k in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\")
            ):
                score = min(100, score + 15)
                reasons.append("Расположен в зоне риска (+15)")
            if not tr and hid:
                score = min(100, score + 25)
                reasons.append("Скрытый атрибут файла (+25)")
        elif ext in SCRIPT_EXTS:
            with open(p, "rb") as f:
                sc_score, sc_reasons = scan_script(f.read())
            score = min(100, score + sc_score)
            reasons.extend(sc_reasons)
            if hid and score > 0:
                score = min(100, score + 20)
                reasons.append("Скрытый скрипт (+20)")
        elif ext == ".lnk":
            if sz <= 65536:
                with open(p, "rb") as f:
                    lnk_score, lnk_reasons = scan_lnk(f.read())
                score = min(100, score + lnk_score)
                reasons.extend(lnk_reasons)
        elif ext == ".zip":
            with zipfile.ZipFile(p, "r") as zf:
                for i in zf.infolist():
                    if i.is_dir() or i.file_size > 52428800:
                        continue
                    ie = os.path.splitext(i.filename)[1].lower()
                    inn = zf.read(i.filename)
                    if is_eicar(inn):
                        return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, [f"EICAR в {i.filename} (+100)"])
                    if ie in PE_EXTS:
                        s, r = scan_pe(inn, False)
                        if s > score:
                            score, reasons = s, [f"В архиве ({i.filename}):"] + r
                    elif ie in SCRIPT_EXTS:
                        s, r = scan_script(inn)
                        if s > score:
                            score, reasons = s, [f"В архиве ({i.filename}):"] + r
                    elif ie == ".lnk":
                        s, r = scan_lnk(inn)
                        if s > score:
                            score, reasons = s, [f"Ярлык в архиве ({i.filename}):"] + r
        else:
            if sz == 0:
                return (0, "БЕЗОПАСНО", p, ["Пустой файл"]) if strict_mode else None
            with open(p, "rb") as f:
                head = f.read(128)
            if is_eicar(head):
                return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, ["Сигнатура EICAR! (+100)"])
            if head.startswith(b"MZ") and ext not in LEGIT_MZ and ext != "":
                if verify_windows_signature(p):
                    return (0, "БЕЗОПАСНО", p, ["Подписанный модуль"]) if strict_mode else None
                return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, [f"Маскировка PE-программы под '{ext}' (+100)"])
            return (0, "БЕЗОПАСНО", p, ["Угроз не обнаружено"]) if strict_mode else None

        status = (
            "ВЫСОКАЯ ОПАСНОСТЬ"
            if score >= 75
            else "ПОДОЗРИТЕЛЬНО"
            if score >= 45
            else "БЕЗОПАСНО"
        )
        if not strict_mode and status == "БЕЗОПАСНО":
            return None
        return (score, status, p, reasons or ["Угроз не обнаружено"])
    except Exception:
        return None
