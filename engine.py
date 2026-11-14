import ctypes, hashlib, json, math, os, sys, zipfile, pefile
from ctypes import wintypes
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
SIG_DB = os.path.join(BASE_DIR, "signatures.json")
PE_EXTS, SCRIPT_EXTS = (".exe", ".dll", ".sys", ".scr"), (".ps1", ".bat", ".cmd", ".vbs", ".js")
EICAR = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE"
SAFE_NAMES = ("unins000.exe", "unins001.exe", "uninstall.exe")
LEGIT_MZ = (".mui", ".pyd", ".ocx", ".ax", ".cpl", ".efi", ".drv", ".winmd", ".tlb", ".asi", ".bpl", ".ime", ".acm")

APIS = {
    b"RtlDecompressBuffer": (25, "Распаковка в памяти"), b"CryptDecrypt": (20, "Расшифровка данных"),
    b"CreateProcessW": (15, "Запуск процессов"), b"ShellExecuteExW": (15, "Запуск файлов"),
    b"URLDownloadToFileW": (30, "Скачивание из сети"), b"VirtualAlloc": (15, "Выделение памяти"),
    b"WriteProcessMemory": (35, "Внедрение в процесс"),
}
SCRIPT_SIGS = [
    ("invoke-webrequest", 35, "Загрузка из сети"), ("downloadstring", 35, "Запуск из сети"),
    ("certutil -urlcache", 40, "Скачивание через certutil"), ("powershell -enc", 40, "Шифрованный PowerShell"),
    ("add-mppreference", 50, "Отключение Защитника"),
]

def load_db():
    try:
        with open(SIG_DB, "r", encoding="utf-8") as f: return json.load(f)
    except: return {"malware_hashes_sha256": {}, "dangerous_strings": [], "whitelist_paths": []}

def add_to_whitelist(p: str):
    db, norm = load_db(), os.path.abspath(p).lower()
    if norm not in db.get("whitelist_paths", []):
        db.setdefault("whitelist_paths", []).append(norm)
        with open(SIG_DB, "w", encoding="utf-8") as f: json.dump(db, f, ensure_ascii=False, indent=2)

def is_whitelisted(p: str) -> bool:
    return os.path.abspath(p).lower() in load_db().get("whitelist_paths", [])

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
        return ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(g), ctypes.byref(td)) == 0
    except: return False

def is_hidden_file(p: str) -> bool:
    try: a = ctypes.windll.kernel32.GetFileAttributesW(p); return False if a == -1 else bool(a & 0x2)
    except: return False

def get_entropy(data: bytes) -> float:
    n = len(data)
    return 0.0 if not n else -sum((c / n) * math.log2(c / n) for b in range(256) if (c := data.count(b)) > 0)

def scan_pe(data: bytes, trusted: bool):
    if EICAR in data: return 100, ["Сигнатура EICAR! (+100)"]
    db, h = load_db(), hashlib.sha256(data).hexdigest().lower()
    if h in db.get("malware_hashes_sha256", {}): return 100, [f"База SHA-256: {db['malware_hashes_sha256'][h]} (+100)"]
    score, reasons = (0, []) if trusted else (15, ["Нет проверенной подписи (+15)"])
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    for s in pe.sections:
        if s.get_entropy() > 7.4: score += 15; reasons.append(f"Сжатая секция {s.get_entropy():.2f} (+15)"); break
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        seen = set()
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                if imp.name in APIS and imp.name not in seen:
                    seen.add(imp.name); pts, desc = APIS[imp.name]; score += pts; reasons.append(f"{imp.name.decode()}: {desc} (+{pts})")
    low = data.lower()
    for it in db.get("dangerous_strings", []):
        if it["pattern"].encode() in low: score += it["score"]; reasons.append(f"{it['desc']} (+{it['score']})")
    ov = pe.get_overlay_data_start_offset()
    if ov and ov < len(data) and get_entropy(data[ov:ov + 2097152]) > 7.3: score += 25; reasons.append("Скрытый блок в конце (+25)")
    if trusted: score = max(0, score - 25); reasons.append("Подпись подтверждена (-25)")
    pe.close(); return min(100, score), reasons

def scan_script(data: bytes):
    if EICAR in data: return 100, ["Сигнатура EICAR! (+100)"]
    score, reasons, txt = 0, [], data.decode(errors="ignore").lower()
    for sig, pts, desc in SCRIPT_SIGS:
        if sig in txt: score += pts; reasons.append(f"{sig}: {desc} (+{pts})")
    return min(100, score), reasons

def deep_reverify(cand: tuple):
    score, _, path, reasons = cand; low, base = path.lower(), os.path.basename(path.lower())
    if is_whitelisted(path) or "\\microsoft\\windowsapps\\" in low or low.startswith(("c:\\windows\\", "c:\\$winreagent\\", "c:\\program files\\windowsapps\\")): return None
    if any("EICAR" in r or "Маскировка" in r or "SHA-256" in r for r in reasons): return (100, "ВЫСОКАЯ ОПАСНОСТЬ", path, reasons + ["[Перепроверено] Угроза"])
    if base in SAFE_NAMES or base.startswith("libpython") or verify_windows_signature(path): return None
    if not any("Стиллер" in r or "криптомайнер" in r or "Защитника" in r for r in reasons) and score < 70: return None
    return (score, "ВЫСОКАЯ ОПАСНОСТЬ", path, reasons + ["[Перепроверено] Подтверждено"])

def analyze_file_worker(p: str, strict_mode: bool = False):
    try:
        if is_whitelisted(p): return (0, "БЕЗОПАСНО", p, ["В Белом списке"]) if strict_mode else None
        low = p.lower()
        if not strict_mode and ("\\microsoft\\windowsapps\\" in low or low.startswith(("c:\\windows\\", "c:\\$winreagent\\", "c:\\program files\\windowsapps\\"))): return None
        if os.path.islink(p): return None
        sz = os.path.getsize(p)
        if not strict_mode and sz > 157286400: return None
        ext, hid, score, reasons = Path(p).suffix.lower(), is_hidden_file(p), 0, []
        if ext in PE_EXTS:
            if sz == 0: return None
            tr = verify_windows_signature(p)
            if tr and not strict_mode: return None
            with open(p, "rb") as f: score, reasons = scan_pe(f.read(), tr)
            if not tr and any(k in low for k in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\")): score = min(100, score + 20); reasons.append("Зона риска (+20)")
            if not tr and hid: score = min(100, score + 25); reasons.append("Скрытый файл (+25)")
        elif ext in SCRIPT_EXTS:
            with open(p, "rb") as f: score, reasons = scan_script(f.read())
            if hid: score = min(100, score + 20); reasons.append("Скрытый скрипт (+20)")
        elif ext == ".zip":
            with zipfile.ZipFile(p, "r") as zf:
                for i in zf.infolist():
                    if i.is_dir() or i.file_size > 52428800: continue
                    ie, inn = Path(i.filename).suffix.lower(), zf.read(i.filename)
                    if EICAR in inn: return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, [f"EICAR в {i.filename} (+100)"])
                    if ie in PE_EXTS:
                        s, r = scan_pe(inn, False)
                        if s > score: score, reasons = s, [f"В {i.filename}:"] + r
                    elif ie in SCRIPT_EXTS:
                        s, r = scan_script(inn)
                        if s > score: score, reasons = s, [f"В {i.filename}:"] + r
        else:
            if sz == 0: return (0, "БЕЗОПАСНО", p, ["Пустой файл"]) if strict_mode else None
            with open(p, "rb") as f: hd = f.read(4096)
            if EICAR in hd: return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, ["Сигнатура EICAR (+100)"])
            if hd.startswith(b"MZ") and ext not in LEGIT_MZ:
                score = 100 if hid else 85; reasons.append(f"Маскировка MZ под '{ext}' (+{score})")
        if strict_mode: return (score, "БЕЗОПАСНО" if score < 40 else ("УМЕРЕННАЯ ОПАСНОСТЬ" if score < 70 else "ВЫСОКАЯ ОПАСНОСТЬ"), p, reasons or ["Угроз нет"])
        return (score, "ВЫСОКАЯ ОПАСНОСТЬ", p, reasons) if score >= 70 else None
    except PermissionError: return (95, "ВЫСОКАЯ ОПАСНОСТЬ", p, ["Заблокировано защитой Windows (+95)"]) if strict_mode else None
    except OSError as e: return (100, "ВЫСОКАЯ ОПАСНОСТЬ", p, ["Перехвачено ядром Windows (+100)"]) if getattr(e, "winerror", None) == 225 else ((0, "ОШИБКА", p, [str(e)]) if strict_mode else None)
    except Exception as e: return (0, "ОШИБКА", p, [str(e)]) if strict_mode else None
