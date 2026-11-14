import ctypes, os, shutil, string, sys, threading, time, tkinter as tk
from tkinter import filedialog, messagebox, ttk
from engine import add_to_whitelist, analyze_file_worker, deep_reverify, is_hidden_file
from system_monitor import get_active_connections, scan_autorun, scan_running_processes

is_admin = lambda: ctypes.windll.shell32.IsUserAnAdmin() != 0
get_drives = lambda: [f"{c}:\\" for i, c in enumerate(string.ascii_uppercase) if ctypes.windll.kernel32.GetLogicalDrives() & (1 << i)]
def q_dir():
    d = os.path.join(os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)), "_Quarantine")
    os.makedirs(d, exist_ok=True); return d

L = {
    "ru": dict(adm="● Админ", usr="● Обычный", t1="🔍 Сканер", t2="🛡️ Щит 24/7", t3="⚡ Система", b1="🔍 Проверить файл / ZIP", b2="💻 Быстрая проверка всего ПК", rdy="Готов.", q="🔒 Карантин", dl="🗑️ Удалить", wl="✅ Белый список", cq="🧹 Очистить", soff="⚪ Щит ВЫКЛ", son="🟢 Щит ВКЛ", bso="▶️ Включить", bsf="⏹️ Стоп", sys="⚡ Память и Автозагрузка", net="🌐 Сеть", cln="✅ Угроз нет!\n"),
    "en": dict(adm="● Admin", usr="● Standard", t1="🔍 Scanner", t2="🛡️ 24/7 Shield", t3="⚡ System", b1="🔍 Scan File / ZIP", b2="💻 Fast Full PC Scan", rdy="Ready.", q="🔒 Quarantine", dl="🗑️ Delete", wl="✅ Whitelist", cq="🧹 Clear", soff="⚪ Shield OFF", son="🟢 Shield ON", bso="▶️ Enable", bsf="⏹️ Stop", sys="⚡ Memory & Autorun", net="🌐 Network", cln="✅ Clean!\n"),
}
SKIP_DIRS = {"windows", "winsxs", "$recycle.bin", "system volume information", "node_modules", ".git", "cache", "code cache"}

class App:
    def __init__(self, r):
        self.r, self.stop, self.shield, self.threats, self.lang = r, threading.Event(), False, [], "ru"
        r.title("MyAntivirus | by sha1"); r.geometry("840x520"); r.configure(bg="#0F172A"); r.protocol("WM_DELETE_WINDOW", self.close)
        top = tk.Frame(r, bg="#1E293B", pady=8); top.pack(fill="x", padx=10, pady=8)
        tk.Label(top, text="🛡️ MyAntivirus | by sha1", font=("Segoe UI", 13, "bold"), bg="#1E293B", fg="#60A5FA").pack(side="left", padx=12)
        self.bl = tk.Button(top, text="🌐 EN", bg="#334155", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", padx=8, command=self.tog_lang); self.bl.pack(side="right", padx=(0, 12))
        self.al = tk.Label(top, font=("Segoe UI", 10, "bold"), bg="#1E293B", fg="#4ADE80" if is_admin() else "#FACC15"); self.al.pack(side="right", padx=10)

        self.nb = ttk.Notebook(r); self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        t1, t2, t3 = tk.Frame(self.nb, bg="#0F172A"), tk.Frame(self.nb, bg="#0F172A"), tk.Frame(self.nb, bg="#0F172A")
        self.nb.add(t1, text=""); self.nb.add(t2, text=""); self.nb.add(t3, text="")

        bf = tk.Frame(t1, bg="#0F172A"); bf.pack(fill="x", pady=6)
        self.b1 = tk.Button(bf, bg="#2563EB", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=6, command=self.scan_one); self.b1.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.b2 = tk.Button(bf, bg="#1D4ED8", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=6, command=self.scan_all); self.b2.pack(side="left", expand=True, fill="x", padx=(4, 0))
        self.lbl = tk.Label(t1, bg="#0F172A", fg="#CBD5E1", font=("Segoe UI", 9)); self.lbl.pack(anchor="w")
        self.pb = ttk.Progressbar(t1, mode="indeterminate"); self.pb.pack(fill="x", pady=4)

        af = tk.Frame(t1, bg="#0F172A"); af.pack(side="bottom", fill="x", pady=(6, 0))
        self.bq = tk.Button(af, bg="#D97706", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", pady=6, state="disabled", command=self.to_quar); self.bq.pack(side="left", expand=True, fill="x", padx=(0, 3))
        self.bd = tk.Button(af, bg="#DC2626", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", pady=6, state="disabled", command=self.del_all); self.bd.pack(side="left", expand=True, fill="x", padx=3)
        self.bw = tk.Button(af, bg="#059669", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", pady=6, state="disabled", command=self.to_wl); self.bw.pack(side="left", expand=True, fill="x", padx=3)
        self.bc = tk.Button(af, bg="#334155", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", pady=6, command=self.clear_q); self.bc.pack(side="left", expand=True, fill="x", padx=(3, 0))
        self.box = tk.Text(t1, bg="#1E293B", fg="#F8FAFC", font=("Consolas", 10), relief="flat", wrap="word"); self.box.pack(fill="both", expand=True)

        ts = tk.Frame(t2, bg="#1E293B", pady=10, padx=12); ts.pack(fill="x", pady=8)
        self.sl = tk.Label(ts, bg="#1E293B", fg="#FACC15", font=("Segoe UI", 10, "bold")); self.sl.pack(side="left")
        self.bs = tk.Button(ts, bg="#16A34A", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", padx=10, pady=5, command=self.tog_shield); self.bs.pack(side="right")
        self.sbox = tk.Text(t2, bg="#1E293B", fg="#F8FAFC", font=("Consolas", 10), relief="flat", wrap="word"); self.sbox.pack(fill="both", expand=True)

        bf2 = tk.Frame(t3, bg="#0F172A"); bf2.pack(fill="x", pady=8)
        self.bsy = tk.Button(bf2, bg="#2563EB", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=7, command=self.sys_chk); self.bsy.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.bne = tk.Button(bf2, bg="#0284C7", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=7, command=self.net_chk); self.bne.pack(side="left", expand=True, fill="x", padx=(4, 0))
        self.ybox = tk.Text(t3, bg="#1E293B", fg="#F8FAFC", font=("Consolas", 10), relief="flat", wrap="word"); self.ybox.pack(fill="both", expand=True)
        self.apply_l()

    def tog_lang(self): self.lang = "en" if self.lang == "ru" else "ru"; self.bl.config(text="🌐 RU" if self.lang == "en" else "🌐 EN"); self.apply_l()
    def apply_l(self):
        t = L.get(self.lang); self.al.config(text=t.get("adm") if is_admin() else t.get("usr"))
        self.nb.tab(0, text=t.get("t1")); self.nb.tab(1, text=t.get("t2")); self.nb.tab(2, text=t.get("t3"))
        self.b1.config(text=t.get("b1")); self.b2.config(text=t.get("b2")); self.lbl.config(text=t.get("rdy")); self.bc.config(text=t.get("cq"))
        self.sl.config(text=t.get("son") if self.shield else t.get("soff")); self.bs.config(text=t.get("bsf") if self.shield else t.get("bso"))
        self.bsy.config(text=t.get("sys")); self.bne.config(text=t.get("net")); self.upd_btns()

    def upd_btns(self):
        t, n, s = L.get(self.lang), len(self.threats), "normal" if self.threats else "disabled"
        self.bq.config(text=f"{t.get('q')} ({n})", state=s); self.bd.config(text=f"{t.get('dl')} ({n})", state=s); self.bw.config(text=f"{t.get('wl')} ({n})", state=s)

    def log(self, sc, lv, p, rs): self.box.insert("end", f"[{lv} — {sc}/100] {p}\n" + "\n".join(f"  • {x}" for x in rs) + "\n\n"); self.box.see("end")
    def to_quar(self):
        for p in list(self.threats):
            if os.path.exists(p): shutil.move(p, os.path.join(q_dir(), os.path.basename(p) + ".quarantined"))
        self.threats.clear(); self.upd_btns(); self.box.insert("end", "🔒 Quarantined!\n\n")
    def del_all(self):
        if messagebox.askyesno("Confirm", f"Delete ({len(self.threats)}) permanently?"):
            for p in list(self.threats):
                if os.path.exists(p): os.remove(p)
            self.threats.clear(); self.upd_btns(); self.box.insert("end", "🗑️ Deleted!\n\n")
    def to_wl(self):
        for p in list(self.threats): add_to_whitelist(p)
        self.threats.clear(); self.upd_btns(); self.box.insert("end", "✅ Whitelisted!\n\n")
    def clear_q(self):
        for f in os.listdir(q_dir()): os.remove(os.path.join(q_dir(), f))
        messagebox.showinfo("OK", "Cleared!")

    def scan_one(self):
        p = filedialog.askopenfilename()
        if not p: return
        self.box.delete("1.0", "end"); self.threats.clear(); self.upd_btns()
        res = analyze_file_worker(p, True)
        if res:
            sc, lv, path, rs = res; self.log(sc, lv, path, rs)
            if sc >= 40: self.threats.append(path); self.upd_btns()

    def scan_all(self):
        self.b1.config(state="disabled"); self.b2.config(state="disabled"); self.box.delete("1.0", "end"); self.threats.clear(); self.upd_btns(); self.stop.clear()
        self.pb.start(12); threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        cnt, hd, cands = 0, 0, []
        for d in get_drives():
            for rt, dirs, files in os.walk(d):
                if self.stop.is_set(): return
                dirs[:] = [dn for dn in dirs if dn.lower() not in SKIP_DIRS]
                hd += sum(1 for dn in dirs if is_hidden_file(os.path.join(rt, dn)))
                for f in files:
                    cnt += 1; res = analyze_file_worker(os.path.join(rt, f), False)
                    if res: cands.append(res)
                    if cnt % 400 == 0: self.r.after(0, lambda n=cnt, h=hd, c=len(cands): self.lbl.config(text=f"Scanned: {n} | Hidden dirs: {h} | Candidates: {c}"))
        ok = 0
        for c in cands:
            v = deep_reverify(c)
            if v: sc, lv, p, rs = v; ok += 1; self.threats.append(p); self.r.after(0, lambda s=sc, l=lv, pt=p, r=rs: self.log(s, l, pt, r))
        if not ok: self.r.after(0, lambda: self.box.insert("end", L.get(self.lang).get("cln")))
        self.r.after(0, lambda: (self.pb.stop(), self.b1.config(state="normal"), self.b2.config(state="normal"), self.upd_btns(), self.lbl.config(text=f"Done! Scanned: {cnt} (Hidden: {hd}) | Threats: {ok}")))

    def tog_shield(self):
        self.shield = not self.shield; self.apply_l()
        if self.shield: threading.Thread(target=self._sh_loop, daemon=True).start()

    def _sh_loop(self):
        wds = [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop")]
        kn = {os.path.join(w, f) for w in wds if os.path.exists(w) for f in os.listdir(w)}
        while self.shield and not self.stop.is_set():
            time.sleep(2)

            for w in wds:
                if not os.path.exists(w): continue
                for f in os.listdir(w):
                    fp = os.path.join(w, f)
                    if fp not in kn and os.path.isfile(fp) and not f.endswith((".crdownload", ".part", ".tmp")):
                        kn.add(fp); res = analyze_file_worker(fp, True)
                        if res:
                            sc, lv, p, _ = res
                            self.r.after(0, lambda m=f"[{time.strftime('%H:%M:%S')}] {f} -> {lv} ({sc}/100)\n": (self.sbox.insert("end", m), self.sbox.see("end")))
                            if sc >= 70: self.r.after(0, lambda pt=p, s=sc: messagebox.showwarning("🛡️ Shield", f"Threat ({s}/100):\n{pt}"))

    def sys_chk(self):
        self.ybox.delete("1.0", "end"); self.r.update()
        items = [(sc, lv, t, rs) for sc, lv, t, rs, _ in scan_running_processes()] + scan_autorun()
        self.ybox.insert("end", L.get(self.lang).get("cln") if not items else "".join(f"[{lv} — {sc}/100] {t}\n" + "\n".join(f"  • {x}" for x in rs) + "\n\n" for sc, lv, t, rs in items))

    def net_chk(self):
        self.ybox.delete("1.0", "end"); c = get_active_connections()
        self.ybox.insert("end", ("\n".join(c) if c else "No connections.") + "\n")

    def close(self):
        self.shield = False; self.stop.set(); self.r.destroy(); os._exit(0)

if __name__ == "__main__":
    mtx = ctypes.windll.kernel32.CreateMutexW(None, False, "MyAntivirus_sha1_Mutex")
    if ctypes.windll.kernel32.GetLastError() == 183: sys.exit(0)
    root = tk.Tk(); App(root); root.mainloop()
