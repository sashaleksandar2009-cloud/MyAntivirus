import ctypes
import json
import multiprocessing
import os
import shutil
import sys
import threading
import tkinter as tk
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

from engine import (
    BASE_DIR,
    add_to_whitelist,
    analyze_file_worker,
    deep_reverify,
    is_excluded,
)
from system_monitor import (
    get_active_connections,
    kill_process_by_pid,
    remove_autorun_entry,
    scan_autorun,
    scan_running_processes,
)

QUARANTINE_DIR = os.path.join(BASE_DIR, "_Quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)


def check_single_instance():
    mutex = ctypes.windll.kernel32.CreateMutexW(
        None, False, "MyAntivirus_KVRT_Mutex"
    )
    if ctypes.windll.kernel32.GetLastError() == 183:
        sys.exit(0)
    return mutex


class AntivirusKVRTApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.scanning = False
        self.stop_flag = False
        self.shield_active = False
        self.custom_target = ""
        self.threats = []

        self.var_mem = tk.BooleanVar(value=True)
        self.var_autorun = tk.BooleanVar(value=True)
        self.var_quick = tk.BooleanVar(value=True)
        self.var_custom = tk.BooleanVar(value=False)

        self.title("Virus Removal Tool — MyAntivirus Edition")
        self.geometry("1080x720")
        self.minsize(960, 640)
        self.configure(bg="#0b1116")

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self.after(500, self.refresh_quarantine_list)
        self.after(700, self.refresh_network_tab)

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background="#0b1116", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#131c24",
            foreground="#8b9bb4",
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#00a88e")],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview",
            background="#101820",
            foreground="#e2e8f0",
            fieldbackground="#101820",
            rowheight=28,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#182430",
            foreground="#00d2b4",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Treeview", background=[("selected", "#1e3a4c")])
        style.configure(
            "KVRT.Horizontal.TProgressbar",
            troughcolor="#16202a",
            background="#00a88e",
            thickness=10,
            borderwidth=0,
        )

    def _build_header(self):
        header = tk.Frame(self, bg="#101820", height=58)
        header.pack(fill="x")
        header.pack_propagate(False)

        logo_frame = tk.Frame(header, bg="#101820")
        logo_frame.pack(side="left", padx=18)

        tk.Label(
            logo_frame,
            text="🛡️",
            bg="#101820",
            fg="#00a88e",
            font=("Segoe UI", 18),
        ).pack(side="left", padx=(0, 8))

        title_box = tk.Frame(logo_frame, bg="#101820")
        title_box.pack(side="left")
        tk.Label(
            title_box,
            text="Virus Removal Tool",
            bg="#101820",
            fg="#ffffff",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="Утилита лечения и поиска угроз | Engine v2.0",
            bg="#101820",
            fg="#64748b",
            font=("Segoe UI", 8),
        ).pack(anchor="w")

        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        adm_text = (
            "● Режим Администратора (Полный доступ)"
            if is_admin
            else "▲ Обычный режим (Ограниченная очистка реестра)"
        )
        adm_color = "#00d2b4" if is_admin else "#f59e0b"
        tk.Label(
            header,
            text=adm_text,
            bg="#101820",
            fg=adm_color,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=18)

    def _build_tabs(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=10)

        self.tab_scan = tk.Frame(self.nb, bg="#0b1116")
        self.tab_quar = tk.Frame(self.nb, bg="#0b1116")
        self.tab_shield = tk.Frame(self.nb, bg="#0b1116")
        self.tab_net = tk.Frame(self.nb, bg="#0b1116")

        self.nb.add(self.tab_scan, text="🔍 Проверка компьютера")
        self.nb.add(self.tab_quar, text="📦 Карантин")
        self.nb.add(self.tab_shield, text="🛡️ Монитор 24/7")
        self.nb.add(self.tab_net, text="🌐 Сетевые соединения")

        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_shield_tab()
        self._build_network_tab()

    def _build_scan_tab(self):
        top_card = tk.Frame(
            self.tab_scan,
            bg="#101820",
            highlightbackground="#1e2d3b",
            highlightthickness=1,
        )
        top_card.pack(fill="x", pady=(6, 10))

        left_opts = tk.Frame(top_card, bg="#101820")
        left_opts.pack(side="left", fill="both", expand=True, padx=16, pady=12)

        tk.Label(
            left_opts,
            text="Области проверки:",
            bg="#101820",
            fg="#ffffff",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        cb_style = {
            "bg": "#101820",
            "fg": "#cbd5e1",
            "selectcolor": "#0b1116",
            "activebackground": "#101820",
            "activeforeground": "#00d2b4",
            "font": ("Segoe UI", 9),
        }
        tk.Checkbutton(
            left_opts,
            text="Системная память (активные процессы)",
            variable=self.var_mem,
            **cb_style,
        ).pack(anchor="w")
        tk.Checkbutton(
            left_opts,
            text="Объекты автозапуска (реестр Windows Run)",
            variable=self.var_autorun,
            **cb_style,
        ).pack(anchor="w")
        tk.Checkbutton(
            left_opts,
            text="Системные разделы (Рабочий стол, Загрузки, AppData)",
            variable=self.var_quick,
            **cb_style,
        ).pack(anchor="w")

        custom_row = tk.Frame(left_opts, bg="#101820")
        custom_row.pack(fill="x", pady=(2, 0))
        tk.Checkbutton(
            custom_row,
            text="Выборочный объект:",
            variable=self.var_custom,
            **cb_style,
        ).pack(side="left")

        self.lbl_custom_path = tk.Label(
            custom_row,
            text="не выбран",
            bg="#101820",
            fg="#64748b",
            font=("Segoe UI", 9, "italic"),
        )
        self.lbl_custom_path.pack(side="left", padx=6)

        tk.Button(
            custom_row,
            text="📁 Папка",
            bg="#1e2d3b",
            fg="#e2e8f0",
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            command=self.choose_custom_folder,
        ).pack(side="left", padx=2)

        tk.Button(
            custom_row,
            text="📄 Файл / ZIP",
            bg="#1e2d3b",
            fg="#e2e8f0",
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            command=self.choose_custom_file,
        ).pack(side="left", padx=2)

        right_ctrl = tk.Frame(top_card, bg="#101820")
        right_ctrl.pack(side="right", padx=20, pady=12)

        self.btn_start = tk.Button(
            right_ctrl,
            text="▶ Начать проверку",
            bg="#00a88e",
            fg="#ffffff",
            activebackground="#008f78",
            activeforeground="#ffffff",
            font=("Segoe UI", 12, "bold"),
            relief="flat",
            width=20,
            height=2,
            cursor="hand2",
            command=self.start_scan,
        )
        self.btn_start.pack(pady=(0, 6))

        self.btn_stop = tk.Button(
            right_ctrl,
            text="⏹ Остановить",
            bg="#1e293b",
            fg="#94a3b8",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            width=20,
            state="disabled",
            command=self.stop_scan,
        )
        self.btn_stop.pack()

        prog_frame = tk.Frame(self.tab_scan, bg="#101820", padx=14, pady=10)
        prog_frame.pack(fill="x", pady=(0, 10))

        stat_row = tk.Frame(prog_frame, bg="#101820")
        stat_row.pack(fill="x", pady=(0, 6))

        self.lbl_status = tk.Label(
            stat_row,
            text="Готов к проверке системы",
            bg="#101820",
            fg="#e2e8f0",
            font=("Segoe UI", 9, "bold"),
        )
        self.lbl_status.pack(side="left")

        self.lbl_counters = tk.Label(
            stat_row,
            text="Проверено: 0 | Угроз: 0",
            bg="#101820",
            fg="#00d2b4",
            font=("Segoe UI", 9, "bold"),
        )
        self.lbl_counters.pack(side="right")

        self.progress = ttk.Progressbar(
            prog_frame,
            style="KVRT.Horizontal.TProgressbar",
            mode="determinate",
        )
        self.progress.pack(fill="x")

        tbl_frame = tk.Frame(self.tab_scan, bg="#101820")
        tbl_frame.pack(fill="both", expand=True)

        cols = ("risk", "type", "target", "reason")
        self.tree_threats = ttk.Treeview(
            tbl_frame, columns=cols, show="headings", selectmode="browse"
        )
        self.tree_threats.heading("risk", text="Риск")
        self.tree_threats.heading("type", text="Тип угрозы")
        self.tree_threats.heading("target", text="Объект / Путь")
        self.tree_threats.heading("reason", text="Вердикт движка")

        self.tree_threats.column("risk", width=85, anchor="center")
        self.tree_threats.column("type", width=170)
        self.tree_threats.column("target", width=420)
        self.tree_threats.column("reason", width=340)

        sb = ttk.Scrollbar(
            tbl_frame, orient="vertical", command=self.tree_threats.yview
        )
        self.tree_threats.configure(yscrollcommand=sb.set)
        self.tree_threats.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        act_bar = tk.Frame(self.tab_scan, bg="#0b1116")
        act_bar.pack(fill="x", pady=(8, 2))

        tk.Button(
            act_bar,
            text="⚡ Лечить / Удалить выбранное",
            bg="#dc2626",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            command=self.cure_selected,
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            act_bar,
            text="📦 В карантин",
            bg="#d97706",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            command=self.quarantine_selected,
        ).pack(side="left", padx=6)

        tk.Button(
            act_bar,
            text="✅ Пропустить (в белый список)",
            bg="#1e293b",
            fg="#cbd5e1",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            command=self.ignore_selected,
        ).pack(side="left", padx=6)

        self.btn_cure_all = tk.Button(
            act_bar,
            text="🛡️ Нейтрализовать все (0)",
            bg="#00a88e",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            command=self.neutralize_all,
        )
        self.btn_cure_all.pack(side="right")
    def _build_quarantine_tab(self):
        top = tk.Frame(self.tab_quar, bg="#0b1116")
        top.pack(fill="x", pady=8)

        tk.Label(
            top,
            text="Изолированные файлы (безопасно заблокированы):",
            bg="#0b1116",
            fg="#e2e8f0",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

        tk.Button(
            top,
            text="🔄 Обновить",
            bg="#1e293b",
            fg="#e2e8f0",
            relief="flat",
            padx=10,
            pady=4,
            command=self.refresh_quarantine_list,
        ).pack(side="right")

        cols = ("date", "name", "orig_path")
        self.tree_quar = ttk.Treeview(
            self.tab_quar, columns=cols, show="headings"
        )
        self.tree_quar.heading("date", text="Дата изоляции")
        self.tree_quar.heading("name", text="Имя файла")
        self.tree_quar.heading("orig_path", text="Исходное расположение")
        self.tree_quar.column("date", width=160)
        self.tree_quar.column("name", width=240)
        self.tree_quar.column("orig_path", width=620)
        self.tree_quar.pack(fill="both", expand=True, pady=4)

        q_btns = tk.Frame(self.tab_quar, bg="#0b1116")
        q_btns.pack(fill="x", pady=6)

        tk.Button(
            q_btns,
            text="♻️ Восстановить файл",
            bg="#0284c7",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            command=self.restore_quarantined,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            q_btns,
            text="🗑️ Удалить навсегда",
            bg="#dc2626",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            command=self.delete_quarantined,
        ).pack(side="left")

    def _build_shield_tab(self):
        top = tk.Frame(self.tab_shield, bg="#0b1116")
        top.pack(fill="x", pady=10)

        self.btn_shield = tk.Button(
            top,
            text="▶ Включить защиту Загрузок и Рабочего стола",
            bg="#00a88e",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=16,
            pady=8,
            command=self.toggle_shield,
        )
        self.btn_shield.pack(side="left")

        self.shield_log = scrolledtext.ScrolledText(
            self.tab_shield,
            bg="#101820",
            fg="#cbd5e1",
            font=("Consolas", 9),
            relief="flat",
        )
        self.shield_log.pack(fill="both", expand=True, pady=6)

    def _build_network_tab(self):
        bar = tk.Frame(self.tab_net, bg="#0b1116")
        bar.pack(fill="x", pady=8)

        tk.Label(
            bar,
            text="Активные внешние TCP-соединения процессов:",
            bg="#0b1116",
            fg="#e2e8f0",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

        tk.Button(
            bar,
            text="🔄 Обновить список",
            bg="#00a88e",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            command=self.refresh_network_tab,
        ).pack(side="right")

        cols = ("proc", "local", "remote")
        self.tree_net = ttk.Treeview(
            self.tab_net, columns=cols, show="headings"
        )
        self.tree_net.heading("proc", text="Процесс / PID")
        self.tree_net.heading("local", text="Локальный адрес")
        self.tree_net.heading("remote", text="Внешний узел")
        self.tree_net.column("proc", width=220)
        self.tree_net.column("local", width=350)
        self.tree_net.column("remote", width=440)
        self.tree_net.pack(fill="both", expand=True, pady=4)

    def choose_custom_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку для проверки")
        if folder:
            self.custom_target = folder
            self.var_custom.set(True)
            self.lbl_custom_path.config(text=folder, fg="#00d2b4")

    def choose_custom_file(self):
        fp = filedialog.askopenfilename(title="Выберите файл или ZIP-архив")
        if fp:
            self.custom_target = fp
            self.var_custom.set(True)
            self.lbl_custom_path.config(text=fp, fg="#00d2b4")

    def start_scan(self):
        if self.scanning:
            return
        areas = [
            self.var_mem.get(),
            self.var_autorun.get(),
            self.var_quick.get(),
            self.var_custom.get(),
        ]
        if not any(areas):
            messagebox.showwarning(
                "Внимание", "Выберите хотя бы одну область для проверки."
            )
            return
        if self.var_custom.get() and not self.custom_target:
            messagebox.showwarning(
                "Внимание", "Укажите файл или папку для выборочной проверки."
            )
            return

        self.scanning = True
        self.stop_flag = False
        self.threats.clear()
        self.tree_threats.delete(*self.tree_threats.get_children())
        self._update_threat_counter(0)

        self.btn_start.config(state="disabled", bg="#1e293b")
        self.btn_stop.config(state="normal", bg="#dc2626", fg="white")
        self.progress["value"] = 0

        threading.Thread(target=self._scan_worker, daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.lbl_status.config(text="Остановка проверки...")

    def _add_threat_to_ui(self, threat_dict):
        idx = len(self.threats)
        self.threats.append(threat_dict)
        self.tree_threats.insert(
            "",
            "end",
            iid=str(idx),
            values=(
                f"{threat_dict['score']}/100",
                threat_dict["category"],
                threat_dict["target"],
                " | ".join(threat_dict["reasons"]),
            ),
        )
        self._update_threat_counter(len(self.threats))

    def _update_threat_counter(self, count):
        self.btn_cure_all.config(text=f"🛡️ Нейтрализовать все ({count})")

    def _scan_worker(self):
        checked_count = 0

        if self.var_mem.get() and not self.stop_flag:
            self.after(
                0,
                lambda: self.lbl_status.config(
                    text="Проверка активных процессов в памяти..."
                ),
            )
            for score, cat, path, reasons, meta in scan_running_processes():
                checked_count += 1
                item = {
                    "score": score,
                    "category": cat,
                    "target": path,
                    "reasons": reasons,
                    "meta": meta,
                }
                self.after(0, lambda it=item: self._add_threat_to_ui(it))
            self.after(
                0,
                lambda c=checked_count: self.lbl_counters.config(
                    text=f"Проверено: {c} | Угроз: {len(self.threats)}"
                ),
            )

        if self.var_autorun.get() and not self.stop_flag:
            self.after(
                0,
                lambda: self.lbl_status.config(
                    text="Проверка объектов автозапуска реестра..."
                ),
            )
            for score, cat, target, reasons, meta in scan_autorun():
                checked_count += 1
                item = {
                    "score": score,
                    "category": cat,
                    "target": target,
                    "reasons": reasons,
                    "meta": meta,
                }
                self.after(0, lambda it=item: self._add_threat_to_ui(it))
            self.after(
                0,
                lambda c=checked_count: self.lbl_counters.config(
                    text=f"Проверено: {c} | Угроз: {len(self.threats)}"
                ),
            )

        files_to_scan = []
        strict_single = False

        if self.var_custom.get() and self.custom_target and not self.stop_flag:
            if os.path.isfile(self.custom_target):
                files_to_scan.append(self.custom_target)
                strict_single = True
            elif os.path.isdir(self.custom_target):
                self._collect_files(self.custom_target, files_to_scan)

        if self.var_quick.get() and not self.stop_flag:
            home = os.path.expanduser("~")
            quick_dirs = [
                os.path.join(home, "Desktop"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "AppData", "Local"),
                os.path.join(home, "AppData", "Roaming"),
                os.environ.get("ProgramData", "C:\\ProgramData"),
            ]
            for d in quick_dirs:
                if self.stop_flag:
                    break
                self._collect_files(d, files_to_scan)

        files_to_scan = list(dict.fromkeys(files_to_scan))
        total_files = len(files_to_scan)

        if total_files > 0 and not self.stop_flag:
            self.after(0, lambda: self.progress.configure(maximum=total_files))
            workers = max(2, min(8, (os.cpu_count() or 4)))

            with ProcessPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(analyze_file_worker, f, strict_single): f
                    for f in files_to_scan
                }
                for idx, fut in enumerate(as_completed(futures), 1):
                    if self.stop_flag:
                        pool.shutdown(wait=False, cancel_futures=True)
                        break

                    checked_count += 1
                    if idx % 80 == 0 or idx == total_files:
                        short_name = os.path.basename(futures[fut])
                        self.after(
                            0,
                            lambda i=idx, c=checked_count, fn=short_name: (
                                self.progress.configure(value=i),
                                self.lbl_status.config(
                                    text=f"Сканирование: {fn}"
                                ),
                                self.lbl_counters.config(
                                    text=f"Проверено: {c} | Угроз: {len(self.threats)}"
                                ),
                            ),
                        )

                    res = fut.result()
                    if res:
                        score, status, fpath, reasons = res
                        if strict_single and score >= 45:
                            item = {
                                "score": score,
                                "category": status,
                                "target": fpath,
                                "reasons": reasons,
                                "meta": {"type": "file", "path": fpath},
                            }
                            self.after(
                                0, lambda it=item: self._add_threat_to_ui(it)
                            )
                        elif not strict_single:
                            ver = deep_reverify(res)
                            if ver:
                                v_score, v_status, v_path, v_reasons = ver
                                item = {
                                    "score": v_score,
                                    "category": v_status,
                                    "target": v_path,
                                    "reasons": v_reasons,
                                    "meta": {"type": "file", "path": v_path},
                                }
                                self.after(
                                    0,
                                    lambda it=item: self._add_threat_to_ui(it),
                                )

        self.after(0, lambda c=checked_count: self._finish_scan(c))

    def _collect_files(self, base_dir, out_list):
        if not os.path.isdir(base_dir):
            return
        self.after(
            0, lambda d=base_dir: self.lbl_status.config(text=f"Индексация: {d}")
        )
        for root, dirs, fnames in os.walk(base_dir):
            if self.stop_flag:
                break
            dirs[:] = [
                d for d in dirs if not is_excluded(os.path.join(root, d))
            ]
            for fn in fnames:
                fp = os.path.join(root, fn)
                if not is_excluded(fp):
                    out_list.append(fp)

    def _finish_scan(self, checked_count):
        self.scanning = False
        self.btn_start.config(state="normal", bg="#00a88e")
        self.btn_stop.config(state="disabled", bg="#1e293b", fg="#94a3b8")

        state_txt = (
            "Проверка прервана пользователем."
            if self.stop_flag
            else "Проверка успешно завершена!"
        )
        self.lbl_status.config(text=state_txt)
        self.lbl_counters.config(
            text=f"Проверено: {checked_count} | Угроз: {len(self.threats)}"
        )

        if not self.stop_flag:
            if len(self.threats) == 0:
                messagebox.showinfo(
                    "KVRT — Результат",
                    f"Угроз не обнаружено!\nПроверено объектов: {checked_count}",
                )
            else:
                messagebox.showwarning(
                    "KVRT — Обнаружены угрозы",
                    f"Найдено угроз: {len(self.threats)}.\n"
                    "Выберите действие в таблице или нажмите «Нейтрализовать все».",
                )
    def _get_selected_index(self):
        sel = self.tree_threats.selection()
        if not sel:
            messagebox.showinfo("Выбор объекта", "Выберите угрозу в списке.")
            return None
        return int(sel)

    def _neutralize_item(self, idx, mode="cure"):
        item = self.threats[idx]
        if item is None:
            return False
        meta = item["meta"]
        mtype = meta["type"]

        try:
            if mtype == "process":
                kill_process_by_pid(meta["pid"])
                fpath = meta["path"]
                if os.path.exists(fpath):
                    if mode == "quarantine":
                        self._move_to_quarantine(fpath)
                    else:
                        os.remove(fpath)
                return True

            elif mtype == "autorun":
                return remove_autorun_entry(
                    meta["hive"], meta["subkey"], meta["name"]
                )

            elif mtype == "file":
                fpath = meta["path"]
                if os.path.exists(fpath):
                    if mode == "quarantine":
                        self._move_to_quarantine(fpath)
                    else:
                        os.remove(fpath)
                return True
        except Exception as e:
            messagebox.showerror(
                "Ошибка лечения", f"Не удалось обработать объект:\n{e}"
            )
            return False
        return False

    def _move_to_quarantine(self, fpath):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        q_name = f"{ts}_{os.path.basename(fpath)}.quarantined"
        q_path = os.path.join(QUARANTINE_DIR, q_name)
        shutil.move(fpath, q_path)

        meta_info = {
            "orig_path": os.path.abspath(fpath),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(q_path + ".meta", "w", encoding="utf-8") as mf:
            json.dump(meta_info, mf, ensure_ascii=False)
        self.refresh_quarantine_list()

    def cure_selected(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        if self._neutralize_item(idx, mode="cure"):
            self.threats[idx] = None
            self.tree_threats.delete(str(idx))
            rem = sum(1 for x in self.threats if x is not None)
            self._update_threat_counter(rem)

    def quarantine_selected(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        if self.threats[idx]["meta"]["type"] == "autorun":
            messagebox.showinfo(
                "Карантин",
                "Записи реестра нельзя поместить в карантин. Нажмите «Лечить / Удалить».",
            )
            return
        if self._neutralize_item(idx, mode="quarantine"):
            self.threats[idx] = None
            self.tree_threats.delete(str(idx))
            rem = sum(1 for x in self.threats if x is not None)
            self._update_threat_counter(rem)

    def ignore_selected(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        meta = self.threats[idx]["meta"]
        if meta["type"] in ("file", "process"):
            add_to_whitelist(meta["path"])
        self.threats[idx] = None
        self.tree_threats.delete(str(idx))
        rem = sum(1 for x in self.threats if x is not None)
        self._update_threat_counter(rem)

    def neutralize_all(self):
        active = [i for i, x in enumerate(self.threats) if x is not None]
        if not active:
            return
        if not messagebox.askyesno(
            "Подтверждение",
            f"Нейтрализовать все найденные угрозы ({len(active)} шт.)?",
        ):
            return
        for idx in active:
            if self._neutralize_item(idx, mode="cure"):
                self.threats[idx] = None
                self.tree_threats.delete(str(idx))
        rem = sum(1 for x in self.threats if x is not None)
        self._update_threat_counter(rem)

    def refresh_quarantine_list(self):
        self.tree_quar.delete(*self.tree_quar.get_children())
        if not os.path.isdir(QUARANTINE_DIR):
            return
        for fn in os.listdir(QUARANTINE_DIR):
            if not fn.endswith(".quarantined"):
                continue
            q_path = os.path.join(QUARANTINE_DIR, fn)
            meta_path = q_path + ".meta"
            orig_path, dt = "Неизвестно", "—"
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        data = json.load(mf)
                        orig_path = data.get("orig_path", orig_path)
                        dt = data.get("date", dt)
                except Exception:
                    pass
            clean_name = fn.replace(".quarantined", "")
            self.tree_quar.insert(
                "", "end", iid=fn, values=(dt, clean_name, orig_path)
            )

    def restore_quarantined(self):
        sel = self.tree_quar.selection()
        if not sel:
            return
        fn = sel
        q_path = os.path.join(QUARANTINE_DIR, fn)
        meta_path = q_path + ".meta"
        orig_path = self.tree_quar.item(fn, "values")

        try:
            if orig_path != "Неизвестно":
                os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                shutil.move(q_path, orig_path)
                add_to_whitelist(orig_path)
            else:
                dst = filedialog.asksaveasfilename(
                    initialfile=fn.replace(".quarantined", "")
                )
                if not dst:
                    return
                shutil.move(q_path, dst)
            if os.path.exists(meta_path):
                os.remove(meta_path)
            self.refresh_quarantine_list()
            messagebox.showinfo(
                "Карантин", "Файл восстановлен и добавлен в белый список."
            )
        except Exception as e:
            messagebox.showerror(
                "Ошибка", f"Не удалось восстановить файл:\n{e}"
            )

    def delete_quarantined(self):
        sel = self.tree_quar.selection()
        if not sel:
            return
        fn = sel
        if not messagebox.askyesno(
            "Удаление",
            "Удалить файл из карантина без возможности восстановления?",
        ):
            return
        q_path = os.path.join(QUARANTINE_DIR, fn)
        meta_path = q_path + ".meta"
        try:
            if os.path.exists(q_path):
                os.remove(q_path)
            if os.path.exists(meta_path):
                os.remove(meta_path)
            self.refresh_quarantine_list()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось удалить:\n{e}")

    def toggle_shield(self):
        self.shield_active = not self.shield_active
        if self.shield_active:
            self.btn_shield.config(text="⏹ Остановить защиту 24/7", bg="#dc2626")
            self.shield_log.insert(
                "end",
                "[Монитор 24/7] Защита Загрузок и Рабочего стола активна...\n",
            )
            threading.Thread(target=self._shield_loop, daemon=True).start()
        else:
            self.btn_shield.config(
                text="▶ Включить защиту Загрузок и Рабочего стола",
                bg="#00a88e",
            )
            self.shield_log.insert("end", "[Монитор 24/7] Остановлен.\n")

    def _shield_loop(self):
        watch_dirs = [
            os.path.join(os.path.expanduser("~"), d)
            for d in ("Downloads", "Desktop")
        ]
        seen = {
            os.path.join(d, fn)
            for d in watch_dirs
            if os.path.isdir(d)
            for fn in os.listdir(d)
        }
        while self.shield_active:
            for d in watch_dirs:
                if not os.path.isdir(d):
                    continue
                for fn in os.listdir(d):
                    fp = os.path.join(d, fn)
                    if (
                        fp not in seen
                        and os.path.isfile(fp)
                        and not is_excluded(fp)
                    ):
                        seen.add(fp)
                        res = analyze_file_worker(fp, strict_mode=False)
                        if res and (ver := deep_reverify(res)):
                            self.after(
                                0, lambda v=ver: self._alert_shield(v)
                            )
            threading.Event().wait(2.0)

    def _alert_shield(self, threat):
        score, _, path, reasons = threat
        self.shield_log.insert(
            "end", f"⚠️ ОБНАРУЖЕНА УГРОЗА [{score}/100]: {path}\n"
        )
        self.shield_log.see("end")
        if messagebox.askyesno(
            "Монитор 24/7 — Обнаружена угроза!",
            f"Файл: {path}\nОпасность: {score}/100\nПричина: {reasons}\n\n"
            "Переместить файл в карантин прямо сейчас?",
        ):
            try:
                self._move_to_quarantine(path)
                self.shield_log.insert(
                    "end", f"📦 Файл изолирован в карантин: {path}\n"
                )
            except Exception as e:
                self.shield_log.insert("end", f"Ошибка изоляции: {e}\n")

    def refresh_network_tab(self):
        self.tree_net.delete(*self.tree_net.get_children())
        for row in get_active_connections():
            self.tree_net.insert("", "end", values=row)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    _mutex = check_single_instance()
    app = AntivirusKVRTApp()
    app.mainloop()
