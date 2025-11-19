import csv
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


DEFAULT_KEYWORDS = [
    "drugs",
    "cocaine",
    "heroin",
    "weed",
    "marijuana",
    "gun",
    "guns",
    "weapon",
    "pistol",
    "rifle",
    "credit card",
    "cvv",
    "carding",
    "hack",
    "hacking",
    "exploit",
    "botnet",
    "malware",
    "ransomware",
    "zero-day",
    "phishing",
    "forged documents",
    "counterfeit",
]


@dataclass
class FlaggedEntry:
    """Represents a single flagged log line."""

    line_number: int
    text: str
    matched_keywords: List[str]
    risk_score: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


class LogAnalyzer:
    """Handles keyword management and line analysis."""

    def __init__(self, keywords: Optional[List[str]] = None) -> None:
        self._default_keywords = list(DEFAULT_KEYWORDS)
        self.keywords = keywords or list(DEFAULT_KEYWORDS)

    def set_keywords(self, keywords: List[str]) -> None:
        self.keywords = [kw.strip() for kw in keywords if kw.strip()]

    def reset_keywords(self) -> None:
        self.keywords = list(self._default_keywords)

    def analyze_line(self, line: str, line_number: int) -> Optional[FlaggedEntry]:
        lowered = line.lower()
        matches = sorted({kw for kw in self.keywords if kw.lower() in lowered})
        if not matches:
            return None
        score = len(matches)
        return FlaggedEntry(line_number=line_number, text=line.strip(), matched_keywords=matches, risk_score=score)


class LogWatcher:
    """Watches a log file for appended lines and analyses them."""

    def __init__(self, filepath: str, analyzer: LogAnalyzer, callback: Callable[[FlaggedEntry], None], poll_interval: float = 1.0) -> None:
        self.filepath = filepath
        self.analyzer = analyzer
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, name="LogWatcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _watch_loop(self) -> None:
        try:
            line_number = 0
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_number, _ in enumerate(f, start=1):
                    pass
                while not self._stop_event.is_set():
                    if not os.path.exists(self.filepath):
                        raise FileNotFoundError
                    position = f.tell()
                    line = f.readline()
                    if not line:
                        time.sleep(self.poll_interval)
                        f.seek(position)
                        continue
                    line_number += 1
                    entry = self.analyzer.analyze_line(line, line_number)
                    if entry:
                        self.callback(entry)
        except FileNotFoundError:
            self.callback(
                FlaggedEntry(
                    line_number=0,
                    text=f"File not found: {self.filepath}",
                    matched_keywords=["error"],
                    risk_score=0,
                )
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.callback(
                FlaggedEntry(
                    line_number=0,
                    text=f"Watcher error: {exc}",
                    matched_keywords=["error"],
                    risk_score=0,
                )
            )


class TorMonitorApp(tk.Tk):
    """Tkinter desktop application for defensive Tor log monitoring."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Tor Defensive Monitor")
        self.geometry("1100x700")

        self.analyzer = LogAnalyzer()
        self.log_file_path: Optional[str] = None
        self.results: List[FlaggedEntry] = []
        self.result_queue: "queue.Queue[FlaggedEntry]" = queue.Queue()
        self.log_watcher: Optional[LogWatcher] = None

        self._build_gui()
        self._configure_tree_tags()
        self.after(500, self._process_queue)

    # GUI construction --------------------------------------------------
    def _build_gui(self) -> None:
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._build_tor_settings(main_frame)
        self._build_middle_section(main_frame)
        self._build_results_table(main_frame)
        self._build_status_bar()

    def _build_tor_settings(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Tor Connection Settings")
        frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(frame, text="SOCKS Host:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.proxy_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frame, textvariable=self.proxy_host_var, width=20).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        self.proxy_port_var = tk.StringVar(value="9150")
        ttk.Entry(frame, textvariable=self.proxy_port_var, width=10).grid(row=0, column=3, padx=5, pady=5)

        self.tor_test_button = ttk.Button(frame, text="Test Tor Connection", command=self.test_tor_connection)
        self.tor_test_button.grid(row=0, column=4, padx=10, pady=5)

        self.tor_status_var = tk.StringVar(value="Tor status: Not tested")
        ttk.Label(frame, textvariable=self.tor_status_var).grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

    def _build_middle_section(self, parent: ttk.Frame) -> None:
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=tk.BOTH, expand=True)

        self._build_log_controls(middle_frame)
        self._build_keyword_editor(middle_frame)

    def _build_log_controls(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Log Controls")
        frame.pack(side=tk.LEFT, fill=tk.Y, expand=True, padx=(0, 10))

        self.log_path_var = tk.StringVar(value="No file selected")
        log_entry = ttk.Entry(frame, textvariable=self.log_path_var, state="readonly")
        log_entry.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(frame, text="Select Log File…", command=self.select_log_file).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(frame, text="Scan Log Once", command=self.scan_log_once).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(frame, text="Start Live Monitor", command=self.start_monitor).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(frame, text="Stop Monitor", command=self.stop_monitor).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(frame, text="Export Flags to CSV", command=self.export_to_csv).pack(fill=tk.X, padx=5, pady=5)

    def _build_keyword_editor(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Keyword List")
        frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        columns = ("keyword",)
        self.keyword_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="extended",
            height=15,
        )
        self.keyword_tree.heading("keyword", text="Keyword / Phrase")
        self.keyword_tree.column("keyword", anchor=tk.W)
        self.keyword_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.keyword_tree.yview)
        self.keyword_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)

        self._refresh_keyword_tree()

        entry_frame = ttk.Frame(frame)
        entry_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(entry_frame, text="New keyword:").pack(side=tk.LEFT)
        self.new_keyword_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.new_keyword_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(entry_frame, text="Add", command=self.add_keyword).pack(side=tk.LEFT)

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected_keywords).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_keywords).pack(side=tk.LEFT, padx=5)

    def _build_results_table(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Flagged Log Entries")
        frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        columns = ("line", "keywords", "score", "text")
        self.results_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        self.results_tree.heading("line", text="Line #")
        self.results_tree.heading("keywords", text="Matched Keywords")
        self.results_tree.heading("score", text="Risk Score")
        self.results_tree.heading("text", text="Log Text")

        self.results_tree.column("line", width=60, anchor=tk.CENTER)
        self.results_tree.column("keywords", width=220)
        self.results_tree.column("score", width=80, anchor=tk.CENTER)
        self.results_tree.column("text", width=600)

        self.results_tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _configure_tree_tags(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.results_tree.tag_configure("low", background="#f2fff2")
        self.results_tree.tag_configure("medium", background="#fff9e6")
        self.results_tree.tag_configure("high", background="#ffeaea")
        self.results_tree.tag_configure("error", background="#f5f5f5")

    def _build_status_bar(self) -> None:
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # Keyword management ------------------------------------------------
    def _refresh_keyword_tree(self) -> None:
        for item in self.keyword_tree.get_children():
            self.keyword_tree.delete(item)
        for kw in self.analyzer.keywords:
            self.keyword_tree.insert("", tk.END, values=(kw,))

    def add_keyword(self) -> None:
        keyword = self.new_keyword_var.get().strip()
        if not keyword:
            return
        self.analyzer.keywords.append(keyword)
        self.new_keyword_var.set("")
        self._refresh_keyword_tree()

    def remove_selected_keywords(self) -> None:
        selections = self.keyword_tree.selection()
        if not selections:
            return
        selected_keywords = {self.keyword_tree.item(item, "values")[0] for item in selections}
        self.analyzer.keywords = [kw for kw in self.analyzer.keywords if kw not in selected_keywords]
        self._refresh_keyword_tree()

    def reset_keywords(self) -> None:
        self.analyzer.reset_keywords()
        self._refresh_keyword_tree()

    # Log control actions ----------------------------------------------
    def select_log_file(self) -> None:
        filepath = filedialog.askopenfilename(title="Select log file", filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
        if filepath:
            self.log_file_path = filepath
            self.log_path_var.set(filepath)
            self.status_var.set(f"Selected log: {filepath}")

    def scan_log_once(self) -> None:
        if not self.log_file_path:
            messagebox.showerror("No file", "Please select a log file first.")
            return
        if not os.path.isfile(self.log_file_path):
            messagebox.showerror("File missing", "The selected log file could not be found.")
            self.status_var.set("Log file not found")
            return
        self.status_var.set("Scanning…")
        self.update_idletasks()
        self.results.clear()
        self.results_tree.delete(*self.results_tree.get_children())
        try:
            with open(self.log_file_path, "r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    entry = self.analyzer.analyze_line(line, idx)
                    if entry:
                        self._add_result(entry)
            self.status_var.set("Scan completed")
        except FileNotFoundError:
            self.status_var.set("Log file not found")
            messagebox.showerror("File missing", "The selected log file could not be found.")
        except Exception as exc:  # pragma: no cover - defensive
            self.status_var.set("Error during scan")
            messagebox.showerror("Error", f"An error occurred while scanning: {exc}")

    def start_monitor(self) -> None:
        if not self.log_file_path:
            messagebox.showerror("No file", "Please select a log file before starting monitoring.")
            return
        if not os.path.isfile(self.log_file_path):
            messagebox.showerror("File missing", "The selected log file could not be found.")
            self.status_var.set("Log file not found")
            return
        if self.log_watcher:
            self.log_watcher.stop()
        self.log_watcher = LogWatcher(self.log_file_path, self.analyzer, self.result_queue.put)
        self.log_watcher.start()
        self.status_var.set("Monitoring…")

    def stop_monitor(self) -> None:
        if self.log_watcher:
            self.log_watcher.stop()
            self.log_watcher = None
        self.status_var.set("Monitoring stopped")

    # Results & exporting ----------------------------------------------
    def _add_result(self, entry: FlaggedEntry) -> None:
        self.results.append(entry)
        keywords_text = ", ".join(entry.matched_keywords)
        truncated_text = entry.text
        if len(truncated_text) > 200:
            truncated_text = truncated_text[:197] + "…"
        tag = self._risk_tag(entry)
        self.results_tree.insert("", tk.END, values=(entry.line_number, keywords_text, entry.risk_score, truncated_text), tags=(tag,))

    def _risk_tag(self, entry: FlaggedEntry) -> str:
        if "error" in entry.matched_keywords:
            return "error"
        if entry.risk_score >= 3:
            return "high"
        if entry.risk_score == 2:
            return "medium"
        return "low"

    def export_to_csv(self) -> None:
        if not self.results:
            messagebox.showinfo("No data", "No flagged entries to export.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not filepath:
            return
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["timestamp_of_export", "line_number", "matched_keywords", "risk_score", "log_line_text", "log_file_path"])
                timestamp = datetime.utcnow().isoformat()
                for entry in self.results:
                    writer.writerow([
                        timestamp,
                        entry.line_number,
                        ";".join(entry.matched_keywords),
                        entry.risk_score,
                        entry.text,
                        self.log_file_path or "",
                    ])
            messagebox.showinfo("Export complete", f"Flagged entries exported to {filepath}")
        except Exception as exc:  # pragma: no cover - defensive
            messagebox.showerror("Export failed", f"Could not export CSV: {exc}")

    # Background processing --------------------------------------------
    def _process_queue(self) -> None:
        while not self.result_queue.empty():
            entry = self.result_queue.get()
            if entry.line_number == 0 and "error" in entry.matched_keywords:
                self.status_var.set(entry.text)
                if self.log_watcher:
                    self.log_watcher.stop()
                    self.log_watcher = None
                messagebox.showerror("Monitoring error", entry.text)
            else:
                self._add_result(entry)
                self.status_var.set(f"Monitoring… Last match at line {entry.line_number}")
        self.after(500, self._process_queue)

    # Tor connection testing -------------------------------------------
    def test_tor_connection(self) -> None:
        host = self.proxy_host_var.get().strip()
        port = self.proxy_port_var.get().strip()
        if not host or not port.isdigit():
            messagebox.showerror("Invalid proxy", "Please enter a valid host and numeric port.")
            return
        self.tor_status_var.set("Testing Tor connection…")
        self.tor_test_button.configure(state=tk.DISABLED)
        threading.Thread(target=self._perform_tor_test, args=(host, port), daemon=True).start()

    def _perform_tor_test(self, host: str, port: str) -> None:
        try:
            proxies = {
                "http": f"socks5h://{host}:{port}",
                "https": f"socks5h://{host}:{port}",
            }
            response = requests.get("https://check.torproject.org/", proxies=proxies, timeout=15)
            if response.status_code == 200:
                self.tor_status_var.set("Tor status: Success")
            else:
                self.tor_status_var.set(f"Tor status: HTTP {response.status_code}")
        except Exception as exc:
            self.tor_status_var.set(f"Tor status: Failed ({exc})")
        finally:
            self.tor_test_button.configure(state=tk.NORMAL)


def main() -> None:
    app = TorMonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
