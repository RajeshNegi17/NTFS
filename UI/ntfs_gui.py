import os
import struct
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

# Placeholder imports for NTFS logic (to be integrated)
# from ..new_extract import list_drives, scan_drive, recover_files

# --- NTFS Utility Functions (from new_extract.py) ---
def get_cluster_size(drive_letter):
    sectors_per_cluster = ctypes.c_ulong()
    bytes_per_sector = ctypes.c_ulong()
    num_free_clusters = ctypes.c_ulong()
    total_clusters = ctypes.c_ulong()
    ret = ctypes.windll.kernel32.GetDiskFreeSpaceW(
        f"{drive_letter}:\\",
        ctypes.byref(sectors_per_cluster),
        ctypes.byref(bytes_per_sector),
        ctypes.byref(num_free_clusters),
        ctypes.byref(total_clusters)
    )
    if ret == 0:
        raise ctypes.WinError()
    return sectors_per_cluster.value * bytes_per_sector.value

def detect_mft_offset(f, cluster_size):
    f.seek(0)
    boot_sector = f.read(512)
    mft_cluster = struct.unpack_from("<Q", boot_sector, 48)[0]
    return mft_cluster * cluster_size

def list_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drives.append(chr(65 + i))
    return drives

def parse_attributes(record_raw):
    offset = struct.unpack_from("<H", record_raw, 20)[0]
    attrs = []
    while offset < 1024:
        attr_type = struct.unpack_from("<I", record_raw, offset)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_len = struct.unpack_from("<I", record_raw, offset + 4)[0]
        non_resident = struct.unpack_from("<B", record_raw, offset + 8)[0]
        content_offset = struct.unpack_from("<H", record_raw, offset + 20)[0]
        attr = {
            "type": attr_type,
            "length": attr_len,
            "non_resident": non_resident,
            "content_offset": content_offset,
            "raw": record_raw[offset:offset + attr_len]
        }
        attrs.append(attr)
        offset += attr_len
    return attrs

def extract_filename(attr):
    try:
        name_len = attr['raw'][88]
        name = attr['raw'][90:90 + name_len * 2].decode('utf-16le', errors='ignore')
        return name
    except:
        return None

def extract_resident_data(attr):
    try:
        content_len = struct.unpack_from("<I", attr['raw'], 16)[0]
        content_offset = struct.unpack_from("<H", attr['raw'], 20)[0]
        return attr['raw'][content_offset:content_offset + content_len]
    except:
        return None

def parse_runlist(runlist_bytes):
    runs = []
    i = 0
    prev_offset = 0
    while i < len(runlist_bytes) and runlist_bytes[i] != 0x00:
        header = runlist_bytes[i]
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        i += 1
        length = int.from_bytes(runlist_bytes[i:i + len_size], 'little')
        i += len_size
        offset_raw = runlist_bytes[i:i + off_size]
        offset = int.from_bytes(offset_raw + (b'\x00' * (8 - off_size)), 'little', signed=True)
        i += off_size
        prev_offset += offset
        runs.append((prev_offset, length))
    return runs

def extract_non_resident_data(attr, cluster_size, f, max_bytes=100 * 1024 * 1024):
    start = 0x40
    runlist = attr['raw'][start:]
    runs = parse_runlist(runlist)
    data = bytearray()
    total_read = 0
    for cluster_num, length in runs:
        for i in range(length):
            if total_read >= max_bytes:
                print("[!] Truncated large file to avoid memory error.")
                return data
            f.seek((cluster_num + i) * cluster_size)
            chunk = f.read(cluster_size)
            if not chunk:
                break
            data += chunk
            total_read += len(chunk)
    return data

# --- NTFS Scanning and Recovery Logic ---
def scan_ntfs_drive(drive_letter, max_records=1000000):
    """Scan the NTFS drive and return a list of (record_id, filename, label) tuples."""
    found_files = []
    try:
        cluster_size = get_cluster_size(drive_letter)
        img_path = r"\\.\{}:".format(drive_letter)
        with open(img_path, 'rb') as f:
            mft_offset = detect_mft_offset(f, cluster_size)
            for i in range(max_records):
                record_offset = mft_offset + i * 1024
                f.seek(record_offset)
                record_raw = f.read(1024)
                if record_raw[0:4] != b'FILE':
                    continue
                flags = struct.unpack_from("<H", record_raw, 22)[0]
                is_deleted = (flags & 0x01) == 0
                try:
                    attrs = parse_attributes(record_raw)
                except Exception:
                    continue
                filename = None
                for attr in attrs:
                    if attr['type'] == 0x30 and filename is None:
                        filename = extract_filename(attr)
                if filename:
                    label = "deleted" if is_deleted else "recovered"
                    found_files.append((i, filename, label))
    except Exception as e:
        return [], str(e)
    return found_files, None

def recover_selected_files(drive_letter, selected_records, max_records=1000000):
    """Recover the selected files by record_id. selected_records is a set of record_ids."""
    summary_lines = []
    try:
        cluster_size = get_cluster_size(drive_letter)
        img_path = r"\\.\{}:".format(drive_letter)
        os.makedirs("output/recovered", exist_ok=True)
        os.makedirs("output/deleted", exist_ok=True)
        with open(img_path, 'rb') as f:
            mft_offset = detect_mft_offset(f, cluster_size)
            for i in range(max_records):
                if i not in selected_records:
                    continue
                record_offset = mft_offset + i * 1024
                f.seek(record_offset)
                record_raw = f.read(1024)
                if record_raw[0:4] != b'FILE':
                    continue
                flags = struct.unpack_from("<H", record_raw, 22)[0]
                is_deleted = (flags & 0x01) == 0
                try:
                    attrs = parse_attributes(record_raw)
                except Exception:
                    continue
                filename = None
                data = None
                for attr in attrs:
                    if attr['type'] == 0x30 and filename is None:
                        filename = extract_filename(attr)
                    elif attr['type'] == 0x80 and data is None:
                        if attr['non_resident'] == 0:
                            data = extract_resident_data(attr)
                        else:
                            data = extract_non_resident_data(attr, cluster_size, f)
                if filename and data:
                    label = "deleted" if is_deleted else "recovered"
                    safe_name = filename.replace("/", "_").replace("\\", "_")
                    out_name = f"{label}_{i}_{safe_name}"
                    out_path = f"output/{label}/{out_name}"
                    try:
                        with open(out_path, 'wb') as out:
                            out.write(data)
                        summary_lines.append(f"{label.upper()}: Record {i} | Filename: {filename}")
                    except Exception as e:
                        summary_lines.append(f"FAILED: Record {i} | Filename: {filename} | Error: {e}")
    except Exception as e:
        return False, str(e)
    # Write report
    report_path = "output/recovery_report.txt"
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Recovered Files Summary Report\n")
        report.write("="*35 + "\n\n")
        report.write("\n".join(summary_lines))
    return True, report_path

# --- GUI Application ---
class NTFSRecoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NTFS File Recovery")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.configure(bg="#f4f4f4")
        self.found_files = []
        self.drive_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")
        self.mode_var = tk.StringVar(value='all')
        self.create_styles()
        self.create_widgets()
        self.drive_var.set("")

    def create_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 14), background="#f4f4f4")
        style.configure("TButton", font=("Segoe UI", 14), padding=10, relief="flat", foreground="#fff", background="#4a90e2")
        style.map("TButton", background=[("active", "#357ABD")])
        style.configure("Treeview.Heading", font=("Segoe UI", 14, "bold"))
        style.configure("Treeview", font=("Segoe UI", 13), rowheight=32)
        style.configure("TRadiobutton", font=("Segoe UI", 13), background="#f4f4f4")
        style.configure("TCombobox", font=("Segoe UI", 13))

    def create_widgets(self):
        # Header
        header = ttk.Label(self, text="NTFS File Recovery Tool", font=("Segoe UI", 22, "bold"), background="#f4f4f4", foreground="#333")
        header.pack(pady=(20, 10))

        # Drive selection
        drive_frame = ttk.Frame(self, style="TFrame")
        drive_frame.pack(fill='x', padx=20, pady=10)
        ttk.Label(drive_frame, text="Select Drive:").pack(side='left', padx=(0, 10))
        self.drive_combo = ttk.Combobox(drive_frame, textvariable=self.drive_var, state='readonly', width=8)
        self.drive_combo['values'] = list_drives()
        self.drive_combo.pack(side='left', padx=5)
        if self.drive_combo['values']:
            self.drive_combo.current(0)
            self.drive_var.set(self.drive_combo['values'][0])

        # Recovery mode
        mode_frame = ttk.Frame(self, style="TFrame")
        mode_frame.pack(fill='x', padx=20, pady=10)
        ttk.Label(mode_frame, text="Recovery Mode:").pack(side='left', padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="Recover All", variable=self.mode_var, value='all', style="TRadiobutton").pack(side='left', padx=10)
        ttk.Radiobutton(mode_frame, text="Select Files", variable=self.mode_var, value='select', style="TRadiobutton").pack(side='left', padx=10)
        scan_btn = ttk.Button(mode_frame, text="Scan Drive", command=self.scan_drive)
        scan_btn.pack(side='right', padx=10)

        # File list (Treeview with scrollbar)
        list_frame = ttk.Frame(self, style="TFrame")
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)
        columns = ("Record ID", "Filename", "Status")
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', selectmode='extended', height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=300 if col == "Filename" else 150, anchor='center')
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        # Recovery button
        btn_frame = ttk.Frame(self, style="TFrame")
        btn_frame.pack(fill='x', padx=20, pady=10)
        self.recover_btn = ttk.Button(btn_frame, text="Start Recovery", command=self.start_recovery)
        self.recover_btn.pack(side='right', padx=10)

        # Status bar
        status_bar = tk.Label(self, textvariable=self.status_var, font=("Segoe UI", 13, "bold"), bg="#e0e0e0", anchor='w', relief='sunken', bd=2, height=2)
        status_bar.pack(fill='x', side='bottom', pady=(0, 0))

    def scan_drive(self):
        drive = self.drive_var.get()
        if not drive:
            self.status_var.set("No drive selected.")
            return
        self.status_var.set(f"Scanning drive {drive}...")
        self.tree.delete(*self.tree.get_children())
        def do_scan():
            files, err = scan_ntfs_drive(drive)
            self.found_files = files
            if err:
                self.status_var.set(f"Scan failed: {err}")
                messagebox.showerror("Scan Error", err)
                return
            for rec_id, fname, status in files:
                self.tree.insert('', 'end', values=(rec_id, fname, status))
            self.status_var.set(f"Scan complete. {len(files)} files found.")
        threading.Thread(target=do_scan, daemon=True).start()

    def start_recovery(self):
        mode = self.mode_var.get()
        if mode == 'all':
            selected_records = set(rec_id for rec_id, _, _ in self.found_files)
        else:
            selected_indices = self.tree.selection()
            if not selected_indices:
                messagebox.showwarning("No Selection", "Please select files to recover.")
                return
            selected_records = set(self.found_files[self.tree.index(i)][0] for i in selected_indices)
        drive = self.drive_var.get()
        self.status_var.set("Recovering files...")
        def do_recover():
            success, result = recover_selected_files(drive, selected_records)
            if success:
                self.status_var.set(f"Recovery complete. See report: {result}")
                messagebox.showinfo("Success", f"Files recovered successfully.\nReport: {result}")
            else:
                self.status_var.set(f"Recovery failed: {result}")
                messagebox.showerror("Error", f"Recovery failed: {result}")
        threading.Thread(target=do_recover, daemon=True).start()

if __name__ == "__main__":
    app = NTFSRecoveryApp()
    app.mainloop() 