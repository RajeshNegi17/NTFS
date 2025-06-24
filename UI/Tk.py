import os
import struct
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ctypes
import customtkinter as ctk

ctk.set_appearance_mode("System")  
ctk.set_default_color_theme("blue") 

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
                return data
            f.seek((cluster_num + i) * cluster_size)
            chunk = f.read(cluster_size)
            if not chunk:
                break
            data += chunk
            total_read += len(chunk)

    return data

class NTFSRecoveryGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NTFS File Recovery Tool")
        self.geometry("850x700")
        self.resizable(True, True)

        self.drive_letter = tk.StringVar()
        self.files_found = []
        self.build_gui()

    def build_gui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        top_frame = ctk.CTkFrame(self)
        top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        top_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(top_frame, text="Select Drive:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
        self.drive_menu = ctk.CTkComboBox(top_frame, variable=self.drive_letter, values=list_drives(), state="readonly")
        self.drive_menu.grid(row=0, column=1, padx=5, pady=5)
        
        self.scan_button = ctk.CTkButton(top_frame, text="Scan Drive", command=self.scan_drive)
        self.scan_button.grid(row=0, column=2, padx=10, pady=5, sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(top_frame)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=3, padx=10, pady=5, sticky="ew")


        middle_frame = ctk.CTkFrame(self)
        middle_frame.grid(row=1, column=0, padx=10, pady=0, sticky="ew")
        middle_frame.grid_columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(middle_frame, placeholder_text="Search/Filter files...")
        self.search_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self.filter_files)

        self.file_list_frame = ctk.CTkFrame(self)
        self.file_list_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        self.file_list_frame.grid_rowconfigure(0, weight=1)
        self.file_list_frame.grid_columnconfigure(0, weight=1)
        
        self.create_file_tree()


        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        bottom_frame.grid_columnconfigure(0, weight=1)
        
        self.recover_selected_button = ctk.CTkButton(bottom_frame, text="Recover Selected", command=self.recover_selected)
        self.recover_selected_button.pack(side="left", padx=10, pady=5)

        self.recover_all_button = ctk.CTkButton(bottom_frame, text="Recover All Visible", command=self.recover_all_visible)
        self.recover_all_button.pack(side="left", padx=10, pady=5)

        self.log_box = ctk.CTkTextbox(self, height=150, font=("Courier", 10))
        self.log_box.grid(row=4, column=0, padx=10, pady=10, sticky="nsew")

    def create_file_tree(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#2a2d2e",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#343638",
                        bordercolor="#343638",
                        borderwidth=0)
        style.map('Treeview', background=[('selected', '#22559b')])
        style.configure("Treeview.Heading",
                        background="#565b5e",
                        foreground="white",
                        relief="flat")
        style.map("Treeview.Heading",
                  background=[('active', '#3484F0')])

        self.file_tree = ttk.Treeview(self.file_list_frame, columns=("ID", "Filename", "Status"), show='headings')
        self.file_tree.heading("ID", text="ID")
        self.file_tree.heading("Filename", text="Filename")
        self.file_tree.heading("Status", text="Status")
        self.file_tree.column("ID", width=50, anchor='center')
        self.file_tree.column("Filename", width=400)
        self.file_tree.column("Status", width=100, anchor='center')
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        
        vsb = ttk.Scrollbar(self.file_list_frame, orient="vertical", command=self.file_tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.file_tree.configure(yscrollcommand=vsb.set)


    def log(self, msg):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    def scan_drive(self):
        self.file_tree.delete(*self.file_tree.get_children())
        self.files_found.clear()
        drive = self.drive_letter.get()
        if not drive:
            messagebox.showerror("Error", "Please select a drive.")
            return

        self.scan_button.configure(state="disabled")
        self.progress_bar.set(0)
        
        try:
            cluster_size = get_cluster_size(drive)
            path = r"\\.\{}:".format(drive)

            with open(path, 'rb') as f:
                mft_offset = detect_mft_offset(f, cluster_size)
                total_records_to_scan = 100000 

                for i in range(total_records_to_scan):
                    self.update()
                    if i % (total_records_to_scan // 100) == 0:
                        self.progress_bar.set(i / total_records_to_scan)

                    f.seek(mft_offset + i * 1024)
                    record_raw = f.read(1024)
                    if record_raw[0:4] != b'FILE':
                        continue

                    flags = struct.unpack_from("<H", record_raw, 22)[0]
                    is_deleted = not (flags & 0x01)

                    attrs = parse_attributes(record_raw)
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
                        status = "Deleted" if is_deleted else "Active"
                        self.files_found.append({'id': i, 'name': filename, 'status': status, 'data': data})
                        self.file_tree.insert("", "end", values=(i, filename, status))
            
            self.progress_bar.set(1)
            self.log(f"[✓] Scan complete. {len(self.files_found)} files found.")

        except Exception as e:
            self.log(f"[!] Scan failed: {e}")
        finally:
            self.scan_button.configure(state="normal")

    def filter_files(self, event=None):
        query = self.search_entry.get().lower()
        self.file_tree.delete(*self.file_tree.get_children())
        for file_info in self.files_found:
            if query in file_info['name'].lower():
                self.file_tree.insert("", "end", values=(file_info['id'], file_info['name'], file_info['status']))


    def recover_selected(self):
        selected_items = self.file_tree.selection()
        if not selected_items:
            self.log("[!] No files selected for recovery.")
            return

        output_dir = filedialog.askdirectory(title="Select Recovery Folder")
        if not output_dir:
            return

        for item in selected_items:
            rec_id = self.file_tree.item(item, 'values')[0]
            file_info = next((f for f in self.files_found if str(f['id']) == str(rec_id)), None)
            
            if file_info:
                self.recover_file(file_info, output_dir)

    def recover_all_visible(self):
        visible_items = self.file_tree.get_children()
        if not visible_items:
            self.log("[!] No files to recover.")
            return
            
        output_dir = filedialog.askdirectory(title="Select Recovery Folder")
        if not output_dir:
            return

        for item in visible_items:
            rec_id = self.file_tree.item(item, 'values')[0]
            file_info = next((f for f in self.files_found if str(f['id']) == str(rec_id)), None)

            if file_info:
                self.recover_file(file_info, output_dir)
                
    def recover_file(self, file_info, output_dir):
        rec_id = file_info['id']
        fname = file_info['name']
        data = file_info['data']
        status_dir = "deleted" if file_info['status'] == 'Deleted' else "active"

        safe_fname = fname.replace("/", "_").replace("\\", "_").replace(":", "_")
        target_dir = os.path.join(output_dir, status_dir)
        os.makedirs(target_dir, exist_ok=True)
        
        path = os.path.join(target_dir, f"{status_dir}_{rec_id}_{safe_fname}")
        
        try:
            with open(path, 'wb') as out:
                out.write(data)
            self.log(f"[+] Recovered: {fname} to {path}")
        except Exception as e:
            self.log(f"[!] Failed to recover {fname}: {e}")

if __name__ == "__main__":
    app = NTFSRecoveryGUI()
    app.mainloop()