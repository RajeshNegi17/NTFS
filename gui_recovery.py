#!/usr/bin/env python3
"""
NTFS File Recovery GUI Application
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
import subprocess
from pathlib import Path

class NTFSRecoveryGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NTFS File Recovery Tool")
        self.root.state('zoomed')
        self.root.minsize(800, 600)
        
        # Variables
        self.selected_path = tk.StringVar()
        self.output_dir = tk.StringVar(value="output")
        self.recover_deleted = tk.BooleanVar(value=True)
        self.recover_active = tk.BooleanVar(value=True)
        
        # Recovery state
        self.recovery_running = False
        self.found_files = []
        
        self.setup_ui()
        self.setup_styles()
        
    def setup_styles(self):
        """Setup modern styling with larger text"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors and larger fonts
        style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Normal.TLabel', font=('Arial', 11))
        style.configure('Success.TLabel', foreground='green', font=('Arial', 11))
        style.configure('Error.TLabel', foreground='red', font=('Arial', 11))
        style.configure('Info.TLabel', foreground='blue', font=('Arial', 11))
        style.configure('Warning.TLabel', foreground='orange', font=('Arial', 11))
        
        # Configure buttons with larger text
        style.configure('TButton', font=('Arial', 11))
        style.configure('Accent.TButton', font=('Arial', 12, 'bold'))
        
        # Configure entry fields
        style.configure('TEntry', font=('Arial', 11))
        
        # Configure combobox
        style.configure('TCombobox', font=('Arial', 11))
        
        # Configure checkbuttons and radiobuttons
        style.configure('TCheckbutton', font=('Arial', 11))
        style.configure('TRadiobutton', font=('Arial', 11))
        
        # Configure Treeview
        style.configure('Treeview', font=('Arial', 10))
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        
    def setup_ui(self):
        """Setup the user interface with scrollable main frame"""
        # Create main scrollable frame
        self.main_canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        )
        
        self.frame_on_canvas = self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.bind("<Configure>", self._on_canvas_configure)
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack the canvas and scrollbar
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel scrolling
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Main container with padding
        main_frame = ttk.Frame(self.scrollable_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="NTFS File Recovery Tool", style='Title.TLabel')
        title_label.pack(pady=(0, 15))
        
        # Source Selection Section
        self.create_source_section(main_frame)
        
        # Recovery Options Section
        self.create_options_section(main_frame)
        
        # Action Buttons
        self.create_action_buttons(main_frame)
        
        # Progress and Log Section
        self.create_progress_section(main_frame)
        
        # Results Section
        self.create_results_section(main_frame)
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def _on_canvas_configure(self, event):
        """Update the scrollable frame's width to match the canvas"""
        self.main_canvas.itemconfig(self.frame_on_canvas, width=event.width)
        
    def create_source_section(self, parent):
        """Create source selection section"""
        # Source Frame
        source_frame = ttk.LabelFrame(parent, text="Source Selection", padding="15")
        source_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Path selection
        ttk.Label(source_frame, text="Image File Path:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        path_frame = ttk.Frame(source_frame)
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.selected_path, font=('Arial', 11))
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.browse_button = ttk.Button(path_frame, text="Browse", command=self.browse_source, style='Accent.TButton')
        self.browse_button.pack(side=tk.RIGHT)
        
        # Help text
        help_text = "💡 Select an NTFS image file (.img, .dd, .raw, .bin) to recover files from"
        ttk.Label(source_frame, text=help_text, style='Info.TLabel').pack(anchor=tk.W, pady=(5, 0))
        
    def create_options_section(self, parent):
        """Create recovery options section"""
        options_frame = ttk.LabelFrame(parent, text="Recovery Options", padding="15")
        options_frame.pack(fill=tk.X, pady=(0, 15))
        
        # File type selection
        ttk.Label(options_frame, text="File Types to Recover:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        file_types_frame = ttk.Frame(options_frame)
        file_types_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Checkbutton(file_types_frame, text="Active Files (Not Deleted)", 
                       variable=self.recover_active, style='TCheckbutton').pack(side=tk.LEFT, padx=(0, 30))
        ttk.Checkbutton(file_types_frame, text="Deleted Files", 
                       variable=self.recover_deleted, style='TCheckbutton').pack(side=tk.LEFT)
        
        # Output directory
        ttk.Label(options_frame, text="Output Directory:", style='Header.TLabel').pack(anchor=tk.W, pady=(10, 5))
        
        output_frame = ttk.Frame(options_frame)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Entry(output_frame, textvariable=self.output_dir, font=('Arial', 11)).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(output_frame, text="Browse", command=self.browse_output).pack(side=tk.RIGHT)
        
    def create_action_buttons(self, parent):
        """Create action buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Center the buttons
        center_frame = ttk.Frame(button_frame)
        center_frame.pack(expand=True)
        
        self.scan_button = ttk.Button(center_frame, text="🔍 Scan for Files", command=self.scan_files, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=(0, 15))
        
        self.recover_button = ttk.Button(center_frame, text="💾 Recover Selected", command=self.recover_files, state='disabled')
        self.recover_button.pack(side=tk.LEFT, padx=(0, 15))
        
        self.recover_all_button = ttk.Button(center_frame, text="💾 Recover All", command=self.recover_all_files, state='disabled')
        self.recover_all_button.pack(side=tk.LEFT, padx=(0, 15))
        
        self.stop_button = ttk.Button(center_frame, text="⏹️ Stop", command=self.stop_recovery, state='disabled')
        self.stop_button.pack(side=tk.LEFT)
        
    def create_progress_section(self, parent):
        """Create progress and log section"""
        progress_frame = ttk.LabelFrame(parent, text="Progress & Log", padding="15")
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(progress_frame, text="Ready to scan", style='Info.TLabel')
        self.status_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(progress_frame, height=10, width=80, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def create_results_section(self, parent):
        """Create results section"""
        results_frame = ttk.LabelFrame(parent, text="Found Files", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for files
        columns = ('Record', 'Filename', 'Status', 'Size')
        self.file_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=8)
        
        # Configure columns
        self.file_tree.heading('Record', text='Record ID')
        self.file_tree.heading('Filename', text='Filename')
        self.file_tree.heading('Status', text='Status')
        self.file_tree.heading('Size', text='Size (bytes)')
        
        self.file_tree.column('Record', width=100)
        self.file_tree.column('Filename', width=400)
        self.file_tree.column('Status', width=120)
        self.file_tree.column('Size', width=120)
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        tree_scroll_x = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Grid layout
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Results info
        self.results_info = ttk.Label(results_frame, text="No files found", style='Normal.TLabel')
        self.results_info.pack(anchor=tk.W, pady=(10, 0))
        
    def browse_source(self):
        """Browse for image file"""
        filetypes = [
            ("Image files", "*.img *.dd *.raw *.bin"),
            ("All files", "*.*")
        ]
        filename = filedialog.askopenfilename(
            title="Select NTFS Image File",
            filetypes=filetypes
        )
        if filename:
            self.selected_path.set(filename)
            
    def browse_output(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_dir.set(directory)
            
    def log_message(self, message):
        """Add message to log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_status(self, message):
        """Update status message"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def scan_files(self):
        """Start file scanning in a separate thread"""
        if not self.selected_path.get():
            messagebox.showerror("Error", "Please select an image file")
            return
            
        if not (self.recover_active.get() or self.recover_deleted.get()):
            messagebox.showerror("Error", "Please select at least one file type to recover")
            return
            
        # Check if source exists
        source_path = self.selected_path.get()
        if not os.path.exists(source_path):
            messagebox.showerror("Error", f"Image file '{source_path}' not found.")
            return
            
        self.recovery_running = True
        self.found_files = []
        
        # Update UI
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_bar.start()
        self.file_tree.delete(*self.file_tree.get_children())
        self.log_text.delete(1.0, tk.END)
        
        # Start scanning thread
        scan_thread = threading.Thread(target=self._scan_files_thread)
        scan_thread.daemon = True
        scan_thread.start()
        
    def _scan_files_thread(self):
        """Scan files in background thread"""
        try:
            # Build command with default values
            cmd = [sys.executable, "extract.py", self.selected_path.get()]
            cmd.extend(["--cluster-size", "4096"])
            cmd.extend(["--max-records", "1000000"])
            cmd.extend(["--output-dir", self.output_dir.get()])
            cmd.extend(["--max-file-size", "104857600"])  # 100MB
            
            # Add scan-only flag
            cmd.append("--scan-only")
            cmd.append("--gui-mode")
            
            self.log_message(f"[*] Starting scan: {' '.join(cmd)}")
            self.update_status("Scanning for files...")
            
            # Run the scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Read output
            for line in process.stdout:
                if not self.recovery_running:
                    process.terminate()
                    break
                    
                line = line.strip()
                if line:
                    self.log_message(line)
                    
                    # Parse found files
                    if line.startswith("[FOUND_FILE]"):
                        parts = line.split("|")
                        if len(parts) >= 4:
                            record_id = parts[1].strip()
                            filename = parts[2].strip()
                            status = parts[3].strip()
                            size = parts[4].strip() if len(parts) > 4 else "0"
                            
                            self.found_files.append({
                                'record_id': record_id,
                                'filename': filename,
                                'status': status,
                                'size': size
                            })
                            
                            # Add to treeview
                            self.root.after(0, self.add_file_to_tree, record_id, filename, status, size)
                            
            process.wait()
            
            if self.recovery_running:
                self.root.after(0, self.scan_complete)
                
        except Exception as e:
            self.log_message(f"[!] Error during scan: {e}")
            self.root.after(0, self.scan_complete)
            
    def add_file_to_tree(self, record_id, filename, status, size):
        """Add file to treeview"""
        self.file_tree.insert('', 'end', values=(record_id, filename, status, size))
        
    def scan_complete(self):
        """Handle scan completion"""
        self.recovery_running = False
        self.progress_bar.stop()
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        
        if self.found_files:
            self.recover_button.config(state='normal')
            self.recover_all_button.config(state='normal')
            self.results_info.config(text=f"Found {len(self.found_files)} files")
            self.update_status(f"Scan complete. Found {len(self.found_files)} files.")
        else:
            self.update_status("Scan complete. No files found.")
            
    def stop_recovery(self):
        """Stop the recovery process"""
        self.recovery_running = False
        self.update_status("Stopping...")
        
    def recover_files(self):
        """Recover selected files"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select files to recover")
            return
            
        # Get selected files
        selected_files = []
        for item in selection:
            values = self.file_tree.item(item, 'values')
            selected_files.append(values[1])  # filename
            
        self._recover_files(selected_files)
        
    def recover_all_files(self):
        """Recover all found files"""
        if not self.found_files:
            messagebox.showwarning("Warning", "No files to recover")
            return
            
        # Build command for all files with default values
        cmd = [sys.executable, "extract.py", self.selected_path.get()]
        cmd.extend(["--cluster-size", "4096"])
        cmd.extend(["--max-records", "1000000"])
        cmd.extend(["--output-dir", self.output_dir.get()])
        cmd.extend(["--max-file-size", "104857600"])  # 100MB
        
        # Add recover-all flag
        cmd.append("--recover-all")
        
        self.log_message(f"[*] Starting recovery of all files: {' '.join(cmd)}")
        self.update_status("Recovering all files...")
        
        # Run recovery in thread
        recovery_thread = threading.Thread(target=self._run_recovery, args=(cmd,))
        recovery_thread.daemon = True
        recovery_thread.start()
        
    def _run_recovery(self, cmd):
        """Run recovery in background thread"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            for line in process.stdout:
                line = line.strip()
                if line:
                    self.log_message(line)
                    
            process.wait()
            
            if process.returncode == 0:
                self.root.after(0, lambda: messagebox.showinfo("Success", "File recovery completed successfully!"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "File recovery failed"))
                
        except Exception as e:
            self.log_message(f"[!] Error during recovery: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Recovery failed: {e}"))

    def _recover_files(self, filenames):
        """Recover specified files"""
        if not filenames:
            return
            
        # Build command with default values
        cmd = [sys.executable, "extract.py", self.selected_path.get()]
        cmd.extend(["--cluster-size", "4096"])
        cmd.extend(["--max-records", "1000000"])
        cmd.extend(["--output-dir", self.output_dir.get()])
        cmd.extend(["--max-file-size", "104857600"])  # 100MB
        
        # Add file filter - use record IDs instead of filenames for more reliable matching
        selected_items = self.file_tree.selection()
        record_ids = []
        for item in selected_items:
            values = self.file_tree.item(item, 'values')
            record_ids.append(values[0])  # Record ID
            
        if record_ids:
            cmd.extend(["--record-ids", ",".join(record_ids)])
        else:
            # Fallback to filename matching
            cmd.extend(["--files", ",".join(filenames)])
        
        self.log_message(f"[*] Starting recovery: {' '.join(cmd)}")
        self.update_status("Recovering files...")
        
        # Run recovery in thread
        recovery_thread = threading.Thread(target=self._run_recovery, args=(cmd,))
        recovery_thread.daemon = True
        recovery_thread.start()

def main():
    root = tk.Tk()
    app = NTFSRecoveryGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 