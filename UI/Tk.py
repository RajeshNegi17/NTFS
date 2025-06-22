import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk

# ------------ Main Setup ------------ #
root = tk.Tk()
root.title("NTFS File Recovery Tool")
root.geometry("600x500")
root.resizable(False, False)
root.configure(bg="#f4f4f4")  # Soft background

# ------------ Styling ------------- #
style = ttk.Style()
style.theme_use("clam")

style.configure("TButton",
                font=("Segoe UI", 12),
                padding=10,
                relief="flat",
                foreground="#ffffff",
                background="#4a90e2")
style.map("TButton",
          background=[("active", "#357ABD")])

style.configure("TLabel",
                font=("Segoe UI", 14),
                background="#f4f4f4")

# ------------ Header ------------- #
header_frame = ttk.Frame(root)
header_frame.pack(pady=20)

title_label = ttk.Label(header_frame, text="NTFS File Recovery Tool", font=("Segoe UI", 20, "bold"), foreground="#333")
title_label.pack()

# ------------ Buttons Frame ------------- #
btn_frame = ttk.Frame(root)
btn_frame.pack(pady=30)

def show_recoverable_files():
    messagebox.showinfo("Action", "Showing all recoverable files...")

def search_specific_file():
    messagebox.showinfo("Action", "Searching for a specific file...")

def permanently_delete_file():
    messagebox.showinfo("Action", "Permanently deleting file...")

# Button 1
btn1 = ttk.Button(btn_frame, text="🔍  Show Recoverable Files", width=30, command=show_recoverable_files)
btn1.grid(row=0, column=0, pady=15)

# Button 2
btn2 = ttk.Button(btn_frame, text="🧭  Search & Retrieve File", width=30, command=search_specific_file)
btn2.grid(row=1, column=0, pady=15)

# Button 3
btn3 = ttk.Button(btn_frame, text="🗑️  Permanently Delete File", width=30, command=permanently_delete_file)
btn3.grid(row=2, column=0, pady=15)

# ------------ Footer Info ------------- #
footer = ttk.Label(root, text="© 2025 NTFS Recovery Project | Built with 💻 in Python", font=("Segoe UI", 9), foreground="#777")
footer.pack(side="bottom", pady=20)

root.mainloop()

