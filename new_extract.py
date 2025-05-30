import os
import struct
import ctypes

# ---------------- Utility Functions ----------------

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

# ---------------- Main Script ----------------

def main():
    print("\n[🔍] Scanning available drives...")
    drives = list_drives()
    print("Available drives:", ", ".join(drives))
    
    drive_letter = input("Enter drive letter to scan (e.g., C): ").strip().upper()
    if drive_letter not in drives:
        print("[!] Invalid drive letter. Exiting.")
        return

    try:
        cluster_size = get_cluster_size(drive_letter)
        img_path = r"\\.\{}:".format(drive_letter)

        with open(img_path, 'rb') as f:
            mft_offset = detect_mft_offset(f, cluster_size)

        print(f"[✔] Cluster size: {cluster_size} bytes")
        print(f"[✔] MFT offset: {mft_offset} bytes")
    except Exception as e:
        print(f"[!] Failed to analyze disk: {e}")
        return

    max_records = 1000000
    os.makedirs("output/recovered", exist_ok=True)
    os.makedirs("output/deleted", exist_ok=True)

    print("\n[?] Do you want to:\n1. Recover all files\n2. Select specific files manually")
    choice = input("Enter 1 or 2: ").strip()
    recover_all = (choice == "1")

    summary_lines = []
    all_found_files = []

    with open(img_path, 'rb') as f:
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
            except Exception as e:
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
                all_found_files.append((i, filename, label, data))

    selected_files = []

    if recover_all:
        selected_files = all_found_files
    else:
        print("\n[📄] Found files:")
        for idx, (rec_id, fname, label, _) in enumerate(all_found_files):
            print(f"{idx + 1}. [{label}] Record {rec_id} - {fname}")

        print("\nEnter file numbers (e.g., 1,3,5) or type 'all' to recover all:")
        sel = input("Your selection: ").strip().lower()

        if sel == "all":
            selected_files = all_found_files
        else:
            try:
                indices = [int(x.strip()) - 1 for x in sel.split(",")]
                selected_files = [all_found_files[i] for i in indices if 0 <= i < len(all_found_files)]
            except:
                print("[!] Invalid input. Exiting.")
                return

    for rec_id, filename, label, data in selected_files:
        safe_name = filename.replace("/", "_").replace("\\", "_")
        out_name = f"{label}_{rec_id}_{safe_name}"
        out_path = f"output/{label}/{out_name}"

        try:
            with open(out_path, 'wb') as out:
                out.write(data)
            print(f"[+] {out_name} recovered.")
            summary_lines.append(f"{label.upper()}: Record {rec_id} | Filename: {filename}")
        except Exception as e:
            print(f"[!] Failed to write {out_name}: {e}")

    report_path = "output/recovery_report.txt"
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Recovered Files Summary Report\n")
        report.write("="*35 + "\n\n")
        report.write("\n".join(summary_lines))

    print(f"\n[✔] Summary report saved to: {report_path}")


if __name__ == "__main__":
    main()
