import os
import struct
import argparse
import sys

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

def find_mft_offset(f):
    """Try to find MFT offset by scanning for MFT signature"""
    print("[*] Searching for MFT offset...")
    
    # Common MFT locations to check
    common_offsets = [
        0x0C0000,      # Common MFT location
        0x080000,      # Alternative location
        0x100000,      # Another common location
        34951168,      # Original hardcoded value
    ]
    
    # First check common locations
    for offset in common_offsets:
        try:
            f.seek(offset)
            record_raw = f.read(1024)
            if record_raw[0:4] == b'FILE':
                print(f"[+] Found MFT at offset: 0x{offset:X} ({offset})")
                return offset
        except:
            continue
    
    # If not found in common locations, scan the first 100MB
    print("[*] Scanning for MFT signature...")
    for offset in range(0, 100 * 1024 * 1024, 1024):
        try:
            f.seek(offset)
            record_raw = f.read(1024)
            if record_raw[0:4] == b'FILE':
                print(f"[+] Found MFT at offset: 0x{offset:X} ({offset})")
                return offset
        except:
            continue
    
    print("[!] Could not find MFT offset automatically. Using default.")
    return 34951168

def main():
    parser = argparse.ArgumentParser(description='NTFS File Recovery Tool')
    parser.add_argument('image_path', help='Path to the NTFS image file')
    parser.add_argument('--mft-offset', type=int, help='MFT offset in bytes (will auto-detect if not provided)')
    parser.add_argument('--cluster-size', type=int, default=4096, help='Cluster size in bytes (default: 4096)')
    parser.add_argument('--max-records', type=int, default=1000000, help='Maximum MFT records to scan (default: 1000000)')
    parser.add_argument('--output-dir', default='output', help='Output directory (default: output)')
    parser.add_argument('--recover-all', action='store_true', help='Recover all files without prompting')
    parser.add_argument('--max-file-size', type=int, default=100*1024*1024, help='Maximum file size to recover in bytes (default: 100MB)')
    parser.add_argument('--scan-only', action='store_true', help='Only scan for files, do not recover')
    parser.add_argument('--files', help='Comma-separated list of filenames to recover')
    parser.add_argument('--record-ids', help='Comma-separated list of record IDs to recover')
    parser.add_argument('--gui-mode', action='store_true', help='Enable GUI-friendly output format')
    
    args = parser.parse_args()
    
    # Check if image file exists
    if not os.path.exists(args.image_path):
        print(f"[!] Error: Image file '{args.image_path}' not found.")
        sys.exit(1)
    
    # Create output directories if not scan-only
    if not args.scan_only:
        os.makedirs(f"{args.output_dir}/recovered", exist_ok=True)
        os.makedirs(f"{args.output_dir}/deleted", exist_ok=True)
    
    summary_lines = []
    all_found_files = []
    
    if not args.gui_mode:
        print(f"[*] Processing image: {args.image_path}")
        print(f"[*] Cluster size: {args.cluster_size} bytes")
        print(f"[*] Max records to scan: {args.max_records}")
    
    with open(args.image_path, 'rb') as f:
        # Determine MFT offset
        if args.mft_offset is not None:
            mft_offset = args.mft_offset
            if not args.gui_mode:
                print(f"[*] Using provided MFT offset: 0x{mft_offset:X} ({mft_offset})")
        else:
            mft_offset = find_mft_offset(f)
        
        # Main scanning loop
        if not args.gui_mode:
            print(f"[*] Starting MFT scan from offset: 0x{mft_offset:X}")
        
        for i in range(args.max_records):
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
                if not args.gui_mode:
                    print(f"[!] Failed to parse attributes for record {i}: {e}")
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
                        data = extract_non_resident_data(attr, args.cluster_size, f, args.max_file_size)

            if filename and data:
                label = "deleted" if is_deleted else "recovered"
                all_found_files.append((i, filename, label, data))
                
                # Output for GUI mode
                if args.gui_mode:
                    print(f"[FOUND_FILE]|{i}|{filename}|{label}|{len(data)}")
                elif i % 1000 == 0:
                    print(f"[*] Scanned {i} records, found {len(all_found_files)} files...")

    if not args.gui_mode:
        print(f"\n[*] Scan complete. Found {len(all_found_files)} files.")
    
    # If scan-only mode, exit here
    if args.scan_only:
        if not args.gui_mode:
            print(f"[*] Scan completed. Found {len(all_found_files)} files.")
        return
    
    # File selection
    selected_files = []
    
    if args.recover_all:
        selected_files = all_found_files
        if not args.gui_mode:
            print("[*] Recovering all files...")
    elif args.record_ids:
        # Filter by specified record IDs
        target_record_ids = [int(rid.strip()) for rid in args.record_ids.split(',')]
        selected_files = [(rec_id, filename, label, data) 
                         for rec_id, filename, label, data in all_found_files 
                         if rec_id in target_record_ids]
        if not args.gui_mode:
            print(f"[*] Recovering {len(selected_files)} files by record ID...")
    elif args.files:
        # Filter by specified filenames
        target_files = [f.strip() for f in args.files.split(',')]
        selected_files = [(rec_id, filename, label, data) 
                         for rec_id, filename, label, data in all_found_files 
                         if filename in target_files]
        if not args.gui_mode:
            print(f"[*] Recovering {len(selected_files)} specified files...")
    else:
        if not args.gui_mode:
            print("\n[?] Do you want to:\n1. Recover all files\n2. Select specific files manually")
            choice = input("Enter 1 or 2: ").strip()
            recover_all = (choice == "1")

            if recover_all:
                selected_files = all_found_files
            else:
                print("\n[🔍] Found files:")
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
                        sys.exit(1)

    # Recovery execution
    if not args.gui_mode:
        print(f"\n[*] Recovering {len(selected_files)} files...")
    
    for rec_id, filename, label, data in selected_files:
        safe_name = filename.replace("/", "_").replace("\\", "_").replace(":", "_")
        out_name = f"{label}_{rec_id}_{safe_name}"
        out_path = f"{args.output_dir}/{label}/{out_name}"

        try:
            with open(out_path, 'wb') as out:
                out.write(data)
            if not args.gui_mode:
                print(f"[+] {out_name} recovered ({len(data)} bytes)")
            summary_lines.append(f"{label.upper()}: Record {rec_id} | Filename: {filename} | Size: {len(data)} bytes")
        except Exception as e:
            if not args.gui_mode:
                print(f"[!] Failed to write {out_name}: {e}")

    # Generate report
    report_path = f"{args.output_dir}/recovery_report.txt"
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("NTFS File Recovery Report\n")
        report.write("="*30 + "\n\n")
        report.write(f"Image file: {args.image_path}\n")
        report.write(f"MFT offset: 0x{mft_offset:X} ({mft_offset})\n")
        report.write(f"Cluster size: {args.cluster_size} bytes\n")
        report.write(f"Files recovered: {len(selected_files)}\n\n")
        report.write("Recovered Files:\n")
        report.write("-" * 20 + "\n")
        report.write("\n".join(summary_lines))

    if not args.gui_mode:
        print(f"\n[+] Recovery complete!")
        print(f"[+] Summary report saved to: {report_path}")
        print(f"[+] Files saved to: {args.output_dir}/")

if __name__ == "__main__":
    main()
