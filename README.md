# NTFS File Recovery Tool

A simple and effective GUI tool for recovering files from NTFS image files.

## Features

- **Easy-to-use GUI** with scrollable interface
- **File scanning** to find recoverable files
- **Selective recovery** - choose specific files or recover all
- **Support for both active and deleted files**
- **Automatic MFT detection**
- **Real-time progress tracking**

## Quick Start

### Option 1: Simple Launcher

Double-click `launch_gui_simple.bat` to start the GUI.

### Option 2: Command Line

```bash
python gui_recovery.py
```

## How to Use

1. **Select Image File**: Click "Browse" and select your NTFS image file (.img, .dd, .raw, .bin)
2. **Choose File Types**: Select which types of files to recover (active/deleted)
3. **Set Output Directory**: Choose where to save recovered files
4. **Scan for Files**: Click "🔍 Scan for Files" to find recoverable files
5. **Recover Files**:
   - Select specific files from the list and click "💾 Recover Selected"
   - Or click "💾 Recover All" to recover all found files

## File Types Supported

- **Image files**: .img, .dd, .raw, .bin
- **Recovery targets**: Active files and deleted files
- **Output**: Files are saved to `output/recovered/` and `output/deleted/` directories

## Requirements

- Python 3.6+
- tkinter (usually included with Python)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Command Line Usage

For advanced users, you can also use the command-line tool directly:

```bash
# Scan for files only
python extract.py image.img --scan-only --gui-mode

# Recover all files
python extract.py image.img --recover-all

# Recover specific files by record ID
python extract.py image.img --record-ids 1,2,3

# Recover specific files by filename
python extract.py image.img --files "file1.txt,file2.pdf"
```

## Output Structure

```
output/
├── recovered/          # Active files
├── deleted/           # Deleted files
└── recovery_report.txt # Detailed recovery report
```

## Creating Image Files

If you need to create an image file from a physical drive, see `CREATE_IMAGE_GUIDE.md` for detailed instructions using various tools like dd, FTK Imager, WinHex, etc.

## Troubleshooting

- **No files found**: Ensure your image file contains valid NTFS data
- **Recovery fails**: Check that the output directory is writable
- **GUI not responding**: The tool is processing large files - wait for completion

## License

This tool is provided as-is for educational and recovery purposes.
