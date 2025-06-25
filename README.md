# NTFS File Recovery Tool

A powerful Python-based GUI application for recovering deleted files from NTFS file systems by directly reading the Master File Table (MFT).

## Features

- **Direct MFT Access**: Reads the Master File Table directly for comprehensive file recovery
- **Modern GUI**: Clean, dark-themed interface built with CustomTkinter
- **Drive Selection**: Automatically detects and lists available drives
- **File Filtering**: Search and filter recovered files by name
- **Batch Recovery**: Recover individual files or all visible files at once
- **Status Tracking**: Distinguishes between active and deleted files
- **Progress Monitoring**: Real-time progress bar during scanning
- **Organized Output**: Automatically organizes recovered files into separate folders

## Prerequisites

### System Requirements
- **Windows Operating System** (Windows 7/8/10/11)
- **Administrator Privileges** (required for direct disk access)
- **Python 3.7+**

### Required Python Packages
```bash
pip install customtkinter
```

The following packages are included with Python:
- `tkinter` (usually included with Python)
- `os`
- `struct`
- `ctypes`

## Installation

1. **Clone or download** this repository
2. **Install dependencies**:
   ```bash
   pip install customtkinter
   ```
3. **Run as Administrator** (required for disk access)

## Usage

### Starting the Application
```bash
python ntfs_recovery.py
```
**Important**: Must be run with Administrator privileges for disk access.

### Step-by-Step Guide

1. **Select Drive**: Choose the drive you want to scan from the dropdown menu
2. **Scan Drive**: Click "Scan Drive" to begin the MFT analysis
3. **Filter Results**: Use the search box to filter files by name
4. **Select Files**: Choose specific files or use "Recover All Visible"
5. **Choose Output**: Select a folder where recovered files will be saved
6. **Recovery**: Files are automatically organized into `active` and `deleted` folders

### Recovery Process

The tool will:
- Create separate folders for `active` and `deleted` files
- Prefix recovered files with their MFT record ID
- Sanitize filenames to prevent filesystem conflicts
- Provide detailed logging of the recovery process

## How It Works

### Technical Overview

1. **Cluster Size Detection**: Determines the cluster size of the target drive
2. **MFT Location**: Calculates the Master File Table offset from the boot sector
3. **Record Parsing**: Reads and parses individual MFT records
4. **Attribute Analysis**: Extracts file attributes including names and data
5. **Data Recovery**: Reconstructs file data from resident and non-resident attributes
6. **Runlist Processing**: Handles fragmented files through runlist interpretation

### File Recovery Mechanics

- **Resident Data**: Small files stored directly in MFT records
- **Non-Resident Data**: Larger files stored in clusters, reconstructed via runlists
- **Attribute Types**: Handles filename attributes (0x30) and data attributes (0x80)
- **Status Detection**: Identifies deleted files through MFT record flags

## Safety and Limitations

### Important Warnings

⚠️ **Administrator Rights Required**: The tool needs administrative privileges to access raw disk data

⚠️ **Read-Only Operation**: This tool only reads data and does not modify the disk

⚠️ **Recovery Success**: File recovery success depends on whether the data has been overwritten

### Limitations

- **Windows Only**: Uses Windows-specific APIs for disk access
- **NTFS Only**: Designed specifically for NTFS file systems
- **Memory Usage**: Large files may consume significant memory during recovery
- **Scan Time**: Full MFT scans can take time depending on disk size
- **Fragmentation**: Heavily fragmented files may not recover completely

## File Structure

```
ntfs_recovery_tool/
├── ntfs_recovery.py          # Main application file
├── README.md                 # This documentation
└── requirements.txt          # Python dependencies (optional)
```

## Troubleshooting

### Common Issues

**"Access Denied" Error**
- Solution: Run the application as Administrator

**"No drives detected"**
- Ensure you're running on a Windows system
- Check that you have appropriate permissions

**"Scan failed" Error**
- Verify the selected drive is accessible
- Check that the drive uses NTFS file system
- Ensure no other applications are exclusively accessing the drive

**Recovery fails for specific files**
- File data may have been overwritten
- File might be heavily fragmented
- Insufficient memory for large files

### Performance Tips

- Close other applications during scanning to free up memory
- For large drives, consider scanning during low-activity periods
- Use the search filter to focus on specific file types or names

## Technical Details

### MFT Structure
- Each MFT record is 1024 bytes
- Records contain multiple attributes
- File data can be resident (stored in MFT) or non-resident (stored in clusters)

### Supported Attributes
- **0x30**: Filename attributes
- **0x80**: Data attributes (file content)

### Recovery Limitations
- Maximum file size: 100MB per file (configurable in code)
- Scans up to 100,000 MFT records by default

## Contributing

This tool is provided as-is for educational and recovery purposes. When contributing:

1. Test thoroughly on non-critical drives
2. Maintain read-only operations
3. Follow Windows API best practices
4. Document any changes to the MFT parsing logic

## License

This project is provided for educational and personal use. Use at your own risk.

## Disclaimer

**Use this tool responsibly and at your own risk.** Always:
- Test on non-critical drives first
- Maintain backups of important data
- Understand that file recovery is not guaranteed
- Comply with applicable laws and regulations

The authors are not responsible for any data loss or system damage resulting from the use of this tool.