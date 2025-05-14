import struct


with open('C:/Users/ASUS/Desktop/ntfs_test.img', 'rb') as f:
    # Read first 512 bytes (boot sector)
    boot_sector = f.read(512)

    # OEM ID (should be NTFS)
    oem_id = boot_sector[3:11].decode()
    print("OEM ID:", oem_id)  # Should be 'NTFS    '

    # Bytes per sector
    bps = struct.unpack_from("<H", boot_sector, 11)[0]
    print("Bytes per Sector:", bps)

    # Sectors per cluster
    spc = struct.unpack_from("<B", boot_sector, 13)[0]
    print("Sectors per Cluster:", spc)

    # MFT Cluster Number (offset in clusters)
    mft_cluster = struct.unpack_from("<Q", boot_sector, 48)[0]
    print("MFT Cluster:", mft_cluster)

    mft_offset = mft_cluster * bps * spc
    print("MFT Offset (bytes):", mft_offset)
