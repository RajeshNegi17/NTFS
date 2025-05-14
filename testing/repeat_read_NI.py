import struct

def read_boot_sector(f):
    f.seek(0)
    boot_sector = f.read(512)

    bytes_per_sector = struct.unpack_from("<H", boot_sector, 0x0B)[0]
    sectors_per_cluster = struct.unpack_from("<B", boot_sector, 0x0D)[0]
    mft_cluster_number = struct.unpack_from("<Q", boot_sector, 0x30)[0]

    return bytes_per_sector, sectors_per_cluster, mft_cluster_number

# Usage:
with open("nt.img", "rb") as f:
    bps, spc, mft_cluster = read_boot_sector(f)
    print(f"Bytes/Sector: {bps}, Sectors/Cluster: {spc}, MFT Cluster #: {mft_cluster}")
