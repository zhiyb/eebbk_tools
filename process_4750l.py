#!/usr/bin/env python3
import os
import yaml
import shutil
import datetime
import subprocess
from bbk_iboxh2_sn import write_sn
from pprint import pprint

def c_str(ba):
    return ba.split(b'\0', 1)[0]

def to_int(ba):
    return int.from_bytes(ba, 'little')

def xor(pattern, in_data):
    out_data = bytearray()
    for i in range(len(in_data)):
        out_data.append(pattern[i % len(pattern)] ^ in_data[i])
    return out_data

def path_convert(path):
    return path["path"][2].replace("\\", "/")

def debug_args(a):
    print("+", " ".join(a))
    return a

def build_vfat_partition(out_dir, files, image_path, start_block, max_blocks=0, label="DISK"):
    blklen = 512
    start_offset = start_block * blklen
    max_size = max_blocks * blklen

    # Create loopback device at specified offset
    args = ["losetup", "-f", "--show", image_path,
            "-o", f"{start_offset}",
            "-b", f"{blklen}"]
    if max_blocks:
        args += ["--sizelimit", f"{max_size}"]
    lo = subprocess.run(debug_args(args), capture_output=True).stdout.decode("ASCII").strip()
    if not lo:
        raise RuntimeError("Cannot create loopback device")

    # Format partition
    # BBK OS bug: FAT16 partitions must have the same parameters
    # Parameters like "Sectors per Cluster" from user partition are being used for processing the system partition
    # Also parameter values must be strictly as specified below, file system driver can only handle these values
    if subprocess.run(debug_args(["mkfs.vfat", "-F", "16", "-a",
                                  "-S", "512", "-s", "64", "-R", "64",
                                  "-g", "64/32", "-h", "1", "-r", "512",
                                  "-n", label, lo])).returncode != 0:
        raise RuntimeError("Failed to format FAT partition")

    # Mount
    mnt = os.path.join(out_dir, "mnt")
    os.makedirs(mnt, exist_ok=True)
    subprocess.run(debug_args(["mount", "-t", "vfat,codepage=936,iocharset=cp936", lo, mnt]))

    # Copy files
    for file in files:
        f_path = path_convert(file)
        src_path = os.path.join(out_dir, f_path)
        if f_path.endswith("_4720"):
            continue
        elif f_path.endswith("_4750l"):
            f_path = f_path[:-6]
        dst_path = os.path.join(mnt, f_path)
        print(f"Copying file: {f_path}")
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)

    # Done, cleanup
    subprocess.run(debug_args(["df", "-h", mnt]))
    subprocess.run(debug_args(["umount", mnt]))
    os.rmdir(mnt)
    subprocess.run(debug_args(["losetup", "-d", lo]))

    # # Create a partition file for debugging
    # dd_blklen = 4096
    # args = ["dd", f"if={image_path}", f"of={os.path.join(out_dir, f"part-{start_offset:#010x}.bin")}",
    #         f"bs={dd_blklen}", f"skip={start_offset // dd_blklen}"]
    # if max_blocks:
    #     args += [f"count={max_size // dd_blklen}"]
    # subprocess.run(debug_args(args))

def main():

    out_dir = "output/"
    os.makedirs(out_dir, exist_ok=True)

    # Find the XOR pattern from this string
    #                      s_HAN#Buffer_...._80052e34                      XREF[2]:     FUN_8002e31c:8002e458(*),
    #                                                                                   decode_buffer:8002f900(*)
    # 80052e34 0d 0a b5        ds         "\r\n底层Buffer解码中...."
    #          d7 b2 e3
    #          42 75 66
    # 80052e4b 00              ??         00h
    xor_offset = 0x800561f0 - 0x80004000
    xor_len = 0x1000
    xor_file = os.path.join(out_dir, "xor.bin")
    xor_data = None

    in_file = "BurnSys_H2L_V1.0.bin"
    with open(in_file, "rb") as f_in:
        f_in.seek(xor_offset)
        xor_data = f_in.read(xor_len)
    with open(xor_file, "wb") as f_out:
        f_out.write(xor_data)

    packets = {}
    for in_file in ["packet1.dat", "packet2.dat"]:
        packet = {}
        packets[in_file] = packet
        with open(in_file, "rb") as f_in:
            global_header = f_in.read(16)
            header = {}
            header["u32_0x00"] = to_int(global_header[0x00:0x04])
            header["u32_0x04"] = to_int(global_header[0x04:0x08])
            header["num_files"] = to_int(global_header[0x08:0x0c])
            header["u32_0x0c"] = to_int(global_header[0x0c:0x10])
            packet["header"] = header
            packet["files"] = []
            for _ in range(header["num_files"]):
                file_header = f_in.read(0x100)
                file = {}
                file["size"] = to_int(file_header[0x00:0x04])
                file["offset"] = to_int(file_header[0x04:0x08])
                file["path"] = c_str(file_header[0x08:]).decode("GBK").split(" ", 2)
                packet["files"].append(file)

            for file in packet["files"]:
                # f_in.seek(len(global_header) + file["offset"])
                # file["magic"] = f_in.read(4)

                f_in.seek(len(global_header) + file["offset"])
                path = os.path.join(out_dir, path_convert(file))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f_out:
                    f_out.write(f_in.read(file["size"]))

    with open(os.path.join(out_dir, "index.yaml"), "w", encoding="UTF-8") as f_out:
        yaml.dump(packets, f_out, allow_unicode=True)

    for f_name in os.listdir("."):
        if f_name.startswith("data"):
            with open(f_name, "rb") as f_in:
                file_header = f_in.read(16)     # What are those?
                with open(os.path.join(out_dir, f_name), "wb") as f_out:
                    f_out.write(xor(xor_data, f_in.read()))

    # System image
    image_path = os.path.join(out_dir, "image.bin")
    image_size = 2 * 1024 * 1024 * 1024
    with open(image_path, "wb") as f_out:
        f_out.truncate(image_size)

        # Erase first
        f_out.seek(0)
        buf = bytes([0xff] * 4096)
        for _ in range(image_size // len(buf)):
            f_out.write(buf)

        # First stage bootloader
        f_out.seek(0)
        with open(os.path.join(out_dir, "data0_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())
        # # Clear first 4 bytes
        # f_out.seek(0)
        # f_out.write(b'\0\0\0\0')

        # Second stage bootloader primary
        # block_offset 0x0c00 (1.5 MiB)
        f_out.seek(0x0c00 * 512)
        with open(os.path.join(out_dir, "data2_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

        # OS_0 primary kernel - classic theme
        # block_offset 0x2000 (4 MiB)
        # entry_address 0x804af000
        f_out.seek(0x2000 * 512)
        with open(os.path.join(out_dir, "data3_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

        # OS_1 primary kernel - cartoon theme
        # block_offset 0x6400 (12.5 MiB)
        # entry_address 0x8086b000
        f_out.seek(0x6400 * 512)
        with open(os.path.join(out_dir, "data4_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

        # Second stage bootloader secondary
        # block_offset 0x8400 (16.5 MiB)
        f_out.seek(0x8400 * 512)
        with open(os.path.join(out_dir, "data2_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

        # OS_0 secondary kernel - classic theme
        # block_offset 0x9800 (19 MiB)
        f_out.seek(0x9800 * 512)
        with open(os.path.join(out_dir, "data3_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

        # OS_1 secondary kernel - cartoon theme
        # block_offset 0xdc00 (27.5 MiB)
        f_out.seek(0xdc00 * 512)
        with open(os.path.join(out_dir, "data4_L.dat"), "rb") as f_in:
            f_out.write(f_in.read())

    write_sn(image_path, "QEMU " + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d"))

    # Partition 0: system
    # FAT16, starts from block offset 0x0000f400 (0x01e80000 / 30.5 MiB)
    blklen = 512
    part_size = (0x000dec00 - 0x0000f400) * blklen
    # Label should be "H2 V2.2L", but "." is not allowed by mkfs.vfat
    build_vfat_partition(out_dir, packets["packet1.dat"]["files"], image_path, 0x0000f400, part_size // blklen, label="H2-V2_2L")

    # Partition 1: user data
    # FAT16, starts from block offset 0x000dec00 (0x1bd80000 / 445.5 MiB)
    part_size = (2048 - 446) * 1024 * 1024
    # Label should be "@ibox H2"
    build_vfat_partition(out_dir, packets["packet2.dat"]["files"], image_path, 0x000dec00, part_size // blklen, label="@ibox-H2")

    # Partition 2 is SD card at MSC1

if __name__ == '__main__':
    main()
