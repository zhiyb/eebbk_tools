#!/usr/bin/env python3
import argparse
from pprint import pprint
from Cryptodome.Cipher import AES

# From eMMC CID register bytes 7 to 14
#               !     !                    0xdeadbeef    41
key = bytes([0x21, 0x21, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x29] + [0xaa] * 24)

parts = [v * 512 for v in [0x7c00, 0x7e00, 0x8000, 0x8200, 0x7d00, 0x7f00, 0x8100, 0x8300]]

def to_int(ba):
    return int.from_bytes(ba, 'little')

def to_bytes(v, len):
    return int.to_bytes(v, len, 'little')

def hexdump(ba):
    hex = [f"{v:02x}" for v in ba]
    for i in range(0, len(hex), 16):
        print(f"{i:08x}  " + " ".join(hex[i : i + 16]) + "  " + "".join([f"{v:c}" for v in ba[i : i + 16]]))

def read_sn(image_file):
    with open(image_file, "rb") as f_image:
        for offset in parts:
            print(f"Serial number at partition {offset:#010x}:")
            f_image.seek(offset)
            data = AES.new(key, AES.MODE_ECB).decrypt(f_image.read(0x0200))

            magic = 0x20101228
            val = to_int(data[0x00:0x04])
            if val != magic:
                print(f"    Magic 0x00 mismatch: {val:#010x} != {magic:#010x}")
                continue
            else:
                print(f"    Magic 0x00 OK: {val:#010x} == {magic:#010x}")

            magic = 0x44313030
            val = to_int(data[0x04:0x08])
            if val != magic:
                print(f"    Magic 0x04 mismatch: {val:#010x} != {magic:#010x}")
                continue
            else:
                print(f"    Magic 0x04 OK: {val:#010x} == {magic:#010x}")

            magic = 0x5d245588
            val = to_int(data[0x08:0x0c])
            if val != magic:
                print(f"    Magic 0x08 mismatch: {val:#010x} != {magic:#010x}")
                continue
            else:
                print(f"    Magic 0x08 OK: {val:#010x} == {magic:#010x}")

            ref = b'JZ4750L\0'
            val = data[0x2c:0x34]
            if val != ref:
                print(f"    String 0x2c mismatch: {val} != {ref}")
                continue
            else:
                print(f"    String 0x2c OK: {val} == {ref}")

            print(f"    Serial number: {data[0x1c:0x29]}")

def write_sn(image_file, sn):
        data = bytearray([0xaa] * 512)
        # data = bytearray([random.randint(0x20, 0x7e) for v in range(512)])
        data[511] = 0
        data[0x00:0x04] = to_bytes(0x20101228, 4)
        data[0x04:0x08] = to_bytes(0x44313030, 4)
        data[0x08:0x0c] = to_bytes(0x5d245588, 4)
        data[0x2c:0x2c+8] = b'JZ4750L\0'
        sn = sn.encode('GBK')
        sn = (sn + b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')[:13]
        data[0x1c:0x29] = sn

        with open(image_file, "r+b") as f_image:
            for offset in parts:
                print(f"Updating serial number at partition {offset:#010x}...")
                f_image.seek(offset)
                f_image.write(AES.new(key, AES.MODE_ECB).encrypt(data))

def main():
    parser = argparse.ArgumentParser(prog='bbk_iboxh2_sn',
                                     description='BBK @ibox H2 device system image serial number tool')
    op_group = parser.add_mutually_exclusive_group()
    op_group.add_argument('--read', action="store_true", help="Read and verify serial number")
    op_group.add_argument('--write', help="Write serial number")
    parser.add_argument('image_file', help="image.bin")
    args = parser.parse_args()

    if args.read:
        read_sn(args.image_file)

    elif args.write:
        write_sn(args.image_file, args.write)

if __name__ == '__main__':
    main()
