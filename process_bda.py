#!/usr/bin/env python3
import argparse
from pprint import pprint

xor_header = b'\x44\x57\x52\x44'
xor_checksum = b'\x4b\x46\x2d\x32'

def to_int(ba):
    return int.from_bytes(ba, 'little')

def xor(pattern, in_data):
    out_data = bytearray()
    for i in range(len(in_data)):
        out_data.append(pattern[i % len(pattern)] ^ in_data[i])
    return out_data

def hexdump(ba):
    hex = [f"{v:02x}" for v in ba]
    for i in range(0, len(hex), 16):
        print(f"{i:08x}  " + " ".join(hex[i : i + 16]))

def main():
    parser = argparse.ArgumentParser(prog='decode_bda',
                                     description='BBK bda executable file decoder')
    parser.add_argument('bda_file', help="program.bda")
    parser.add_argument('bin_file', help="program.bin")
    args = parser.parse_args()

    with open(args.bda_file, "rb") as f_in:
        f_in.seek(0)
        header = f_in.read(0x88)
        header = xor(xor_header, header[0:11*4]) + header[11*4:]
        print("File header:")
        hexdump(header)

        if header[0:4] != b'BBK\0':
            raise RuntimeError("Sanity check failed")
        if to_int(header[4:8]) != 0x5d245562:
            raise RuntimeError("Sanity check failed")
        if to_int(xor(xor_checksum, header[0x84:0x88])) != sum(header[0:0x84]):
            raise RuntimeError("Sanity check failed")

        data_offset = to_int(header[20:24])
        # Load data from data_offset to 0x81c30040
        print("Load address: 0x81c30040")
        f_in.seek(data_offset)
        with open(args.bin_file, "wb") as f_out:
            f_out.write(f_in.read())

        # Entry address is also 0x81c30040

if __name__ == '__main__':
    main()
