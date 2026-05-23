#!/usr/bin/env python3
"""
JZ4750L eMMC 序列号修改工具

基于内核函数 read_sn (0x8004FD60) 的逆向分析结果。

=== 数据结构 (AES-256-ECB解密后, 512字节) ===

偏移    大小    说明
0x00    4       Magic1: 0x20101228
0x04    4       Magic2: 0x44313030
0x08    4       Magic3: 0x5D245588
0x0C    16      版本标识 (如 "H2 V2.20")
0x1C    16      序列号字符串 (ASCII, 最大16字节)
0x2C    ...     其余数据
0x1FC   4       校验和 (0x0C~0x1FB 字节的累加和, 小端 uint32)

=== AES-256 加密 ===

MMC 上存储的数据经过 AES-256 ECB 加密 (每16字节一块, 共32块=512字节)。
密钥来源 (32字节):
  - 前8字节:  内存 0x801A708C (GDB转储: 21 21 01 DE AD BE EF 29)
  - 后24字节: memset 0xAA 残留 (AA AA AA ... AA)
read_sn 调用 aes_key_expand(buf, 256), 参数256选择AES-256路径 (14轮)。

=== MMC 存储位置 (8个扇区, 需全部写入) ===

扇区号  字节偏移
0x7C00  16252928   (15.500 MB)
0x7D00  16384000   (15.625 MB)
0x7E00  16515072   (15.750 MB)
0x7F00  16646144   (15.875 MB)
0x8000  16777216   (16.000 MB)
0x8100  16908288   (16.125 MB)
0x8200  17039360   (16.250 MB)
0x8300  17170432   (16.375 MB)
"""

import struct
import sys
import os

from Cryptodome.Cipher import AES

SECTOR_SIZE = 512

# 8个扇区位置 (read_sn 使用 jiffies 伪随机选扇区, 必须全部写入一致)
SN_SECTORS = [0x7C00, 0x7D00, 0x7E00, 0x7F00, 0x8000, 0x8100, 0x8200, 0x8300]

# Magic 值 (小端序, 解密后可见)
MAGIC1 = 0x20101228
MAGIC2 = 0x44313030
MAGIC3 = 0x5D245588

# 默认 AES-256 密钥 (32字节)
# 前8字节: 0x801A708C 处的运行时数据 (64-bit, GDB转储)
# 后24字节: memset 0xAA 残留
DEFAULT_AES_KEY = bytes([
    0x21, 0x21, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x29,  # 0x801A708C
]) + bytes([0xAA] * 24)  # memset 残留


def calc_checksum(block):
    """计算校验和: 偏移 0x0C 到 0x1FB 的所有字节累加, 取低32位"""
    return sum(block[0x0C:0x1FC]) & 0xFFFFFFFF


def aes_ecb_encrypt(data, key):
    """AES-256 ECB 加密"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_ecb_decrypt(data, key):
    """AES-256 ECB 解密"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def parse_sn_block(block):
    """解析512字节明文数据块, 提取序列号等信息"""
    magic1 = struct.unpack_from('<I', block, 0x00)[0]
    magic2 = struct.unpack_from('<I', block, 0x04)[0]
    magic3 = struct.unpack_from('<I', block, 0x08)[0]

    if magic1 != MAGIC1 or magic2 != MAGIC2 or magic3 != MAGIC3:
        return None

    version = block[0x0C:0x1C].split(b'\x00')[0].decode('ascii', errors='replace')
    serial = block[0x1C:0x2C].split(b'\x00')[0].decode('ascii', errors='replace')
    stored_cksum = struct.unpack_from('<I', block, 0x1FC)[0]
    calc_cksum = calc_checksum(block)

    return {
        'version': version,
        'serial': serial,
        'stored_checksum': stored_cksum,
        'calc_checksum': calc_cksum,
        'checksum_ok': stored_cksum == calc_cksum,
    }


def make_sn_block(serial, version=b'H2 V2.20'):
    """创建512字节明文数据块 (含Magic/版本/序列号/校验和)"""
    block = bytearray(SECTOR_SIZE)
    struct.pack_into('<I', block, 0x00, MAGIC1)
    struct.pack_into('<I', block, 0x04, MAGIC2)
    struct.pack_into('<I', block, 0x08, MAGIC3)
    block[0x0C:0x1C] = version[:16].ljust(16, b'\x00')
    block[0x1C:0x2C] = serial.encode('ascii')[:16].ljust(16, b'\x00')
    struct.pack_into('<I', block, 0x1FC, calc_checksum(block))
    return block


def find_sn_blocks(image_data, key=DEFAULT_AES_KEY):
    """在 eMMC 镜像中扫描8个扇区, 解密并解析"""
    results = []
    for sector in SN_SECTORS:
        byte_offset = sector * SECTOR_SIZE
        if byte_offset + SECTOR_SIZE > len(image_data):
            results.append({
                'sector': sector, 'byte_offset': byte_offset,
                'found': False, 'reason': '超出镜像范围',
            })
            continue

        raw = image_data[byte_offset:byte_offset + SECTOR_SIZE]

        # 先试明文
        info = parse_sn_block(raw)
        if info:
            results.append({
                'sector': sector, 'byte_offset': byte_offset,
                'found': True, 'encrypted': False, **info,
            })
            continue

        # 再试解密
        decrypted = aes_ecb_decrypt(raw, key)
        info = parse_sn_block(decrypted)
        if info:
            results.append({
                'sector': sector, 'byte_offset': byte_offset,
                'found': True, 'encrypted': True, **info,
            })
            continue

        results.append({
            'sector': sector, 'byte_offset': byte_offset,
            'found': False, 'reason': 'Magic不匹配 (明文/解密均失败)',
        })
    return results


def cmd_read(args):
    """读取 eMMC 镜像中的序列号"""
    if len(args) < 1:
        print("用法: jz4750l_sn_tool.py read <emmc_image.bin> [--key HEX]")
        return 1

    image_path = args[0]
    key = DEFAULT_AES_KEY
    if '--key' in args:
        ki = args.index('--key')
        if ki + 1 < len(args):
            key = bytes.fromhex(args[ki + 1])
            if len(key) not in (16, 24, 32):
                print("错误: AES密钥必须16/24/32字节")
                return 1

    with open(image_path, 'rb') as f:
        image_data = f.read()

    print(f"=== JZ4750L eMMC 序列号读取 ===")
    print(f"镜像: {image_path}  ({len(image_data)} 字节, {len(image_data)/1024/1024:.1f} MB)")
    print(f"AES密钥 ({len(key)}字节): {key.hex()}\n")

    results = find_sn_blocks(image_data, key)
    found_count = sum(1 for r in results if r['found'])

    for r in results:
        tag = f"扇区 0x{r['sector']:04X}  偏移 {r['byte_offset']}"
        if r['found']:
            enc = "[加密]" if r['encrypted'] else "[明文]"
            ck = "OK" if r['checksum_ok'] else f"FAIL (存储=0x{r['stored_checksum']:08X}, 计算=0x{r['calc_checksum']:08X})"
            print(f"  {tag}  {enc}  序列号: {r['serial']}  版本: {r['version']}  校验: {ck}")
        else:
            print(f"  {tag}  [未找到] {r['reason']}")

    if found_count == 0:
        print("\n所有8个扇区均未找到有效序列号数据块。")
        return 1

    serials = set(r['serial'] for r in results if r['found'])
    if len(serials) > 1:
        print(f"\n不同扇区的序列号不一致: {serials}")
    else:
        print(f"\n当前序列号: {list(serials)[0]}")

    return 0


def cmd_write(args):
    """修改 eMMC 镜像中的序列号"""
    if len(args) < 2:
        print("用法: jz4750l_sn_tool.py write <emmc_image.bin> <新序列号> [-o output.bin] [--key HEX]")
        print("  序列号最大16个ASCII字符")
        return 1

    image_path = args[0]
    new_serial = args[1]
    output_path = None
    key = DEFAULT_AES_KEY

    if '-o' in args:
        oi = args.index('-o')
        if oi + 1 < len(args):
            output_path = args[oi + 1]
    if '--key' in args:
        ki = args.index('--key')
        if ki + 1 < len(args):
            key = bytes.fromhex(args[ki + 1])
            if len(key) not in (16, 24, 32):
                print("错误: AES密钥必须16/24/32字节")
                return 1

    if len(new_serial.encode('ascii')) > 16:
        print(f"错误: 序列号 '{new_serial}' 超过16字节限制")
        return 1

    with open(image_path, 'rb') as f:
        image_data = bytearray(f.read())

    print(f"=== JZ4750L eMMC 序列号写入 ===")
    print(f"镜像: {image_path}  ({len(image_data)} 字节)")
    print(f"AES密钥 ({len(key)}字节): {key.hex()}")
    print(f"新序列号: {new_serial}\n")

    # 先读取当前状态
    results = find_sn_blocks(image_data, key)
    found_count = sum(1 for r in results if r['found'])

    if found_count > 0:
        old_serials = set(r['serial'] for r in results if r['found'])
        encrypted_count = sum(1 for r in results if r['found'] and r['encrypted'])
        print(f"当前序列号: {old_serials}")
        if encrypted_count > 0:
            print(f"数据状态: AES加密")
        else:
            print(f"数据状态: 明文")
    else:
        print("当前: 未找到有效数据, 将创建新数据块")

    # 决定写入格式
    write_encrypted = True  # 默认加密
    if found_count > 0:
        plaintext_count = sum(1 for r in results if r['found'] and not r['encrypted'])
        if plaintext_count == found_count:
            write_encrypted = False

    print(f"写入模式: {'AES-256加密' if write_encrypted else '明文'}")

    # 构造明文数据块
    if found_count > 0:
        for r in results:
            if r['found']:
                bo = r['byte_offset']
                raw = image_data[bo:bo + SECTOR_SIZE]
                if r['encrypted']:
                    plain_block = bytearray(aes_ecb_decrypt(raw, key))
                else:
                    plain_block = bytearray(raw)
                break
    else:
        plain_block = make_sn_block(new_serial)

    # 修改序列号
    sn_bytes = new_serial.encode('ascii')[:16].ljust(16, b'\x00')
    plain_block[0x1C:0x2C] = sn_bytes
    struct.pack_into('<I', plain_block, 0x1FC, calc_checksum(plain_block))

    # 验证
    info = parse_sn_block(plain_block)
    assert info is not None, "构造的明文块Magic无效"
    assert info['serial'] == new_serial
    assert info['checksum_ok'], "校验和不匹配"

    # 加密 (如需要)
    if write_encrypted:
        write_block = aes_ecb_encrypt(bytes(plain_block), key)
    else:
        write_block = bytes(plain_block)

    # 写入所有8个扇区
    modified = 0
    for sector in SN_SECTORS:
        bo = sector * SECTOR_SIZE
        if bo + SECTOR_SIZE > len(image_data):
            print(f"  扇区 0x{sector:04X}: 超出镜像范围, 跳过")
            continue
        image_data[bo:bo + SECTOR_SIZE] = write_block
        modified += 1
        print(f"  扇区 0x{sector:04X}: 已写入 OK")

    if output_path is None:
        base, ext = os.path.splitext(image_path)
        output_path = f"{base}_modified{ext}"

    with open(output_path, 'wb') as f:
        f.write(image_data)

    print(f"\n已修改 {modified}/8 个扇区")
    print(f"输出: {output_path}")
    return 0


def cmd_info(args):
    """显示逆向分析摘要"""
    print(f"""=== JZ4750L 序列号系统逆向分析摘要 ===

1. 内核关键函数
   read_sn         0x8004FD60  读取序列号主函数
   prepare_sn_data 0x8005021C  构造序列号明文数据块
   aes_key_expand  0x80050354  AES密钥扩展 (支持128/192/256-bit)
   aes_decrypt_blk 0x80050898  AES单块解密 (16字节)
   mmc_read        0x8003CBB4  MMC扇区读取 (CMD17)
   mmc_init        0x8003F330  MMC初始化

2. read_sn 调用
   aes_key_expand(buf, 256)  ← 参数256选择AES-256路径 (14轮)
   密钥32字节: buf[0..7]=0x801A708C数据 + buf[8..31]=memset 0xAA

3. AES-256 密钥 (来自 GDB 转储)
   前8字节  (0x801A708C): 21 21 01 DE AD BE EF 29
   后24字节 (memset 0xAA): AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA
   完整密钥: {DEFAULT_AES_KEY.hex()}

4. 数据结构 (解密后, 512字节)
   0x00  4B  Magic1 = 0x20101228
   0x04  4B  Magic2 = 0x44313030
   0x08  4B  Magic3 = 0x5D245588
   0x0C  16B 版本字符串 "H2 V2.20"
   0x1C  16B 序列号 (ASCII)
   0x1FC 4B  校验和 (0x0C~0x1FB 字节累加和)

5. 8个扇区位置 (必须全部写入一致)
   扇区号    字节偏移
   0x7C00    16252928  (15.500 MB)
   0x7D00    16384000  (15.625 MB)
   0x7E00    16515072  (15.750 MB)
   0x7F00    16646144  (15.875 MB)
   0x8000    16777216  (16.000 MB)
   0x8100    16908288  (16.125 MB)
   0x8200    17039360  (16.250 MB)
   0x8300    17170432  (16.375 MB)
""")


def main():
    if len(sys.argv) < 2:
        print("JZ4750L eMMC 序列号修改工具\n")
        print("用法:")
        print(f"  {sys.argv[0]} read <emmc_image.bin> [--key HEX]            读取序列号")
        print(f"  {sys.argv[0]} write <emmc_image.bin> <新序列号> [-o out]   修改序列号")
        print(f"  {sys.argv[0]} info                                       显示分析报告")
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == 'read':
        sys.exit(cmd_read(args))
    elif cmd == 'write':
        sys.exit(cmd_write(args))
    elif cmd == 'info':
        cmd_info(args)
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
