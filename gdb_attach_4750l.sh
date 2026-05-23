#!/bin/bash -ex

# 0x00    0x00    0x62    0x8c    0x09    0xf8    0x40    0x00
# 0x00    0x00    0x00    0x00    0x89    0xe2    0x70    0x0c
# 0000628c09f84000
# 0000000089e2700c
# 0xF24 -> 0x81c30060

cat - > gdb_cmds.txt <<'GDB'
target remote localhost:8842
set architecture mips:isa32
set charset GBK
set target-charset GBK
# layout asm

# First stage loader
dprintf *0x80000270, "%s", $a0


# Kernel
# dbg_printf()
dprintf *0x80024bd4, "%s", $a0
# dprintf *0x80024bd4, "ra:%#010x -> %s%#010x, %#010x, %#010x, %#010x\n", $ra, $a0, $a0, $a1, $a2, $a3
# dbg_puts()
dprintf *0x80025b5c, "%s\n", $a0
# # File access error
# dprintf *0x80045f50, "=== %s\n", $s2
# # fopen()
# dprintf *0x8002a8e0, "%#010x: fopen(\"%s\", \"%s\")\n", $ra, $a0, $a1
# dprintf *0x8002a960, "%#010x: fopen() = %#010x\n", $ra, $v0
# # fclose()
# dprintf *0x8003591c, "%#010x: fclose(%#010x)\n", $ra, $a0
# # strlen()
# dprintf *0x80024a98, "strlen(%#010x = \"%s\")\n", *$a0, $a0
# # fs_read_sector()
# dprintf *0x8003ab60, "ra:%#010x -> %#010x: fs_read_sector(%d, %#010x, %#010x, %#010x)\n", $ra, $pc, $a0, $a1, $a2, $a3

# dprintf *0x80036fc0, "ra:%#010x -> %#010x: (%d, %#010x, %#010x)\n", $ra, $pc, $a0, $a1, $a2
# dprintf *0x800303d8, "ra:%#010x -> %#010x: (%d, %#010x), 0x8019f480 = %#010x, 0x8019f460 = %#010x\n", $ra, $pc, $a0, $a1, *(unsigned long *)0x8019f480, *(unsigned long *)0x8019f460


# b *0x80045f50
# b *0x80020c58
b *0x80008644


# SN
# b *0x8004fd60
# watch *(unsigned long *)0x801a708c

# dprintf *0x80050898, "ra:%#010x -> %#010x: aes_decrypt(%#010x, %#010x)\n", $ra, $pc, $a0, $a1
# b *0x80050898
# commands
#     silent
#     set $aes_in = $a0
#     set $aes_out = $a1
#     c
# end
# b *0x800500e8
# commands
#     silent
#     x/16xb $aes_in
#     x/16xb $aes_out
#     c
# end

dprintf *0x80050100, "%#010x == %#010x\n", $v0, $v1
dprintf *0x80050110, "%#010x == %#010x\n", $v0, $v1
dprintf *0x80050120, "%#010x == %#010x\n", $v0, $v1
dprintf *0x80050130, "strncmp(%#010x = %#010x, %#010x)\n", $a0, *$a0, *($a0+4)
dprintf *0x80050138, "strncmp() = %#010x\n", $v0

watch *(unsigned long *)0x801a7084
commands
    silent
    printf "ra:%#010x -> %#010x: 0x801a7084 = %#010x\n", $ra, $pc, *0x801a7084
    c
end

# b *0x80050354
# commands
#     silent
#     printf "ra:%#010x -> %#010x: aes_key_expand(%#010x, %#010x)\n", $ra, $pc, $a0, $a1
#     x/32xb $a0
#     c
# end

# ra:0x80037014 -> 0x800303d8: (0, 0x00000003), 0x8019f480 = 0x00000010, 0x8019f460 = 0x000001d0
# ra:0x80037028 -> 0x8003ab60: fs_read_sector(0, 0x000001e0, 0x00000010, 0x809eeee0)

# ra:0x80037014 -> 0x800303d8: (0, 0x00000003), 0x8019f480 = 0x00000040, 0x8019f460 = 0x000001d0
# ra:0x80037028 -> 0x8003ab60: fs_read_sector(0, 0x00000210, 0x00000040, 0x80cd0080)


# # Switch os type -> 小学
# b *0x800442c0
# commands
#     p *(unsigned long *)0x80487dd8 = 1
#     c
# end


# dprintf *0x804c4bdc, "%#010x: printf(\"%s\", \"%s\")\n", $pc, $a0, $a1
# b *0x81c30060

# dprintf *0x8003cbb4, "%#010x -> msc0_read_sn(%#010x, %#010x)\n", $ra, $a0, $a1


# GUI加载完毕2
# 这里被跳出
# 0x80045e90: fopen(A:\系统\数据\Shell\imedat.dlx, rb)
# 0x80045e90: fopen() = 0000000000
# === A:\系统\数据\Shell\imedat.dlx
# ===%s
# 文件读写有问题
# b *0x80045e88
# b *0x80045e90

# dprintf *0x8002a550, "fopen_3() = %d\n", $v0

# dprintf *0x8002fb54, "%#010x: %s\n", $pc, $a0

# dprintf *0x8002db14, "%#010x: %s\n", $pc, $s1
# dprintf *0x8002dbdc, "%#010x: short_name = \"%s\", attr=%#04x\n", $pc, $s1, *(unsigned char *)($s1+11)

# b *0x8002dad4
# commands
#     x/22xw    $s8
#     c
# end

# dprintf *0x8002a8fc, "FUN_80025ab8(%#010x) = ", $a0
# dprintf *0x8002a904, "%#010x\n", $v0
# dprintf *0x800299e0, "FUN_800299e0(%s, %s)\n", $a0, $a1
# dprintf *0x8002a918, "FUN_800299e0(%s, %s) = %#010x\n", $s0, $s1, $v0
# dprintf *0x8002a3c0, "fopen_2(\"%s\", \"%s\")\n", $a0, $a1
# dprintf *0x8002a534, "FUN_800299e0(\"%s\", \"%s\")\n", $s1, $s4
# dprintf *0x8002d9d0, "FUN_8002d9d0(%#010x, \"%s\", %#010x, %#010x)\n", $a0, $a1, $a2, $a3
# dprintf *0x8002a550, "FUN_8002d9d0() = %#010x\n", $v0
# dprintf *0x8002a7ec, "(mode_flag & 8) == %d\n", $s0

# b *0x8002e834
# commands
#     set $param0 = $a0
#     set $param1 = $a1
#     c
# end
# dprintf *0x8002da18, "FUN_8002e834(%s) -> %s\n", $param0, $param1

# dprintf *0x8002da2c, "%#010x: %#010x == %#010x\n", $pc, $a0, $v0
# dprintf *0x8002da34, "%#010x: %#010x - 2\n", $pc, $v1
# dprintf *0x8002da38, "%#010x: %d == 0\n", $pc, $v0
# dprintf *0x8002da80, "%#010x: %#010x == %#010x\n", $pc, $v0, $v1
# dprintf *0x8002da90, "%#010x: %#010x == 0\n", $pc, $v0
# dprintf *0x8002daa0, "%#010x: %#010x == 0\n", $pc, $v0
# dprintf *0x8002daac, "%#010x: %#010x == %#010x\n", $pc, $v0, $s6
# dprintf *0x8002e60c, "%#010x: %s\n", $pc, $s7
# dprintf *0x8002dad4, "%#010x: %#010x == 0\n", $pc, $v1
# dprintf *0x8002dc80, "%#010x: %#010x == %#010x\n", $pc, $v0, $s6
# dprintf *0x8002dafc, "%#010x: %#010x == 0\n", $pc, $v0
# dprintf *0x8002db1c, "%#010x: 0x%x(%c) != 0\n", $pc, $v1, $v1
# dprintf *0x8002db30, "%#010x: %#010x != %#010x\n", $pc, $s6, $s5
# dprintf *0x8002dbe8, "%#010x: %#010x == %#010x\n", $pc, $v0, $v1
# dprintf *0x8002dbf4, "%#010x: %#010x != 0\n", $pc, $a0
# dprintf *0x8002dc0c, "%#010x: %#010x == %#010x, %s\n", $pc, $v0, $v1, $s1
# dprintf *0x8002dc2c, "%#010x: %#010x != 0\n", $pc, $v0
# dprintf *0x8002dde4, "%#010x: %#010x, %#010x\n", $pc, $v1, $s2
# dprintf *0x8002ed6c, "%#010x: %#010x == %#010x\n", $pc, $v0, $s6
# dprintf *0x8002ef48, "%#010x: %s\n", $pc, $s3
# dprintf *0x8002effc, "%#010x: %s\n", $pc, $s0

# watch *(unsigned long *)0x8019f480
# dprintf *0x80034368, "ra:%#010x -> %#010x fs_init(): %#010x, %#010x\n", $ra, $pc, $a2, *(unsigned long *)0x801a45c0

# watch *(unsigned long *)0x81c419c8
# commands
#     x/xw 0x81c419c8
# end

# dprintf *0x80034160, "ra:%#010x -> %#010x fs_init(%u)\n", $ra, $pc, $a0
# b *0x80034368
# commands
#     printf "ra:%#010x -> %#010x fs_init(): %#010x\n", $ra, $pc, $a2
#     x/32xw 0x801a45c0
# end

#            Code,    OS Name,                  BpSec, SC,Resv,
# 01E80000   EB 3C 90 6D  6B 66 73 2E  66 61 74 00  02 10 20 00  02 00 02 00  00 F8 C0 00  3F 00 10 00  00 00 00 00  .<.mkfs.fat... .........?.......
# 01E80020   D5 8B 0B 00  80 00 29 AC  75 59 BA 4E  4F 20 4E 41  4D 45 20 20  20 20 46 41  54 31 36 20  20 20 0E 1F  ......).uY.NO NAME    FAT16   ..
# 01E80040   BE 5B 7C AC  22 C0 74 0B  56 B4 0E BB  07 00 CD 10  5E EB F0 32  E4 CD 16 CD  19 EB FE 54  68 69 73 20  .[|.".t.V.......^..2.......This
# 01E80060   69 73 20 6E  6F 74 20 61  20 62 6F 6F  74 61 62 6C  65 20 64 69  73 6B 2E 20  20 50 6C 65  61 73 65 20  is not a bootable disk.  Please
# 01E80080   69 6E 73 65  72 74 20 61  20 62 6F 6F  74 61 62 6C  65 20 66 6C  6F 70 70 79  20 61 6E 64  0D 0A 70 72  insert a bootable floppy and..pr
# 01E800A0   65 73 73 20  61 6E 79 20  6B 65 79 20  74 6F 20 74  72 79 20 61  67 61 69 6E  20 2E 2E 2E  20 0D 0A 00  ess any key to try again ... ...
# 01E800C0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E800E0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E80100   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E80120   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E80140   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E80160   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E80180   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E801A0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E801C0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 01E801E0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 55 AA  ..............................U.

# 1BD80000   EB 58 90 6D  6B 66 73 2E  66 61 74 00  02 10 20 00  02 00 00 00  00 F8 00 00  3F 00 40 00  00 00 00 00  .X.mkfs.fat... .........?.@.....
# 1BD80020   D3 0F 32 00  50 06 00 00  00 00 00 00  02 00 00 00  01 00 06 00  00 00 00 00  00 00 00 00  00 00 00 00  ..2.P...........................
# 1BD80040   80 00 29 A5  DC 62 BA 4E  4F 20 4E 41  4D 45 20 20  20 20 46 41  54 33 32 20  20 20 0E 1F  BE 77 7C AC  ..)..b.NO NAME    FAT32   ...w|.
# 1BD80060   22 C0 74 0B  56 B4 0E BB  07 00 CD 10  5E EB F0 32  E4 CD 16 CD  19 EB FE 54  68 69 73 20  69 73 20 6E  ".t.V.......^..2.......This is n
# 1BD80080   6F 74 20 61  20 62 6F 6F  74 61 62 6C  65 20 64 69  73 6B 2E 20  20 50 6C 65  61 73 65 20  69 6E 73 65  ot a bootable disk.  Please inse
# 1BD800A0   72 74 20 61  20 62 6F 6F  74 61 62 6C  65 20 66 6C  6F 70 70 79  20 61 6E 64  0D 0A 70 72  65 73 73 20  rt a bootable floppy and..press
# 1BD800C0   61 6E 79 20  6B 65 79 20  74 6F 20 74  72 79 20 61  67 61 69 6E  20 2E 2E 2E  20 0D 0A 00  00 00 00 00  any key to try again ... .......
# 1BD800E0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD80100   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD80120   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD80140   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD80160   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD80180   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD801A0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD801C0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................................
# 1BD801E0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 55 AA  ..............................U.

# ra:0x800341b4 -> 0x8003ab60: fs_read_sector(0, 0000000000, 0x00000001, 0x801a45c0)
# Breakpoint 13, 0x80034368 in ?? ()
# ra:0x800342d8 -> 0x80034368 fs_init(): 0x00000010
# 0x801a45c0:     0x6d903ceb      0x2e73666b      0x00746166      0x00101002
# 0x801a45d0:     0x00020002      0x00c0f800      0x0010003f      0x00000000
# 0x801a45e0:     0x000b8bd5      0xc2290080      0x4e0303e9      0x414e204f
# 0x801a45f0:     0x2020454d      0x41462020      0x20363154      0x1f0e2020
# 0x801a4600:     0xac7c5bbe      0x0b74c022      0xbb0eb456      0x10cd0007
# 0x801a4610:     0x32f0eb5e      0xcd16cde4      0x54feeb19      0x20736968
# 0x801a4620:     0x6e207369      0x6120746f      0x6f6f6220      0x6c626174
# 0x801a4630:     0x69642065      0x202e6b73      0x656c5020      0x20657361

# ra:0x800341b4 -> 0x8003ab60: fs_read_sector(1, 0000000000, 0x00000001, 0x801a45c0)
# Breakpoint 13, 0x80034368 in ?? ()
# ra:0x800342d8 -> 0x80034368 fs_init(): 0x00000020
# 0x801a45c0:     0x6d903ceb      0x2e73666b      0x00746166      0x00202002
# 0x801a45d0:     0x00020002      0x0100f800      0x0040003f      0x00000000
# 0x801a45e0:     0x001ffff8      0x2c290080      0x4e031494      0x414e204f
# 0x801a45f0:     0x2020454d      0x41462020      0x20363154      0x1f0e2020
# 0x801a4600:     0xac7c5bbe      0x0b74c022      0xbb0eb456      0x10cd0007
# 0x801a4610:     0x32f0eb5e      0xcd16cde4      0x54feeb19      0x20736968
# 0x801a4620:     0x6e207369      0x6120746f      0x6f6f6220      0x6c626174
# 0x801a4630:     0x69642065      0x202e6b73      0x656c5020      0x20657361


# 0x80045e90: fopen("A:\系统\数据\Shell\imedat.dlx", "rb")
# strlen(0xcf5c3a41 = "A:\系统\数据\Shell\imedat.dlx")
# strlen(0xcf5c3a41 = "A:\系统\数据\Shell\imedat.dlx")
# 0x8002dbdc: short_name = "A鹼邁", attr=0x0f
# 0x8002dbdc: short_name = "__~1       ", attr=0x10
# 0x8002ed6c: long name = 0x809f1720:     u"系统"
# 0x8002dc2c: 数据\Shell\imedat.dlx
# 0x8002dda4: cluster = 0x00000190
# strlen(0xddbefdca = "数据\Shell\imedat.dlx")
# 0x8002de20: cluster = 0x00000003
# ra:0x8002de5c -> 0x80036fc0: (0, 0x00000003, 0x80cd0080)
# ra:0x80037014 -> 0x800303d8: (0, 0x00000003), 0x8019f480 = 0x00000020, 0x8019f460 = 0x000001b0
# ra:0x80037028 -> 0x8003ab60: fs_read_sector(0, 0x000001d0, 0x00000020, 0x80cd0080)
# 0x8002de78: short name = ".          "
# 0x8002de78: short name = "..         "
# 0x8002de78: short name = "Ab"
# 0x8002de78: short name = "BGPIC0  BIN "
# 0x8002ed6c: long name = 0x809f1720:     u"bgpic0.bin"

# 0x80017724: fopen("A:\系统\数据\SysTp.cfg", "rb")
# strlen(0xcf5c3a41 = "A:\系统\数据\SysTp.cfg")
# strlen(0xcf5c3a41 = "A:\系统\数据\SysTp.cfg")
# 0x8002dbdc: short_name = "A鹼邁", attr=0x0f
# 0x8002dbdc: short_name = "__~1       ", attr=0x10
# 0x8002ed6c: long name = 0x809f0ee0:     u"系统"
# 0x8002dc2c: 数据\SysTp.cfg
# 0x8002dda4: cluster = 0x00000190
# strlen(0xddbefdca = "数据\SysTp.cfg")
# 0x8002de20: cluster = 0x00000003
# ra:0x8002de5c -> 0x80036fc0: (0, 0x00000003, 0x809eeee0)
# ra:0x80037014 -> 0x800303d8: (0, 0x00000003), 0x8019f480 = 0x00000010, 0x8019f460 = 0x000001b0
# ra:0x80037028 -> 0x8003ab60: fs_read_sector(0, 0x000001c0, 0x00000010, 0x809eeee0)
# 0x8002de78: short name = ".          "
# 0x8002de78: short name = "..         "
# 0x8002de78: short name = "AM憂"
# 0x8002de78: short name = "__~1       "
# 0x8002ed6c: long name = 0x809f0ee0:     u"配置"
# 0x8002df8c: (null)
# 0x8002de78: short name = "Apenc"
# 0x8002de78: short name = "__~2       "
# 0x8002ed6c: long name = 0x809f0ee0:     u"数据"
# 0x8002df8c: SysTp.cfg
# strlen(0x54737953 = "SysTp.cfg")
# 0x8002de20: cluster = 0x000000e1
# ra:0x8002de5c -> 0x80036fc0: (0, 0x000000e1, 0x809eeee0)
# ra:0x80037014 -> 0x800303d8: (0, 0x000000e1), 0x8019f480 = 0x00000010, 0x8019f460 = 0x000001b0
# ra:0x80037028 -> 0x8003ab60: fs_read_sector(0, 0x00000fa0, 0x00000010, 0x809eeee0)

# dprintf *0x8002dc2c, "%#010x: %s\n", $pc, $v0
# dprintf *0x8002dda4, "%#010x: cluster = %#010x\n", $pc, $s3
# dprintf *0x8002de20, "%#010x: cluster = %#010x\n", $pc, $s3
# dprintf *0x8002de78, "%#010x: short name = \"%s\"\n", $pc, $s1

# dprintf *0x8002df8c, "%#010x: %s\n", $pc, $v0

# b *0x8002ed6c
# set $long_name_last = 'a'
# commands
#     silent
#     set target-charset UCS2
#     printf "%#010x: long name = ", $pc
#     x/sh $s4
#     set target-charset GBK
#     if *(unsigned long *)$s4 != 0 || $long_name_last != 0
#         set $long_name_last = *(unsigned long *)$s4
#         c
#     end
# end



# b *0x80030430
# commands
#     silent
#     printf "%#010x: %#010x = %#010x \"%s\"\n", $pc, $a0, *$a0, $a0
#     # x/32xw $a1
#     c
# end

# dprintf *0x8002da18, "%#010x: %s\n", $pc, $v0

# dprintf *0x8002de08, "%#010x: %#010x == 0\n", $pc, $v0
# dprintf *0x8002dcc4, "%#010x;\n", $pc
# dprintf *0x8002de18, "%#010x: %d == 0\n", $pc, $v0
# dprintf *0x8002de64, "%#010x: %#010x == 0\n", $pc, $a0
# # dprintf *0x8002de70, "%#010x: %#010x == %#010x\n", $pc, $s6, $s5
# dprintf *0x8002de80, "%#010x: %#x(%c) != 0\n", $pc, $v1, $v1
# # dprintf *0x8002e18c, "%#010x: %#x(%c) == %#x\n", $pc, $v1, $v1, $a0
# dprintf *0x8002dfa4, "%#010x: %d != 0\n", $pc, $v1
# dprintf *0x8002df38, "%#010x: %#010x == %#010x\n", $pc, $a0, $v0
# dprintf *0x8002df8c, "%#010x: %s\n", $pc, $v0

# b *0x8002ecd8
# commands
#     i r
#     set $param0 = $a0
#     set $param1 = $a1
#     set $param2 = $a2
#     set $param3 = $a3
#     x/4xw $a2
#     x/s $a3
#     c
# end
# b *0x8002df8c
# commands
#     x/4wx $param2
#     x/4wx $param3
#     c
# end


# b *0x8009310c
# b *0x800932e0

b *0x800064e4

# b *0x800924d0
# b *0x80092e50
# b *0x80092e58

# b *0x80013260

# b *0x8002a8e0
# b *0x80013268

# 0x80e560e0 + 0x80e560e0 = 0x01cac1c0

# b *0x8002e918
# b *0x8002e950
# b *0x80030a38
# b *0x80031f68
# b *0x80031f8c

# b *0x8002bf6c
# b *0x8002eb8c
# b *0x8003073c
# b *0x80030a38

# b *0x8002c080
# b *0x8002c08c
# b *0x8002d9d0

# b *0x8001321c
# b *0x80013228
# b *0x80013260
# b *0x80013268
# b *0x800133ac
# b *0x800133b4

# b *0x80013ed8
# b *0x80014cb8
# b *0x80013ee0

# b *0x804af0b8
# b *0x804af0c0
# b *0x804af0c8
# b *0x804af0d0
# b *0x804af0dc
# b *0x804af0f0
# b *0x804af0f8
# b *0x804af138
# b *0x804af120
# b *0x804af130

# b *0x80000270
# b *0x80024bd4
# commands 1-2
# 	silent
# 	# print -raw-values on -repeats unlimited -- /s (char *)$a0
# 	printf "%s", $a0
# 	# output (char *)$a0
# 	# x /s $a0
# 	c
# end



# dprintf *0x8003ee88, "ra:%#010x -> %#010x: krn_msc0_cmd(p=%#010x, cmd=%u, arg=%#010x, nb=%#010x)\n", $ra, $pc, $a0, $a1, $a2, $a3
# dprintf *0x80042300, "ra:%#010x -> %#010x: krn_msc1_cmd(p=%#010x, cmd=%u, arg=%#010x, nb=%#010x)\n", $ra, $pc, $a0, $a1, $a2, $a3
# dprintf *0x81c3469c, "ra:%#010x -> %#010x: upg_msc0_cmd(p=%#010x, cmd=%u, arg=%#010x, nb=%#010x)\n", $ra, $pc, $a0, $a1, $a2, $a3



GDB

. ~/mips/toolchain/vars
# exec mipsel-linux-gdb -x gdb_cmds.txt
exec luit -encoding GBK mipsel-linux-gdb -x gdb_cmds.txt
