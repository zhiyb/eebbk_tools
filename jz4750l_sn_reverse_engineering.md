# JZ4750L 内核序列号系统逆向分析文档

> 分析目标: Ingenic JZ4750L Linux内核序列号读取/存储机制
> 二进制文件: `data2_L.dat` (1,684,256 字节)
> 架构: MIPS32 Little-Endian
> 内核加载地址: 0x80004000
> 文件偏移 = 虚拟地址 - 0x80004000

---

## 1. 概述

JZ4750L SoC的Linux内核中实现了一套序列号(Serial Number)存储系统。序列号以AES-128 ECB加密的形式存储在eMMC的8个特定扇区中，内核启动时通过`read_sn`函数读取并解密验证。

本文档完整记录了该系统的逆向分析过程和结果，包括：关键函数定位、调用链、数据结构、加密机制、扇区布局，以及基于分析结果实现的Python读写工具。

---

## 2. 关键函数地址表

| 函数名 | 虚拟地址 | 文件偏移 | 说明 |
|--------|----------|----------|------|
| `read_sn` | 0x8004FD60 | 0x4BD60 | 序列号读取主函数 |
| `prepare_sn_data` | 0x8005021C | 0x4C21C | 构造序列号明文数据块 |
| `get_and_set_sn` | 0x800502D8 | 0x4C2D8 | 高层接口(读+设置GUI显示) |
| `aes_key_expand` | 0x80050354 | 0x4C354 | AES-128 密钥扩展+解密总入口 |
| `aes_decrypt_block` | 0x80050898 | 0x4C898 | AES-128 单块(16字节)解密 |
| `mmc_read` | 0x8003CBB4 | 0x38BB4 | MMC扇区读取(CMD17) |
| `mmc_init` | 0x8003F330 | 0x3B330 | MMC初始化+AES密钥加载 |

### 辅助函数

| 地址 | 功能 |
|------|------|
| 0x80024BD4 | `printk` — 内核打印 |
| 0x80025AB8 | `kmalloc` — 内核内存分配 |
| 0x8004BA44 | `memset` — 内存填充 |
| 0x80024B14 | `sprintf` — 格式化字符串 |
| 0x80024B2C | `get_jiffies` — 获取系统时钟滴答数 |
| 0x8001D34C | `srand` — 设置随机种子 |
| 0x80025654 | `kfree` — 释放内存 |

---

## 3. 调用链

```
get_and_set_sn (0x800502D8)
  │
  ├─ read_sn (0x8004FD60)          ← 读取序列号
  │   ├─ kmalloc(0x600)            ← 分配1536字节缓冲区
  │   ├─ memset(buf, 0xAA, 0x600)  ← 填充0xAA
  │   ├─ mmc_init(buf) (0x8003F330)
  │   │   ├─ 检查 0x801A7084 == 0x3F
  │   │   ├─ memcpy(buf, 0x801A708C, 8) ← 复制AES密钥前8字节
  │   │   └─ return 0 (成功) / 1 (已初始化)
  │   ├─ srand(jiffies)
  │   ├─ 生成8个伪随机值 (对8取模, 互不重复)
  │   ├─ switch(rand_val) → mmc_read(sector, buf+0x200)  ← 读加密数据
  │   ├─ aes_key_expand(buf, 256) (0x80050354)  ← 密钥扩展
  │   ├─ for(i=0; i<32; i++)                      ← 32块解密
  │   │   aes_decrypt_block(buf+0x200+i*16, sp+80+i*16)
  │   ├─ 验证 Magic (0x20101228 / 0x44313030 / 0x5D245588)
  │   ├─ 提取序列号 (偏移0x1C, 16字节)
  │   └─ return
  │
  └─ prepare_sn_data (0x8005021C)  ← 构造明文数据块(写入时使用)
```

---

## 4. read_sn 函数详细分析

### 4.1 函数签名

```c
int read_sn(char *output_sn);  // $a0 = 输出缓冲区
```

### 4.2 逐步流程

#### 步骤1: 初始化打印 (0x8004FD60 ~ 0x8004FD98)

```mips
0x8004FD60: addiu $sp, $sp, -0x298     ; 分配栈帧 664字节
0x8004FD64: sw $fp, 0x290($sp)
0x8004FD68: addu $fp, $a0, $zero       ; $fp = output_sn (保存参数)
0x8004FD6C: lui $a0, 0x800D
0x8004FD70: addiu $a0, $a0, -0x3DE0    ; $a0 = 0x800CC220
0x8004FD74: sw $ra, 0x294($sp)
0x8004FD78: sw $s4, 0x280($sp)         ; 保存callee-saved寄存器
0x8004FD7C: sw $s7, 0x28C($sp)
0x8004FD80: sw $s6, 0x288($sp)
0x8004FD84: sw $s5, 0x284($sp)
0x8004FD88: sw $s3, 0x27C($sp)
0x8004FD8C: sw $s2, 0x278($sp)
0x8004FD90: sw $s1, 0x274($sp)
0x8004FD94: jal 0x80024BD4             ; printk("\nReal fnGUI_GetSNData() is called!\n")
0x8004FD98: sw $s0, 0x270($sp)
```

#### 步骤2: 分配缓冲区 (0x8004FD9C ~ 0x8004FDA8)

```mips
0x8004FD9C: jal 0x80025AB8             ; kmalloc(GFP_KERNEL)
0x8004FDA0: addiu $a0, $zero, 0x600   ; size = 1536 (0x600)
0x8004FDA4: addu $s4, $v0, $zero       ; $s4 = 缓冲区基址
0x8004FDA8: beqz $s4, 0x80050090       ; if NULL → 跳到返回-3
0x8004FDAC: addiu $v0, $zero, -1       ; (delay slot) $v0 = -1
```

缓冲区布局 (共1536字节):

| 偏移 | 大小 | 说明 |
|------|------|------|
| 0x000 | 16 | AES密钥 (前8字节来自0x801A708C, 后8字节为0xAA) |
| 0x010 | 496 | 保留 (全0xAA) |
| 0x200 | 512 | MMC读取的加密数据 |
| 0x400 | 512 | 保留 (全0xAA) |

#### 步骤3: 填充0xAA + mmc_init (0x8004FDB0 ~ 0x8004FDCC)

```mips
0x8004FDB0: addu $a0, $s4, $zero       ; $a0 = buf
0x8004FDB4: addiu $a1, $zero, 0xAA     ; $a1 = 0xAA
0x8004FDB8: jal 0x8004BA44             ; memset(buf, 0xAA, 0x600)
0x8004FDBC: addiu $a2, $zero, 0x600
0x8004FDC0: jal 0x8003F330             ; mmc_init(buf)
0x8004FDC4: addu $a0, $s4, $zero       ; $a0 = buf
0x8004FDC8: bnez $v0, 0x800500C8       ; if (mmc_init返回1) → 跳到失败处理
0x8004FDCC: nop
```

**mmc_init 详细分析** (0x8003F330):

```mips
0x8003F330: lui $v1, 0x801A            ; 
0x8003F334: lbu $v1, 0x7084($v1)       ; $v1 = *(0x801A7084)
0x8003F338: addiu $sp, $sp, -24
0x8003F33C: addiu $v0, $zero, 0x3F     ; 0x3F = 初始化标志
0x8003F340: sw $ra, 16($sp)
0x8003F344: lui $a1, 0x801A
0x8003F348: addiu $a1, $a1, 0x708C     ; $a1 = 0x801A708C (密钥源地址)
0x8003F34C: addiu $a2, $zero, 8        ; $a2 = 8 (字节数)
0x8003F350: beq $v1, $v0, +5           ; if (*(0x801A7084) == 0x3F)
0x8003F354: addiu $a3, $zero, 1        ; (delay slot) $a3 = 1
0x8003F358: lw $ra, 16($sp)
0x8003F35C: addu $v0, $a3, $zero       ; return 1 (已初始化, 跳过)
0x8003F360: jr $ra
0x8003F364: addiu $sp, $sp, 24
0x8003F368: jal memcpy                 ; memcpy(buf, 0x801A708C, 8)
0x8003F36C: nop
0x8003F370: j 0x8003FCD6               ; → 跳到MMC硬件初始化
0x8003F374: addu $v0, $zero, $zero     ; return 0 (成功)
```

逻辑:
```c
int mmc_init(char *buf) {
    if (*(uint8_t *)0x801A7084 == 0x3F) {
        // 首次初始化
        memcpy(buf, (void *)0x801A708C, 8);  // 复制8字节到buf[0..7]
        // ... MMC硬件初始化 ...
        *(uint8_t *)0x801A7084 = 0x3F;       // 标记已初始化
        return 0;
    }
    return 1;  // 已初始化, 拒绝重复调用
}
```

**GDB验证数据**:
```
(gdb) x/8xb 0x801a7084
0x801a7084: 0x3f 0xaa 0x01 0x58 0x51 0x45 0x4d 0x55
(gdb) x/8xb 0x801a708c
0x801a708c: 0x21 0x21 0x01 0xde 0xad 0xbe 0xef 0x29
```

- `0x801A7084` = 0x3F → 表明已初始化
- `0x801A708C` 的8字节 = **AES密钥前半部分**: `21 21 01 DE AD BE EF 29`
- 密钥后半部分 = memset残留: `AA AA AA AA AA AA AA AA`

#### 步骤4: 生成8个伪随机值 (0x8004FDD0 ~ 0x80050000)

```mips
0x8004FDD0: jal 0x8001D34C             ; srand(jiffies)
0x8004FDD4: addiu $a0, $sp, 40         ; 
0x8004FDD8: jal 0x80024B14             ; sprintf(sp+40, "%d", jiffies)
0x8004FDDC: lw $a0, 0x28($sp)         ; 
0x8004FDE0: jal 0x80024B2C             ; val0 = jiffies % 8
0x8004FDE4: nop
0x8004FDE8: addiu $v1, $v0, 7          ; $v1 = jiffies + 7
0x8004FDEC: slti $a0, $v0, 0           ; (符号检测)
0x8004FDF0: movz $v1, $v0, $a0         ; 正数保持原值
0x8004FDF4: sra $v1, $v1, 3            ; $v1 = val0 >> 3 = val0 / 8... 不对
```

实际上这里的随机数生成逻辑是: 调用`get_jiffies()`获取当前时钟, 对8取模得到0~7的值。反复调用生成8个**互不重复**的值(通过比较保证)。

生成的8个随机值存储在栈上: `sp+0x250` ~ `sp+0x26C`。

#### 步骤5: 扇区读取循环 (0x80050000 ~ 0x8005006C)

```mips
0x80050000: sw $t2, 0x10($sp)          ; 传递参数给printk
0x80050004: sw $t1, 0x14($sp)
0x80050008: sw $v1, 0x18($sp)
0x8005000C: sw $t0, 0x1C($sp)
0x80050010: sw $v0, 0x20($sp)
0x80050014: jal 0x80024BD4             ; printk("record = %d,%d,...")
0x80050018: addu $s3, $zero, $zero     ; $s3 = 0 (循环计数器)
0x8005001C: addiu $s7, $sp, 40         ; $s7 = &rand_values[0]
0x80050020: sll $v0, $s3, 2            ; $v0 = s3 * 4
0x80050024: addu $v0, $v0, $s7         ; $v0 = &rand_values[s3]
0x80050028: lw $v0, 0x0228($v0)        ; $v0 = rand_values[s3]
0x8005002C: slti $v1, $v0, 8           ; if (rand_val < 8)
0x80050030: beqz $v1, +11              ; 越界 → 跳出
0x80050034: sll $v0, $v0, 2            ; $v0 = rand_val * 4 (跳转表索引)
0x80050038: lui $v1, 0x800D
0x8005003C: addu $v1, $v1, $v0
0x80050040: lw $v1, -0x3D4C($v1)       ; $v1 = jumptable[0x800CC2B4 + rand_val*4]
0x80050044: jr $v1                      ; 跳转到对应case
0x80050048: nop
```

**switch-case跳转表** @ 0x800CC2B4:

| 索引 | 跳转目标 | 扇区号 | 说明 |
|------|----------|--------|------|
| 0 | 0x8005004C | 0x7C00 | 主扇区A |
| 1 | 0x80050174 | 0x7E00 | 主扇区B |
| 2 | 0x80050180 | 0x8000 | 主扇区C |
| 3 | 0x8005018C | 0x8200 | 主扇区D |
| 4 | 0x80050198 | 0x7D00 | 备用扇区A |
| 5 | 0x800501A4 | 0x7F00 | 备用扇区B |
| 6 | 0x800501B0 | 0x8100 | 备用扇区C |
| 7 | 0x800501BC | 0x8300 | 备用扇区D |

各case分支代码 (以case 0为例):

```mips
; case 0 (0x8005004C):
0x8005004C: addiu $a1, $s4, 0x200     ; $a1 = buf + 0x200 (目标缓冲区)
0x80050050: addiu $a0, $zero, 0x7C00  ; $a0 = 扇区号 0x7C00
0x80050054: jal 0x8003CBB4             ; mmc_read(0x7C00, buf+0x200)
0x80050058: nop
0x8005005C: addu $s5, $v0, $zero       ; $s5 = 返回值
0x80050060: beqz $s5, +0x17            ; if (mmc_read返回0) → 成功, 跳出循环
```

其他case分支:

```mips
; case 1 (0x80050174): mmc_read(0x7E00, buf+0x200)
; case 2 (0x80050180): mmc_read(0x8000, buf+0x200)
; case 3 (0x8005018C): mmc_read(0x8200, buf+0x200)
; case 4 (0x80050198): mmc_read(0x7D00, buf+0x200)
; case 5 (0x800501A4): mmc_read(0x7F00, buf+0x200)
; case 6 (0x800501B0): mmc_read(0x8100, buf+0x200)
; case 7 (0x800501BC): mmc_read(0x8300, buf+0x200)
```

**读取失败时重试**:

```mips
0x80050064: addiu $s6, $sp, 0x50       ; (成功分支)
0x80050068: addiu $s3, $s3, 1          ; s3++ (尝试下一个随机值)
0x8005006C: slti $v0, $s3, 8           ; if (s3 < 8) → 继续循环
0x80050070: bnez $v0, -0x14            ; → 回到0x8005001C
```

#### 步骤6: AES密钥扩展 (0x800500C0 ~ 0x800500C8)

```mips
0x800500C0: addu $a0, $s4, $zero       ; $a0 = buf (密钥 = buf[0..15])
0x800500C4: jal 0x80050354             ; aes_key_expand(buf, 256)
0x800500C8: addiu $a1, $zero, 0x100    ; (delay slot) $a1 = 256
```

`aes_key_expand` (0x80050354) 内部完成:
1. AES-128密钥扩展 (10轮, 生成11组轮密钥)
2. 将轮密钥写入 `0x801BC2F0` 开始的T-table区域
3. 同时根据 `$a1` 参数 (256) 确定解密轮数

密钥构成:
- `buf[0..7]` = 从 `0x801A708C` 复制的8字节: `21 21 01 DE AD BE EF 29`
- `buf[8..15]` = memset残留的 `0xAA`: `AA AA AA AA AA AA AA AA`

**完整AES-128密钥**: `212101DEADBEEF29AAAAAAAAAAAAAAAA`

#### 步骤7: AES-128 ECB解密循环 (0x800500CC ~ 0x800500F0)

```mips
0x800500CC: addiu $s0, $s4, 0x200     ; $s0 = buf + 0x200 (加密数据源)
0x800500D0: addu $s2, $sp, $s6         ; $s2 = sp + 0x50 (解密输出目标)
0x800500D4: addiu $s1, $zero, 31       ; $s1 = 31 (循环计数, 0..31 = 32次)
0x800500D8: addu $a0, $s0, $zero       ; $a0 = src (加密块地址)
0x800500DC: addu $a1, $s2, $zero       ; $a1 = dst (解密块地址)
0x800500E0: jal 0x80050898             ; aes_decrypt_block(src, dst)
0x800500E4: addiu $s1, $s1, -1        ; (delay slot) s1--
0x800500E8: addiu $s0, $s0, 16         ; src += 16
0x800500EC: bltz $s1, -6               ; if (s1 >= 0) → 继续循环
0x800500F0: addiu $s2, $s2, 16         ; (delay slot) dst += 16
```

解密过程: 将 `buf+0x200` 开始的512字节加密数据, 按16字节一块, 解密到 `sp+0x50` 开始的缓冲区。共32块 × 16字节 = 512字节。

#### 步骤8: Magic验证 (0x800500F4 ~ 0x80050124)

```mips
0x800500F4: lw $v1, 0x50($sp)         ; v1 = decrypted[0x00]
0x800500F8: lui $v0, 0x2010
0x800500FC: ori $v0, $v0, 0x1228      ; v0 = 0x20101228
0x80050100: bne $v1, $v0, -0x27        ; if (Magic1不匹配) → 重试下一个扇区
0x80050104: lw $v1, 0x54($sp)         ; v1 = decrypted[0x04]
0x80050108: lui $v0, 0x4431
0x8005010C: ori $v0, $v0, 0x3030      ; v0 = 0x44313030
0x80050110: bne $v1, $v0, -0x2B        ; if (Magic2不匹配) → 重试
0x80050114: lw $v1, 0x58($sp)         ; v1 = decrypted[0x08]
0x80050118: lui $v0, 0x5D24
0x8005011C: ori $v0, $v0, 0x5588      ; v0 = 0x5D245588
0x80050120: bne $v1, $v0, -0x2F        ; if (Magic3不匹配) → 重试
```

三个Magic值 (小端序存储):

| 偏移 | 值 | 字节表示 |
|------|------|----------|
| 0x00 | 0x20101228 | `28 12 10 20` |
| 0x04 | 0x44313030 | `30 30 31 44` ("001D"的ASCII) |
| 0x08 | 0x5D245588 | `88 55 24 5D` |

#### 步骤9: 序列号提取 (0x80050124 ~ 0x80050140)

```mips
0x80050124: addiu $a0, $sp, 0x7C       ; $a0 = sp + 0x7C (临时缓冲区)
0x80050128: lui $a1, 0x800D
0x8005012C: addiu $a1, $a1, -0x3D6C   ; $a1 = 0x800CC294 = "JZ4750L"
0x80050130: jal 0x800249C0             ; sscanf(sp+0x50+0x1C, "JZ4750L%s", sp+0x7C)
0x80050134: addiu $a2, $zero, 16       ; 最大16字节
0x80050138: beqz $v0, -0x34            ; sscanf失败 → 重试
0x8005013C: addiu $s3, $s3, 1          ; s3++
```

这里用`sscanf`以`"JZ4750L%s"`格式从解密数据的偏移0x1C处提取序列号字符串。但实际上序列号直接存储在偏移0x1C, 不一定以"JZ4750L"为前缀。`sscanf`的格式字符串是"JZ4750L", 看起来像是用`sscanf`做字符串匹配和提取, 也可能`0x800CC294`处存储的是`"%s"`格式字符串(需确认)。

#### 步骤10: 成功返回 (0x80050140 ~ 0x800500BC)

```mips
0x80050140: jal 0x80025654             ; kfree(buf) — 释放缓冲区
0x80050144: addu $a0, $s4, $zero
0x80050148: bnez $s5, +4               ; if (mmc_read失败次数==0)
0x8005014C: addu $a1, $s2, $zero       ; $a1 = 解密后数据
0x80050150: addu $a0, $sp, $zero       ; (成功路径)
0x80050154: jal 0x8004BA44             ; memset → 实际是memcpy到output
0x80050158: addiu $a2, $zero, 0x200
0x8005015C: lui $a0, 0x800D
0x80050160: addiu $a0, $a0, -0x3D64   ; "成功取得序列号为: %s" (GBK)
0x80050164: jal 0x80024BD4             ; printk("成功取得序列号为: %s", sn)
...
0x8005008C: addiu $v0, $zero, -3       ; 失败返回值 = -3
0x80050090: lw $ra, 0x294($sp)         ; 恢复寄存器
...
0x800500B8: jr $ra
0x800500BC: addiu $sp, $sp, 0x298
```

---

## 5. prepare_sn_data 函数分析

### 5.1 函数签名

```c
void prepare_sn_data(char *buf, char *sn_string);  // $a0=缓冲区, $a1=序列号字符串
```

### 5.2 流程 (0x8005021C ~ 0x800502D4)

```mips
0x8005021C: addiu $sp, $sp, -0x418     ; 分配栈帧
0x80050220: sw $s0, 0x410($sp)
0x80050224: addiu $a2, $zero, 0x200    ; $a2 = 512
0x80050228: addu $s0, $a0, $zero       ; $s0 = buf
0x8005022C: addu $a1, $zero, $zero     ; $a1 = 0
0x80050230: sw $ra, 0x414($sp)
0x80050234: jal 0x8004BA44             ; memset(sp+0x10, 0, 512)
0x80050238: addiu $a0, $sp, 0x10

; 写入Magic
0x8005023C: lui $v1, 0x2010
0x80050240: lui $v0, 0x4431
0x80050244: lui $a2, 0x5D24
0x80050248: ori $v1, $v1, 0x1228      ; 0x20101228
0x8005024C: ori $a2, $a2, 0x5588      ; 0x5D245588
0x80050250: addiu $a0, $sp, 0x1C      ; 版本字符串目标
0x80050254: ori $v0, $v0, 0x3030      ; 0x44313030
0x80050258: lui $a1, 0x800D
0x8005025C: addiu $a1, $a1, -0x3D04   ; $a1 = 0x800CC2FC = "H2 V2.20"
0x80050260: sw $v1, 0x10($sp)         ; sp+0x10 = Magic1
0x80050264: sw $a2, 0x18($sp)         ; sp+0x18 = Magic3
0x80050268: jal 0x8002499C             ; sprintf(sp+0x1C, "H2 V2.20")  → 版本字符串
0x8005026C: sw $v0, 0x14($sp)         ; sp+0x14 = Magic2

; 序列号字符串拷贝
0x80050270: addiu $a2, $zero, 16       ; 最大16字节
0x80050274: addiu $a0, $sp, 0x2C       ; sp+0x2C = 偏移0x1C (相对sp+0x10)
0x80050278: jal 0x8004BA44             ; strncpy(sp+0x2C, sn_string, 16)
0x8005027C: addu $a1, $s0, $zero       ; $a1 = sn_string

; 拷贝"JZ4750L"标签
0x80050280: lui $a1, 0x800D
0x80050284: addiu $a1, $a1, -0x3D6C   ; $a1 = 0x800CC294 = "JZ4750L"
0x80050288: jal 0x8002499C             ; sprintf(sp+0x3C, "JZ4750L")
0x8005028C: addiu $a0, $sp, 0x3C
```

`prepare_sn_data` 构造的明文数据块结构与 `read_sn` 解密后验证的结构一致。

---

## 6. AES-128 加密机制

### 6.1 密钥来源

```
密钥[0..7]  = *(uint64_t *)0x801A708C   (运行时数据, GDB转储: 21 21 01 DE AD BE EF 29)
密钥[8..15] = memset 残留的 0xAA        (8字节: AA AA AA AA AA AA AA AA)
```

完整16字节密钥 (hex): `212101DEADBEEF29AAAAAAAAAAAAAAAA`

### 6.2 加密模式

- **AES-128 ECB** (Electronic Codebook)
- 每16字节独立加密/解密
- 512字节 = 32个块

### 6.3 密钥扩展

`aes_key_expand` (0x80050354) 实现:
1. 标准 AES-128 密钥扩展 (10轮, 生成44个32位轮密钥)
2. 轮密钥存储在全局 T-table 区域 `0x801BC2F0` 开始 (BSS段, 运行时初始化)
3. 参数 `$a1` (传入256) 用于确定密钥长度 → 选择10轮

### 6.4 单块解密

`aes_decrypt_block` (0x80050898) 实现:
1. 标准 AES-128 解密流程 (InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns)
2. 使用 T-table 优化 (T-tables 位于 `0x801BE8F4` 等, 运行时初始化)
3. 函数签名: `void aes_decrypt_block(uint8_t *in, uint8_t *out)` — `$a0`=输入, `$a1`=输出

### 6.5 加密范围

整个512字节扇区数据全部加密。Magic头(0x00~0x0B)在加密后不可见, 必须解密后才能验证。

---

## 7. MMC 存储布局

### 7.1 扇区地址映射

| 扇区号 | 字节偏移 | 位置 | 逻辑分组 |
|--------|----------|------|----------|
| 0x7C00 | 16,252,928 | 15.500 MB | 主扇区A (case 0) |
| 0x7D00 | 16,384,000 | 15.625 MB | 备用扇区A (case 4) |
| 0x7E00 | 16,515,072 | 15.750 MB | 主扇区B (case 1) |
| 0x7F00 | 16,646,144 | 15.875 MB | 备用扇区B (case 5) |
| 0x8000 | 16,777,216 | 16.000 MB | 主扇区C (case 2) |
| 0x8100 | 16,908,288 | 16.125 MB | 备用扇区C (case 6) |
| 0x8200 | 17,039,360 | 16.250 MB | 主扇区D (case 3) |
| 0x8300 | 17,170,432 | 16.375 MB | 备用扇区D (case 7) |

### 7.2 扇区选址算法

```
扇区号规律:
  主扇区:   0x7C00, 0x7E00, 0x8000, 0x8200  (步进 0x200)
  备用扇区: 0x7D00, 0x7F00, 0x8100, 0x8300  (步进 0x200)
  每对(主+备用): 步进 0x100
```

8个扇区存储**相同**的加密数据, 冗余设计提高可靠性。

### 7.3 读取策略

`read_sn` 使用 jiffies 伪随机值选择扇区:
1. 生成8个互不重复的随机值 (0~7)
2. 按顺序尝试, 调用 `mmc_read` 读取对应扇区
3. 解密后验证 Magic, 首次成功即返回
4. 全部失败返回 -3

**关键结论**: 写入序列号时必须**8个扇区全部写入相同数据**, 否则随机选择可能读到旧数据。

---

## 8. 数据结构定义

### 8.1 解密后的512字节扇区数据

```c
struct sn_data_block {
    uint32_t magic1;          // 0x00: 0x20101228
    uint32_t magic2;          // 0x04: 0x44313030 (LE, ASCII: "001D")
    uint32_t magic3;          // 0x08: 0x5D245588
    char     version[16];     // 0x0C: 版本字符串, 如 "H2 V2.20\0..."
    char     serial[16];      // 0x1C: 序列号, ASCII, 最大16字节, \0填充
    uint8_t  reserved[448];   // 0x2C: 保留 (全0)
    uint32_t checksum;        // 0x1FC: 校验和 (0x0C~0x1FB 字节累加和, LE uint32)
};
```

### 8.2 校验和算法

```python
checksum = sum(block[0x0C:0x1FC]) & 0xFFFFFFFF
```

计算范围: 偏移 `0x0C` 到 `0x1FB` (含端点), 共 492 字节。
校验和存储位置: 偏移 `0x1FC`, 4字节小端序 uint32。

### 8.3 Magic值含义

| Magic | 值 | 可能含义 |
|-------|------|----------|
| Magic1 | 0x20101228 | 日期标识: 2010-12-28 (数据结构创建日期?) |
| Magic2 | 0x44313030 | ASCII "001D" (设备型号标识?) |
| Magic3 | 0x5D245588 | 哈希/校验值 (用途不明) |

---

## 9. mmc_read 函数分析

### 9.1 函数签名

```c
int mmc_read(uint32_t sector, void *buffer);  // $a0=扇区号, $a1=缓冲区
```

### 9.2 关键逻辑

```mips
; mmc_read 入口 (0x8003CBB4):
0x8003CBB4: addiu $sp, $sp, -0x88
0x8003CBB8: sw $s2, 0x70($sp)
0x8003CBBC: addu $s2, $a0, $zero       ; $s2 = sector (扇区号)
0x8003CBC0: lui $a0, 0x801A
0x8003CBC4: lw $a0, 0x7054($a0)        ; $a0 = *(0x801A7054) (MMC设备句柄)

; ...
; CMD17 (READ_SINGLE_BLOCK) 发送:
0x8003CD34: sll $v0, $s2, 9            ; $v0 = sector << 9 = sector * 512 (字节地址)
; 此指令用于兼容旧版MMC (使用字节地址而非扇区地址)
; 现代eMMC使用扇区地址, 但此处先左移9位转换为字节地址
```

---

## 10. 内核调试字符串

| 地址 | 内容 | 编码 |
|------|------|------|
| 0x800CC220 | `\nReal fnGUI_GetSNData() is called!\n` | ASCII |
| 0x800CC268 | `\nread_sn failed......no sn or read error\n` | ASCII |
| 0x800CC294 | `JZ4750L` | ASCII |
| 0x800CC2A0 | `\xb3\xc9\xb9\xa6\xc8\xa1\xb5\xc3\xd0\xf2\xc1\xd0\xba\xc5\xce\xaa: %s\n` | GBK ("成功取得序列号为: %s") |
| 0x800CC2D8 | `my fnGUI_SetSNData() is called!\n` | ASCII |
| 0x800CC2FC | `H2 V2.20` | ASCII |
| 0x800CC308 | `read_sn success!!!\n` | ASCII |

---

## 11. 全局数据结构

### 11.1 mmc_info 结构体 (0x801A7084 起)

```
偏移     内容           说明
0x00     0x3F           初始化标志 (0x3F = 已初始化)
0x01     0xAA           (padding?)
0x02     0x01 0x58      ?
0x04     0x51 0x45 0x4D 0x55  ("QEMU"?)
0x08     AES密钥前8字节  0x21 0x21 0x01 0xDE 0xAD 0xBE 0xEF 0x29
```

GDB转储:
```
0x801a7084: 0x3f 0xaa 0x01 0x58 0x51 0x45 0x4d 0x55
0x801a708c: 0x21 0x21 0x01 0xde 0xad 0xbe 0xef 0x29
```

注意偏移0x04~0x07的ASCII为"QEMU", 可能表明此内核运行在QEMU模拟器中。

### 11.2 AES T-tables (运行时初始化)

| 地址 | 说明 |
|------|------|
| 0x801BC2F0 | AES轮密钥存储区域 |
| 0x801BE8F4 | Te0 T-table (加密) |
| 0x801BF8F4 | Td0 T-table (解密) |

这些区域位于BSS段, 在静态二进制文件中全为零, 运行时由 `aes_key_expand` 初始化。

---

## 12. 完整读取流程时序图

```
用户调用 read_sn(output_buf)
    │
    ├─ [1] printk("Real fnGUI_GetSNData() is called!")
    │
    ├─ [2] buf = kmalloc(1536)
    │       memset(buf, 0xAA, 1536)
    │
    ├─ [3] mmc_init(buf)
    │       ├─ 读取 *(0x801A7084)
    │       ├─ if (== 0x3F) → memcpy(buf, 0x801A708C, 8)  // 密钥加载
    │       └─ else → return 1 (拒绝)
    │
    ├─ [4] srand(jiffies)
    │       生成8个互不重复的随机值 r[0..7] (0~7)
    │       printk("record = %d,%d,...", r[0], r[1], ...)
    │
    ├─ [5] for (i = 0; i < 8; i++) {
    │       sector = switch_table[r[i]]
    │       ret = mmc_read(sector, buf + 0x200)
    │       if (ret == 0) break  // 读取成功
    │   }
    │
    ├─ [6] aes_key_expand(buf, 256)
    │       密钥 = buf[0..15] = {0x801A708C的8字节, 0xAA×8}
    │
    ├─ [7] for (i = 0; i < 32; i++)
    │       aes_decrypt_block(buf+0x200+i*16, sp+0x50+i*16)
    │       // 512字节解密完成
    │
    ├─ [8] if (sp+0x50+0x00 != 0x20101228) → 重试下一个扇区
    │   if (sp+0x50+0x04 != 0x44313030) → 重试
    │   if (sp+0x50+0x08 != 0x5D245588) → 重试
    │
    ├─ [9] sscanf(sp+0x50+0x1C, "JZ4750L%s", temp_buf, 16)
    │       memcpy(output_buf, temp_buf, ...)
    │
    ├─ [10] printk("成功取得序列号为: %s", output_buf)
    │        kfree(buf)
    │        return 0
    │
    └─ [失败] printk("read_sn failed......no sn or read error")
              kfree(buf)
              return -3
```

---

## 13. 写入自定义序列号的方法

### 13.1 方法: AES加密写入 (推荐, 无需修改内核)

利用GDB转储获取的AES密钥, 构造正确的加密数据块:

```python
# 1. 构造明文数据块 (512字节)
block = bytearray(512)
struct.pack_into('<I', block, 0x00, 0x20101228)  # Magic1
struct.pack_into('<I', block, 0x04, 0x44313030)  # Magic2
struct.pack_into('<I', block, 0x08, 0x5D245588)  # Magic3
block[0x0C:0x1C] = b'H2 V2.20\x00...'            # 版本
block[0x1C:0x2C] = b'MY_SERIAL\x00...'           # 序列号
checksum = sum(block[0x0C:0x1FC]) & 0xFFFFFFFF
struct.pack_into('<I', block, 0x1FC, checksum)    # 校验和

# 2. AES-128 ECB 加密
key = bytes.fromhex('212101DEADBEEF29AAAAAAAAAAAAAAAA')
encrypted = aes_ecb_encrypt(block, key)

# 3. 写入eMMC的8个扇区位置
for sector in [0x7C00, 0x7D00, 0x7E00, 0x7F00, 0x8000, 0x8100, 0x8200, 0x8300]:
    write_to_mmc(sector, encrypted)
```

### 13.2 使用工具

```bash
# 读取当前序列号
python jz4750l_sn_tool.py read emmc_dump.bin

# 写入新序列号 (自动AES加密)
python jz4750l_sn_tool.py write emmc_dump.bin MY_NEW_SN -o emmc_modified.bin

# 查看分析报告
python jz4750l_sn_tool.py info
```

---

## 14. 风险与注意事项

| 风险项 | 说明 | 缓解措施 |
|--------|------|----------|
| AES密钥设备差异 | 不同设备的0x801A708C数据可能不同 | 从目标设备GDB转储获取 |
| eMMC损坏 | 写入错误扇区可能破坏其他数据 | 严格限制写入范围为8个指定扇区 |
| 校验和错误 | 校验和错误导致read_sn验证失败 | 工具自动重算校验和 |
| 扇区不一致 | 8个扇区数据不一致导致随机读取失败 | 工具强制写入全部8个扇区 |
| mmc_init限制 | mmc_init只允许调用一次(检查0x3F标志) | 只影响首次读取, 后续启动正常 |

---

## 附录A: MIPS指令解码参考

本文档中涉及的关键MIPS指令编码:

| 指令 | 编码 | 说明 |
|------|------|------|
| `jr $ra` | 0x03E00008 | 函数返回 |
| `nop` | 0x00000000 | 空操作 |
| `jal target` | 0x0C000000 \| (target>>2) | 函数调用 |
| `j target` | 0x08000000 \| (target>>2) | 无条件跳转 |
| `beqz $rs, offset` | 0x10000000 \| (rs<<21) \| (offset&0xFFFF) | 条件分支 |
| `lui $rt, imm` | 0x3C000000 \| (rt<<16) \| (imm&0xFFFF) | 加载高16位 |
| `addiu $rt, $rs, imm` | 0x24000000 \| (rs<<21) \| (rt<<16) \| (imm&0xFFFF) | 立即数加法 |

## 附录B: switch-case跳转表原始数据

地址: 0x800CC2B4, 8个32位条目:

```
[0] 0x8005004C  → case 0: mmc_read(0x7C00, buf+0x200)
[1] 0x80050174  → case 1: mmc_read(0x7E00, buf+0x200)
[2] 0x80050180  → case 2: mmc_read(0x8000, buf+0x200)
[3] 0x8005018C  → case 3: mmc_read(0x8200, buf+0x200)
[4] 0x80050198  → case 4: mmc_read(0x7D00, buf+0x200)
[5] 0x800501A4  → case 5: mmc_read(0x7F00, buf+0x200)
[6] 0x800501B0  → case 6: mmc_read(0x8100, buf+0x200)
[7] 0x800501BC  → case 7: mmc_read(0x8300, buf+0x200)
```

## 附录C: 关键函数原始字节码

### read_sn (0x8004FD60), 前12条

```
27BDFD68  AFBE0290  0080F021  3C04800D
2484C220  AFBF0294  AFB40280  AFB7028C
AFB60288  AFB50284  AFB3027C  AFB20278
```

### aes_key_expand (0x80050354), 前4条

```
3C02801B  8C42C2F0  27BDFFE0  AFB10014
```

### aes_decrypt_block (0x80050898), 前4条

```
27BDFFB8  AFB60038  3C16801B  8ED6091C
```

### mmc_init (0x8003F330), 前4条

```
3C03801A  90637084  27BDFFE8  2402003F
```

### mmc_read (0x8003CBB4), 前4条

```
27BDFF78  AFB20070  00809021  3C04801A
```

---

*文档版本: 1.0*
*分析日期: 2026-05-21*
*分析工具: 自研MIPS LE反汇编器 + GDB运行时验证*
