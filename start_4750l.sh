#!/bin/bash -ex
prefix=
monitor=vc

if (($# != 0)); then
    # Specify -S to start debugging
    prefix="gdb -ex run --args"
    monitor=stdio
fi

(cd ~/mips/qemu/bootrom; zig build --release=small)

system_image_base=mmc0/image.qcow2
# system_image_base=mmc0/v2.20.qcow2
# system_image_base=mmc0/v2.20_calibrated.qcow2
# system_image_base=mmc0/v3.20_stage1.qcow2
# system_image_base=mmc0/v3.20_calibrated.qcow2
# system_image_base=mmc0/v3.21_calibrated.qcow2
system_image=mmc0/system_overlay.qcow2

# mmc_image_base=mmc1/mmc.qcow2
mmc_image_base=mmc1/mmc_empty.qcow2
# mmc_image_base=mmc1/v3.20_recovery.qcow2
# mmc_image_base=mmc1/v3.20_update.qcow2
mmc_image=mmc1/mmc_overlay.qcow2

(cd mmc0; qemu-img convert -f raw -O qcow2 image.bin image.qcow2)

rm -f $system_image
qemu-img create -f qcow2 -F qcow2 -b $(basename $system_image_base) $system_image
rm -f $mmc_image
qemu-img create -f qcow2 -F qcow2 -b $(basename $mmc_image_base) $mmc_image

eval $prefix ./qemu-system-mipsel \
    -M bbk_iboxh2 \
    -gdb tcp::8842 \
    -d guest_errors,unimp \
    -bios jz4750l.bin \
    -parallel null \
    -serial tcp:localhost:7646 \
    -serial tcp:localhost:7646 \
    -serial tcp:localhost:7646 \
    -serial tcp:localhost:7646 \
    -monitor $monitor \
    -global ingenic-rtc.hspr=0x12345678 \
    -global gpio-matrix-keypad.map-file=keymap.yaml \
    -spice port=5912,disable-ticketing=on \
    -display none \
    -audio spice \
    \
    -blockdev driver=file,node-name=mmc0_qcow2,filename=$system_image \
    -blockdev qcow2,node-name=mmc0,file=mmc0_qcow2 \
    -device emmc,drive=mmc0,bus=sd-bus-msc0 \
    \
    -blockdev driver=file,node-name=mmc1_qcow2,filename=$mmc_image \
    -blockdev qcow2,node-name=mmc1,file=mmc1_qcow2 \
    -device sd-card,spec_version=3,drive=mmc1,bus=sd-bus-msc1 \
    \
    -msg timestamp=on \
    --trace "mmio_*" \
    --trace "ingenic_msc_cmd" --trace "sdbus_command" --trace "sdcard_*_command" --trace "sdcard_response" \
    \
    "$@"

exit

# log guest_errors,unimp,trace:ingenic_dmac_*,trace:ingenic_msc_*,trace:sdbus_*,trace:sdcard_*

false \
    -serial none \
    -serial none \
    -serial none \
    -serial tcp:localhost:7645 \
    \
    -spice port=5910,disable-ticketing=on \
    -display none \
    -audio spice \
    \
    -display gtk \
    -audio pipewire \
    \
    -d guest_errors,unimp,in_asm \
    -accel tcg,one-insn-per-tb=on \
    \
    -D logs/debug.log \
    --trace "ingenic_msc_cmd" --trace "sdbus_command" --trace "sdcard_*_command" --trace "sdcard_response" \
    --trace "ingenic_msc_*" --trace "sdbus_*" --trace "sdcard_*" \
    --trace "ingenic_dmac_*" \
    --trace "gpio_matrix_keypad_event" \
    --trace "gpio_matrix_keypad_*" \
    --trace "ingenic_gpio_*" \
    --trace "ingenic_lcd_*" \
    \
    -device sd-card,spec_version=3,drive=mmc0,bus=sd-bus-msc0 \
    -device emmc,drive=mmc0,bus=sd-bus-msc0 \
    \
    -bios bootrom/build/bootrom.bin \
    -blockdev driver=file,node-name=nand_qcow2,filename=nand_overlay.qcow2 \
    -blockdev qcow2,node-name=nand,file=nand_qcow2 \
    -global ingenic-emc-nand.drive=nand \
    -blockdev driver=file,node-name=mmc_qcow2,filename=mmc_overlay.qcow2 \
    -blockdev qcow2,node-name=mmc,file=mmc_qcow2 \
    -device sd-card,spec_version=3,drive=mmc \
    -global gpio-matrix-keypad.map-file=keymap_noah-np1380.yaml \
    --trace "usb_ohci*" \
    --trace "gpio_matrix_keypad_event" \
    --trace "ingenic_aic_*" \
    --trace "ingenic_msc_*" --trace "sdbus_*" --trace "sdcard_*" \
    --trace "ingenic_dmac_*" \
    --trace "ingenic_dmac_transfer" --trace "ingenic_dmac_start*" \
    --trace "ingenic_adc_*" \

exit

false \
    --trace "ingenic_dmac_*" \
    -blockdev vvfat,node-name=mmc,dir=mmc/mmc,fat-type=32,rw=true,size=4G \
    -display vnc=:10 \
    -display none \
    -spice port=5910,disable-ticketing=on \
    --trace "resettable_phase_*" \
    --trace "ingenic_cpm_*" \
    --trace "ingenic_uart_*" \
    --trace "ingenic_nand_cmd" --trace "ingenic_emc_read" --trace "ingenic_emc_write" \
    --trace "ingenic_msc_cmd" --trace "sdbus_command" \
    --trace "ingenic_msc_*" --trace "sdbus_*" --trace "sdcard_*" \
    --trace "ingenic_msc_*" \
    --trace "ingenic_dmac_*" \
    --trace "ingenic_*" \
    --trace "ingenic_cgu_cclk_freq" \
    --trace "ingenic_adc_ts" --trace "ingenic_adc_irq" \
    --trace "ingenic_bch_write" --trace "ingenic_bch_read" \
    --trace "ingenic_dmac_*" \
    --trace "ingenic_nand_cmd" \
    --trace "ingenic_nand_*" \
    --trace "ingenic_udc_*" \
    --trace "ingenic_adc_*" \
    --trace "ingenic_intc_enable" \
    --trace "ingenic_lcd_*" \
    --trace "ingenic_aic_*" \
    --trace "ingenic_gpio_config" \
    --trace "ingenic_gpio_out" \
    --trace "ingenic_gpio_*" \
    --trace "gpio_matrix_keypad_*" \
    --trace "ingenic_i2c_*" \
    --trace "ingenic_*" \
    --trace "i2c_*" \
    --trace "stmpe2403_reg_*" --trace "stmpe2403_gpio" --trace "stmpe2403_gpio_in" --trace "stmpe2403_irq" \
    --trace "stmpe2403_*" \
    -serial none \
    -serial vc \
    -monitor stdio \
    -accel tcg,one-insn-per-tb=on \
    -blockdev driver=file,node-name=nand1_overlay,filename=nand_overlay.qcow2 \
    -blockdev driver=file,node-name=nand1_base,read-only=on,filename=nand_dump_base_oob256.qcow2 \
    -blockdev qcow2,node-name=nand1,read-only=on,file.driver=file,file.filename=nand_dump_oob256.qcow2 \
    -d guest_errors,unimp,in_asm,cpu,exec \
    -s -S \
