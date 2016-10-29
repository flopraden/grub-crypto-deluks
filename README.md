# Introduction

[![DeLUKS: Deniable Linux Unified Key Setup](https://raw.githubusercontent.com/kriswebdev/grub-crypto-deluks/gh-pages/assets/deluks_logo.png)](https://github.com/kriswebdev/grub-crypto-deluks)

This repository presents an implementation of a plausibly Deniable LUKS header in **`grub`**.

DeLUKS provides most benefits of LUKS and of plausibly [deniable encryption](https://en.wikipedia.org/wiki/Deniable_encryption). The DeUKS header is specified to be indistinguishible from random data. This is like Truecrypt header, but with **GRUB support**, **multiple keyslots** and *(to be implemented)* an **evolutive protection against brute-forcing**.

Note there is a parrallel project to implement DeLUKS in `cryptsetup`: [`cryptsetup-deluks`](https://github.com/kriswebdev/cryptsetup-deluks). This must be installed in the booted OS.

See the [`cryptsetup-deluks` Wiki: System encryption](https://github.com/kriswebdev/cryptsetup-deluks/wiki/System-encryption) for instructions.

Beta available!
===

`grub-crypto-deluks` is leaving the Alpha stage and is now on Beta stage.

Instructions are written for and tested on **Ubuntu 16** (Xenial Xerus).

Install
===

    sudo apt-get install git build-essential bison gettext binutils flex libdevmapper-dev ttf-unifont ttf-dejavu libfreetype6-dev qemu-system-i386 xorriso python autoconf automake liblzma5 liblzma-dev libfuse2 libfuse-dev
    git clone --depth=1 https://github.com/kriswebdev/grub-crypto-deluks.git
    cd grub-crypto-deluks
    make clean
    ./linguas.sh
    ./autogen.sh
    ./configure --prefix=/usr --exec_prefix=/usr --sysconfdir=/etc 
    make
    sudo make install

Install GRUB on the drive root where it is already present, DON'T overwrite the DeLUKS encrypted space!

	sudo lsblk -o NAME,FSTYPE,SIZE,LABEL,MOUNTPOINT
	sudo grub-install /dev/sdX

Optional for international keyboards (eg. *fr*ench):

	sudo grub-kbdcomp -o /boot/grub/keyboard.gkb fr

Edit `/etc/default/grub` with root rights to have:

    # International keyboards:
    #GRUB_HIDDEN_TIMEOUT=0
    GRUB_TERMINAL_INPUT="at_keyboard"
    GRUB_ENABLE_CRYPTODISK=y
    GRUB_PRELOAD_MODULES="luks cryptodisk keylayouts"

Edit `/etc/grub.d/40_custom` with root rights to have:

    #!/bin/sh
    exec tail -n +3 $0

    # International keyboards:
    insmod keylayouts
    keymap /boot/grub/keyboard.gkb


Finally:

    sudo update-grub

Reboot

Run
===

At GRUB menu, press `c` to get into GRUB shell.

> If you don't see GRUB menu because you didn't comment `GRUB_HIDDEN_TIMEOUT`, press and hold `⇧` (SHIFT) during boot (english keyboard only).

At GRUB shell: 

    cryptomount -x /
    # Type your password
    # If needed: ls
    set root=(crypto0,msdos2)
    configfile /boot/grub/grub.cfg

Boot process will be even quicker in future versions.

The real OS now boots.

DeLUKS Features, Specifications...
===

Check [`cryptsetup-deluks`](https://github.com/kriswebdev/cryptsetup-deluks) README.