# packetfilter

An [eBPF](https://ebpf.io/) based `packetfilter` for tracking incoming requests and filtering based on a set of rules.

## Dependencies

- llvm >= 10
- llc >= 10
- clang >= 10
- opt >= 10
- dwarves >= 1.19  

This projects requires a kernel compiled with BTF file format support (CONFIG_DEBUG_INFO_BTF=y) in order
to generate the proper included headers for kernel space.

Currently Azure VM's do not support BTF so to setup one would need to download a new kernel image:
```
# OPTION 1:
> apt-get source linux-image-unsigned-$(uname -r)

# OPTION 2: 
> wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-azure-5.4/5.4.0-1063.66~18.04.1/linux-azure-5.4_5.4.0.orig.tar.gz // or some other version.
```
Than compile the kernel using the following instructions:
```
1. cd linux-5.4
2. Copy you're boot config: `sudo cp /boot/config-.. .config`
3. Edit the .config and set `CONFIG_DEBUG_INFO_BTF=y`.
4. Edit the Makefile with `EXTRAVERSION` (=-btf or whatever name you want to identify this kernel).
```

Building the kernel:
```
1. make oldconfig
2. Edit the Makefile and comment out (i.e. `# CONFIG_SYSTEM_TRUSTED_KEYS =..`).
3. make -j 4
4. sudo make INSTALL_MOD_STRIP=1 modules_install
5. sudo make install
6. Reboot machine (from the portal) and cd into the machine again.
7. Check the new version for the kernel using `uname -r`.
8. Copy the contents of the newly built `linux-5.4/include` folder from the kernel folder to youre `/usr/include`.
```

## Setting up XDP
Make sure to disable LRO (Large recieve offloading) as XDP does not support jumbo frames or LRO:
```
sudo ethtool --offload eth0 lro off
```

## Running the packetfilter:
Make sure to compile the BPF program using the `Makefile`.

To exampne the BPF file generated use: 
```
llvm-objdump-12 -S ./bytecode.x86.o
```

Than run the target binary as root: 
```
sudo  ./target/debug/packetfilter run --config-file=/path/to/config.json
```

By default it will load the binary under `/bpf`.