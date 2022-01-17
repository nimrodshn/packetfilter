# packetfilter

An [eBPF](https://ebpf.io/) based `packetfilter` for tracking incoming requests and filtering based on a set of rules. 

## Dependencies
- llvm >= 10
- clang >= 10
---
1. Retrieve the archive signature for `llvm-10`:
```
wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
```

2. Add the PPA where to install from:
```
add-apt-repository 'deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-10  main'
```
3. Update packages: `sudo apt update`.
4. Install the dependencies: 
```
sudo apt-get install llvm-10     \
                     lldb-10     \
                     llvm-10-dev \
                     libllvm10   \
                     llvm-10-runtime
```

## Important note
The BPF program under `/bpf` is intentionally targeting the Azure VM running `Ubuntu 18.04` and the kernel version that comes with it - version `5.4.0-1064-azure` (as opposed to the CO-RE paradigm) as it is intended to run on such a machine.

## Setting up XDP
Make sure to disable LRO (Large receive offloading) as XDP does not support jumbo frames or LRO:
```
sudo ethtool --offload eth0 lro off
```

## Running the packetfilter
An example `config-file` is provided under `/examples`.
```
sudo ./target/debug/packetfilter run --config-file=/path/to/config.json
```
