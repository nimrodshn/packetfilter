# packetfilter

An [eBPF](https://ebpf.io/) based `packetfilter` for tracking incoming requests and filtering based on a set of rules.

## Dependencies

- llvm >= 10
- llc >= 10
- clang >= 10

## Setting up XDP
Make sure to disable LRO (Large recieve offloading) as XDP does not support jumbo frames or LRO:
```
sudo ethtool --offload eth0 lro off
```

## Running the packetfilter:
Make sure to compile the BPF program using the Makefile.
Than run the target binary as root: `sudo  ./target/debug/packetfilter run`.
By default it will load the binary under `/bpf`.