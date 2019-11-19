# ebpf

clang -v -I./cbpf -O2 -target bpf -c cbpf/xdp_mon.c -o ./xdp_mon.elf
go run .
