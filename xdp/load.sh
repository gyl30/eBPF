clang -O2 -target bpf -c xdp_redirect.c -o xdp_redirect.o
ip link set dev eno1 xdp obj xdp_redirect.o sec xdp_prog
