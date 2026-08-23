CLANG ?= clang
ARCH := $(shell uname -m)

# -target bpf does not search the multiarch include directory, and that is where
# asm/types.h lives on Ubuntu. Without it the build fails inside linux/types.h.
CFLAGS := -O2 -g -Wall -Werror -target bpf -I/usr/include/$(ARCH)-linux-gnu

PROGS := xdp_pass.o xdp_drop.o xdp_portdrop.o xdp_reflect.o xdp_bucket_bench.o \
         xdp_fib_bench.o
DATA := ../data/udp64.bin

.PHONY: all clean
all: $(PROGS) $(DATA)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(DATA): mkpkt.py
	@mkdir -p $(dir $@)
	python3 mkpkt.py $@ 64

clean:
	rm -f $(PROGS) $(DATA)
