FROM alpine:3.18 AS builder
RUN apk update && apk add --no-cache clang15 g++ make bpftool libbpf-dev libelf-static elfutils-dev zlib-dev zlib-static zstd-static linux-headers musl-dev

WORKDIR /src

COPY . .

RUN \
    clang-15 -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c src/monitor.bpf.c -o monitor.bpf.o && \
    \
    bpftool gen skeleton monitor.bpf.o > monitor.skel.h && \
    \
    g++ -std=c++20 src/main.cpp src/app_context.cpp src/prometheus-exporter.cpp -I. \
        -static \
        -l:libbpf.a -l:libelf.a -l:libz.a -l:libzstd.a \
        -o ebpf-monitor

FROM alpine:3.18

WORKDIR /app

COPY --from=builder /src/ebpf-monitor .

CMD ["sleep", "infinity"]