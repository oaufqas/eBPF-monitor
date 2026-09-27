cmake_minimum_required(VERSION 3.20)
project(ebpf-monitor C CXX)

set(CMAKE_CXX_STANDARD 20)

find_program(CLANG_EXT executable NAMES clang REQUIRED)
find_program(BPFTOOL_EXT executable NAMES bpftool REQUIRED)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/monitor.bpf.c)
set(CPP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/monitor.bpf.o)
set(BPF_SKEL ${CMAKE_CURRENT_BINARY_DIR}/monitor.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_EXT} -g -O2 -target bpf -D__TARGET_ARCH_x86 
            -I${CMAKE_CURRENT_SOURCE_DIR} -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h
    COMMENT "Compilation eBPF kernel code..."
)

add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND ${BPFTOOL_EXT} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generation eBPF skeleton for C++..."
)

add_custom_target(bpf_target DEPENDS ${BPF_SKEL})

add_executable(ebpf-monitor ${CPP_SRC})
add_dependencies(ebpf-monitor bpf_target)

target_link_libraries(ebpf-monitor PRIVATE bpf elf)
target_include_directories(ebpf-monitor PRIVATE ${CMAKE_CURRENT_BINARY_DIR})