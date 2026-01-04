cmake_minimum_required(VERSION 3.16)
project(ransom_bpf C)

# --- Project Metadata ---
set(PROJECT_VERSION "0.9.0")
set(CMAKE_C_STANDARD 11)

# --- Compilation Flags (Safety & Performance) ---
# -Wall -Wextra: Enable comprehensive warning levels
# -O2: Optimize for performance without sacrificing debuggability
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -Wall -Wextra")

# --- Dependencies ---
# Libbpf and Elf are critical for eBPF operations
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)

# --- eBPF Kernel Component (hello_kern.c) ---
# This section compiles the BPF program into an object file (.o) and
# generates the userspace skeleton (.skel.h) for easy interaction.

# 1. Compile Kernel Code to BPF Object
execute_process(
        COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hello_kern.c -o ${CMAKE_CURRENT_BINARY_DIR}/hello_kern.o
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE CLANG_RESULT
)

if (NOT CLANG_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to compile eBPF kernel program (hello_kern.c)")
endif()

# 2. Generate Skeleton Header (hello_kern.skel.h)
# This header allows the userspace agent to load and attach the BPF program easily.
execute_process(
        COMMAND bpftool gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/hello_kern.o
        OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/hello_kern.skel.h
        RESULT_VARIABLE SKELETON_RESULT
)

if (NOT SKELETON_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to generate BPF skeleton header")
endif()

# Include current directory to find headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

# --- Userspace Agent (Main Executable) ---
# The primary executable that loads the BPF program and runs the logic.
add_executable(ransom_bpf
        main.c
        logger.c
        state_manager.c
        detector.c
        config.c
        whitelist.c
        cli.c
        # Headers are included here for IDE indexing support
        common.h
        logger.h
        state_manager.h
        detector.h
        config.h
        whitelist.h
        cli.h
        uthash.h
)

# Link against required libraries
target_link_libraries(ransom_bpf ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} z)

# --- Installation & Deployment Rules ---
# These rules define where files go when running 'sudo make install'

# 1. Install Binary -> /usr/local/bin/ransom_bpf
install(TARGETS ransom_bpf DESTINATION bin)

# 2. Install Configuration -> /etc/ransom-bpf/ransom.conf
install(FILES ransom.conf DESTINATION /etc/ransom-bpf)

# 3. Install Systemd Service -> /etc/systemd/system/ransom-bpf.service
install(FILES ransom-bpf.service DESTINATION /etc/systemd/system)

# 4. Install Helper Scripts (Simulation Tools) -> /usr/local/share/ransom-bpf/tools
install(FILES setup_victim.sh ransom_simulator.py
        DESTINATION /usr/local/share/ransom-bpf/tools
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

# --- Output Summary ---
message(STATUS "---------------------------------------------------")
message(STATUS " RansomBPF v${PROJECT_VERSION} Configuration Complete")
message(STATUS "---------------------------------------------------")
message(STATUS " Target Arch    : x86_64")
message(STATUS " Compiler       : ${CMAKE_C_COMPILER}")
message(STATUS " Install Prefix : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "---------------------------------------------------")