cmake_minimum_required(VERSION 3.16)

# Define the project name
project(hello_ebpf C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- 1. Find Dependencies ---

find_package(PkgConfig REQUIRED)
pkg_search_module(LIBBPF REQUIRED libbpf)
pkg_search_module(LIBELF REQUIRED libelf)
find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)


# --- 2. Define eBPF Kernel Program Build ---

set(KERNEL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/hello_kern.c)
set(KERNEL_OBJ ${CMAKE_CURRENT_BINARY_DIR}/hello_kern.o)
set(SKELETON_HEADER ${CMAKE_CURRENT_BINARY_DIR}/hello_kern.skel.h)

# Step 2a: Custom command to compile eBPF code
add_custom_command(
        OUTPUT ${KERNEL_OBJ}
        COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -c ${KERNEL_SRC} -o ${KERNEL_OBJ}
        DEPENDS ${KERNEL_SRC}
        COMMENT "Compiling eBPF kernel code: ${KERNEL_SRC}"
)

# Step 2b: Custom command to generate skeleton header
add_custom_command(
        OUTPUT ${SKELETON_HEADER}
        COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${KERNEL_OBJ} > ${SKELETON_HEADER}
        DEPENDS ${KERNEL_OBJ}
        COMMENT "Generating eBPF skeleton: ${SKELETON_HEADER}"
)

# Step 2c: Custom target to manage eBPF build
add_custom_target(
        ebpf_build
        DEPENDS ${SKELETON_HEADER}
)


# --- 2.5 (IDE FIX) Tell CLion about the kernel source ---

# We create a "dummy" library target.
# This target is NOT used for the actual build.
# It exists ONLY to help the CLion editor index our kernel file
# and understand its include paths (like vmlinux.h).
add_library(kern_ide_helper OBJECT
        ${KERNEL_SRC}
)

# Now, tell this dummy target where to find its headers.
target_include_directories(kern_ide_helper
        PRIVATE
        # 1. The project directory (for vmlinux.h)
        ${CMAKE_CURRENT_SOURCE_DIR}
        # 2. The generated build directory (for skeleton, if needed)
        ${CMAKE_CURRENT_BINARY_DIR}
)

# --- 3. Define User-Space C Agent Build ---

# hello_user.c yerine yeni dosyaları ekliyoruz
set(USER_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/state_manager.c
        ${CMAKE_CURRENT_SOURCE_DIR}/detector.c
        # logger.h header olduğu için kaynak dosyaya eklemeye gerek yok ama IDE için iyi olur
)


# Add the user-space executable target
add_executable(hello_ebpf ${USER_SRC})

# Ensure user-space builds AFTER skeleton is generated
add_dependencies(hello_ebpf ebpf_build)

# Add include directories for the user-space target
target_include_directories(hello_ebpf
        PRIVATE
        # For skeleton header
        ${CMAKE_CURRENT_BINARY_DIR}
        # For vmlinux.h (also needed by user-space sometimes)
        ${CMAKE_CURRENT_SOURCE_DIR}
        # For libbpf and libelf
        ${LIBBPF_INCLUDE_DIRS}
        ${LIBELF_INCLUDE_DIRS}
)

# Link against required libraries
target_link_libraries(hello_ebpf
        PRIVATE
        ${LIBBPF_LIBRARIES}
        ${LIBELF_LIBRARIES}
)

# --- 4. (Optional) Install) ---
install(TARGETS hello_ebpf DESTINATION bin)