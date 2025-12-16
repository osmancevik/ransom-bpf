cmake_minimum_required(VERSION 3.16)

# Define the project name
project(ransom_bpf C)

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

# BU KISIMLARI YORUM SATIRINA ALIN:
# add_library(kern_ide_helper OBJECT
#        ${KERNEL_SRC}
# )

# Now, tell this dummy target where to find its headers.
# target_include_directories(kern_ide_helper
#        PRIVATE
#        # 1. The project directory (for vmlinux.h)
#        ${CMAKE_CURRENT_SOURCE_DIR}
#        # 2. The generated build directory (for skeleton, if needed)
#        ${CMAKE_CURRENT_BINARY_DIR}
# )

# --- 3. Define User-Space C Agent Build ---

# hello_user.c yerine yeni dosyaları ekliyoruz
set(USER_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/state_manager.c
        ${CMAKE_CURRENT_SOURCE_DIR}/detector.c
        ${CMAKE_CURRENT_SOURCE_DIR}/config.c
        ${CMAKE_CURRENT_SOURCE_DIR}/logger.c
        ${CMAKE_CURRENT_SOURCE_DIR}/whitelist.c
        ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
        # logger.h header olduğu için kaynak dosyaya eklemeye gerek yok ama IDE için iyi olur
)


# Add the user-space executable target
add_executable(ransom_bpf ${USER_SRC})

# Ensure user-space builds AFTER skeleton is generated
add_dependencies(ransom_bpf ebpf_build)

# Add include directories for the user-space target
target_include_directories(ransom_bpf
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
target_link_libraries(ransom_bpf
        PRIVATE
        ${LIBBPF_LIBRARIES}
        ${LIBELF_LIBRARIES}
)

# --- 4. (Optional) Install) ---
install(TARGETS ransom_bpf DESTINATION bin)

# --- 5. Unit Tests (Birim Testleri) ---

# Test calistirilabilir dosyasi
add_executable(run_tests
        tests/test_runner.c
        detector.c
        state_manager.c
        # Not: main.c ve logger.c bilerek eklenmedi. Mocklaniyor.
)

# Testlerin ihtiyac duydugu header yollari
target_include_directories(run_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# CTest entegrasyonu (Opsiyonel: make test komutu icin)
enable_testing()
add_test(NAME AllTests COMMAND run_tests)

# --- 6. Config Dosyasını Otomatik Kopyala (Gelişmiş) ---
# Derleme (Make) her yapıldığında, eğer kaynak dosya değişmişse build klasörüne kopyalar.
add_custom_command(
        TARGET ransom_bpf POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/ransom.conf
        ${CMAKE_CURRENT_BINARY_DIR}/ransom.conf
        COMMENT "Guncel ransom.conf dosyasini build klasorune kopyaliyor..."
)

# --- 7. Sistem Kurulumu (Systemd Entegrasyonu) ---

# 1. Binary dosyasını standart yola kopyala (/usr/local/bin)
install(TARGETS ransom_bpf DESTINATION bin)

# 2. Konfigürasyon dosyasını /etc/ransom-bpf/ altına kopyala
install(FILES ransom.conf DESTINATION /etc/ransom-bpf COMPONENT config)

# 3. Systemd servis dosyasını kopyala
# Not: Systemd yolu dağıtıma göre değişebilir ama genelde burasıdır.
install(FILES ransom-bpf.service DESTINATION /etc/systemd/system COMPONENT system)

# Bilgi Mesajı
message(STATUS "Systemd servisi icin: 'sudo make install' ardindan 'sudo systemctl enable --now ransom-bpf' calistirin.")