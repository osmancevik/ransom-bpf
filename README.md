# eBPF Sentinel

This repository hosts the source code for a Final Year Thesis Project focused on real-time behavioral analysis and threat detection in Linux environments.

# Project Goal

The primary objective of this project is to leverage eBPF (Extended Berkeley Packet Filter) to monitor kernel-level system events. By analyzing these events, the tool aims to detect and potentially block malicious behavioral patterns, such as those exhibited by ransomware (e.g., rapid file encryption, shadow copy deletion).

This project is under active development, starting from a simple execve trace prototype and evolving towards a more complex detection engine.

# Repository Structure

The repository is organized to separate documentation from source code, ensuring a clean and manageable project layout.

'''/
├── docs/              # Contains all project documentation, including research,
│                      # planning, and weekly progress reports (e.g., Rapor-1, Rapor-2).
│
├── .gitignore         # Excludes build artifacts, IDE settings, and local files (vmlinux.h).
├── CMakeLists.txt     # The main build script for CMake.
├── README.md          # This file: An overview of the project.
│
└── src/               # (Or root) Contains all kernel (*_kern.c) and
                       # user-space (*_user.c) source code.'''


# Core Technologies

eBPF (for kernel-level tracing)

C (for kernel probe and user-space agent)

libbpf (for BPF object loading and management)

CMake (for building the project)

Getting Started (Current Prototype)

The current hello_ebpf prototype is designed to be built on a modern Linux system (e.g., Debian 13) with the necessary eBPF development headers.

# Prerequisites

clang

libbpf-dev

libelf-dev

bpftool

1. Generate Kernel Headers

eBPF programs require system-specific kernel type definitions (vmlinux.h).

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


2. Build

Use CMake to configure and build the project:

Create a build directory (if not using CLion's default)
mkdir build
cd build
cmake ..
make


3. Run

The agent requires root privileges to load eBPF programs.

Terminal 1 (To monitor trace output):

sudo cat /sys/kernel/tracing/trace_pipe


Terminal 2 (To run the agent):

# From the build directory
sudo ./hello_ebpf
