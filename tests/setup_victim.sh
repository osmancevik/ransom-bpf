#!/bin/bash
#
# setup_victim.sh - RansomBPF Test Environment Provisioner
# Version: 0.9.0
#
# Description:
#   Prepares a controlled "victim" directory containing dummy files (PDF, DOCX)
#   and a strategic honeypot file. This ensures a consistent baseline for
#   validating the ransomware detection engine (Unit & Integration Tests).
#
# Usage:
#   ./setup_victim.sh
#

# Configuration
TARGET_DIR="/home/developer/test_files"
HONEYPOT_FILE="$TARGET_DIR/secret_passwords.txt"

echo "[*] Initializing test environment at: $TARGET_DIR"

# Ensure the directory exists
mkdir -p "$TARGET_DIR"

# Clean up previous test artifacts to ensure a fresh baseline
rm -f "$TARGET_DIR"/*

echo "[*] Generating 50 dummy victim files..."

for i in {1..50}; do
    # Simulate DOCX files
    echo "Confidential corporate data. File ID: $i" > "$TARGET_DIR/budget_report_$i.docx"

    # Simulate PDF files
    echo "Customer database record $i" > "$TARGET_DIR/customer_list_$i.pdf"
done

# Create the Honeypot (Trap) file
# Note: This filename must match the 'HONEYPOT_FILE' setting in ransom.conf
echo "admin:123456root:toor" > "$HONEYPOT_FILE"
echo "[*] Honeypot file deployed: $HONEYPOT_FILE"

echo "[SUCCESS] Victim environment is ready! You can now launch the simulation."