#!/bin/bash

# --- RansomBPF Test Ortamı Hazırlayıcı ---
# Hedef: /home/developer/test_files

TARGET_DIR="/home/developer/test_files"

echo "[*] Test klasoru olusturuluyor: $TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Eski dosyalar varsa temizle (Temiz baslangic)
rm -f "$TARGET_DIR"/*

echo "[*] 50 adet sahte kurban dosyasi olusturuluyor..."

for i in {1..50}; do
    # Docx taklidi
    echo "Bu dosya cok gizli sirket verisi icerir. Dosya numarasi: $i" > "$TARGET_DIR/butce_raporu_$i.docx"
    # PDF taklidi
    echo "Musteri veritabani kayitlari $i" > "$TARGET_DIR/musteri_listesi_$i.pdf"
done

# Honeypot (Yem) dosyasi - Config dosyanla uyumlu olmali!
# RansomBPF config dosyasinda belirtecegimiz yem dosya:
HONEYPOT_FILE="$TARGET_DIR/secret_passwords.txt"
echo "admin:123456root:toor" > "$HONEYPOT_FILE"
echo "[*] Honeypot dosyasi eklendi: $HONEYPOT_FILE"

echo "[SUCCESS] Kurban ortami hazir! Saldiri simulasyonuna baslayabilirsin."