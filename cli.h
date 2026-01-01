/* cli.h */
#ifndef CLI_H
#define CLI_H

// Dönüş Değerleri
#define CLI_ACTION_CONTINUE 0  // Normal çalışmaya devam et
#define CLI_ACTION_EXIT     1  // Help/Version basıldı, programdan çık

// Komut satırı argümanlarını işler
// Return: 0 (Devam), 1 (Çıkış)
int parse_arguments(int argc, char **argv);

void print_startup_summary();

#endif // CLI_H