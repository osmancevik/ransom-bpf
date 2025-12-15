#ifndef CLI_H
#define CLI_H

// Komut satırı argümanlarını işler ve config yapısını günceller
void parse_arguments(int argc, char **argv);

// Başlangıç özet tablosunu basar
void print_startup_summary();

#endif // CLI_H