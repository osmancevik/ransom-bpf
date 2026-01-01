#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>  // getpid() icin gerekli kütüphane eklendi
#include "cli.h"
#include "config.h"
#include "common.h"
#include "logger.h"

// Yeni "RansomBPF" ASCII Art Banner
static void print_banner() {
    printf("\033[1;36m"); // Cyan Rengi
    printf("  ____                                  ____  ____  _____ \n");
    printf(" |  _ \\ __ _ _ __  ___  ___  _ __ ___  | __ )|  _ \\|  ___|\n");
    printf(" | |_) / _` | '_ \\/ __|/ _ \\| '_ ` _ \\ |  _ \\| |_) | |_   \n");
    printf(" |  _ < (_| | | | \\__ \\ (_) | | | | | || |_) |  __/|  _|  \n");
    printf(" |_| \\_\\__,_|_| |_|___/\\___/|_| |_| |_||____/|_|   |_|   v%s\n", APP_VERSION);
    printf("\033[0m\n");
}

static void print_help(const char *prog_name) {
    print_banner();
    printf("Kullanim: %s [SECENEKLER]\n\n", prog_name);
    printf("Secenekler:\n");
    printf("  -c, --config <file>     Konfigurasyon dosyasini yukle (Varsayilan: ./ransom.conf)\n");
    printf("  -l, --log-file <file>   Log dosyasinin konumunu degistir\n");
    printf("      --write-limit <n>   Yazma esik degerini (threshold) ezer\n");
    printf("  -v, --verbose           Detayli hata ayiklama modunu (DEBUG) acar\n");
    printf("  -V, --version           Surum bilgisini gosterir\n");
    printf("  -h, --help              Bu yardim mesajini gosterir\n");
    printf("\nOrnek:\n");
    printf("  sudo %s --config my.conf --verbose\n", prog_name);
    printf("  sudo %s --write-limit 50\n", prog_name);
}

int parse_arguments(int argc, char **argv) {
    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"version",     no_argument,       0, 'V'},
        {"verbose",     no_argument,       0, 'v'},
        {"config",      required_argument, 0, 'c'},
        {"log-file",    required_argument, 0, 'l'},
        {"write-limit", required_argument, 0, 1001},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hVvc:l:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return CLI_ACTION_EXIT; // Exit yerine Return
        case 'V':
            printf("RansomBPF version %s\n", APP_VERSION);
            return CLI_ACTION_EXIT; // Exit yerine Return
        case 'v':
            config.verbose_mode = 1;
            break;
        case 'c':
            // Dosyayı hemen yükleme, yolu kaydet. Main yükleyecek.
            strncpy(config.config_path, optarg, sizeof(config.config_path) - 1);
            break;
        case 'l':
            strncpy(config.log_file, optarg, sizeof(config.log_file) - 1);
            break;
        case 1001: // --write-limit
            config.write_threshold = atoi(optarg);
            break;
        default:
            // Hatalı parametre durumunda da çıkış iste
            return CLI_ACTION_EXIT;
        }
    }

    return CLI_ACTION_CONTINUE;
}

void print_startup_summary() {
    print_banner();
    printf("--------------------------------------------------\n");
    printf(" AKTIF KONFIGURASYON\n");
    printf("--------------------------------------------------\n");
    printf(" PID            : %d\n", getpid());
    printf(" Log Dosyasi    : %s\n", config.log_file);
    printf(" Config Modu    : %s\n", config.verbose_mode ? "DEBUG (Verbose)" : "NORMAL");
    printf(" Whitelist      : %s\n", config.whitelist_str[0] ? config.whitelist_str : "[BOS]");
    printf("--------------------------------------------------\n");
    printf(" ESIK DEGERLERI (Thresholds)\n");
    printf("--------------------------------------------------\n");
    printf(" Zaman Penceresi: %d sn\n", config.window_sec);
    printf(" Yazma Limiti   : %d / pencere\n", config.write_threshold);
    printf(" Rename Limiti  : %d / pencere\n", config.rename_threshold);
    printf("--------------------------------------------------\n\n");
}