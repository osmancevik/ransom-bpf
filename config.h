/* config.h - v0.9.0 (Standardized) */
#ifndef CONFIG_H
#define CONFIG_H

/**
 * @file config.h
 * @brief Configuration constants and structure definitions.
 */

// --- Default Configuration Values ---
#define DEFAULT_WINDOW_SEC 5
#define DEFAULT_RISK_THRESHOLD 100

// Scoring Defaults
#define DEFAULT_SCORE_WRITE 2
#define DEFAULT_SCORE_RENAME 20
#define DEFAULT_SCORE_UNLINK 50
#define DEFAULT_SCORE_HONEYPOT 1000
#define DEFAULT_SCORE_EXT_PENALTY 50

// Log File Paths
#define DEFAULT_SERVICE_LOG "./service.log"
#define DEFAULT_ALERT_LOG   "./alerts.json"
#define DEFAULT_AUDIT_LOG   "./audit.json"

#define MAX_WHITELIST_LENGTH 2048

/**
 * @struct app_config
 * @brief runtime configuration parameters for the detection engine.
 *
 * This structure holds all tunable settings loaded from the config file,
 * CLI arguments, or default values.
 */
struct app_config {
    // --- Timing & Thresholds ---
    int window_sec;          /**< Time window in seconds for rate limiting reset */
    int write_threshold;     /**< Legacy: Max write operations per window (Deprecated) */
    int rename_threshold;    /**< Legacy: Max rename operations per window (Deprecated) */

    // --- Risk Scoring Weights ---
    int score_write;         /**< Risk score for a single write operation */
    int score_rename;        /**< Risk score for a rename operation */
    int score_unlink;        /**< Risk score for a file deletion */
    int score_honeypot;      /**< Risk score for accessing a honeypot file */
    int score_ext_penalty;   /**< Penalty score for suspicious file extensions (e.g., .locked) */
    int risk_threshold;      /**< Cumulative score limit to trigger an alarm */

    // --- Operational Flags ---
    int active_blocking;     /**< 1: Enable process killing (IPS), 0: Passive monitoring (IDS) */
    int verbose_mode;        /**< 1: Enable debug output to stdout */

    // --- Paths & Strings ---
    char service_log[256];   /**< Path to the general service log file */
    char alert_log[256];     /**< Path to the high-priority alerts JSON log */
    char audit_log[256];     /**< Path to the raw audit JSON log */

    char whitelist_str[MAX_WHITELIST_LENGTH]; /**< Raw CSV string of whitelisted process names */
    char honeypot_file[256];                  /**< Name or path of the honeypot file to monitor */
    char config_path[256];                    /**< Path to the loaded configuration file */
};

extern struct app_config config;

/**
 * @brief Initializes the global configuration with default values.
 */
void init_config_defaults();

/**
 * @brief Parses and loads configuration from a specified file.
 * * @param filename Path to the configuration file (e.g., "ransom.conf").
 */
void load_config_file(const char *filename);

#endif // CONFIG_H