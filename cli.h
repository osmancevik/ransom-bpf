/* cli.h - v0.9.0 (Standardized) */
#ifndef CLI_H
#define CLI_H

/**
 * @file cli.h
 * @brief Command Line Interface (CLI) handler.
 *
 * This module parses command-line arguments (using getopt_long) and
 * displays the startup summary banner. It serves as the primary entry
 * point for user interaction before the main event loop begins.
 */

// Return Codes for Argument Parsing
#define CLI_ACTION_CONTINUE 0  /**< Arguments processed successfully, continue execution */
#define CLI_ACTION_EXIT     1  /**< Help or Version requested, exit program gracefully */

/**
 * @brief Parses command-line arguments passed to the program.
 *
 * Handles standard POSIX arguments like --help, --version, --verbose,
 * and configuration overrides like --config or --write-limit.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return CLI_ACTION_CONTINUE (0) if the program should proceed,
 * CLI_ACTION_EXIT (1) if it should terminate (e.g., after printing help).
 */
int parse_arguments(int argc, char **argv);

/**
 * @brief Displays the startup banner and active configuration summary.
 *
 * Prints the ASCII art logo, current version, process ID, active log files,
 * and key risk scoring parameters to the standard output. This provides
 * immediate visual feedback to the operator upon startup.
 */
void print_startup_summary();

#endif // CLI_H