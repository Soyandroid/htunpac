#ifndef UTIL_LOG_H
#define UTIL_LOG_H

#include "defs.h"

#ifndef LOG_MODULE
#define LOG_MODULE STRINGIFY(__FILE__)
#endif

#ifndef LOG_SUPPRESS

#define LOG_TRACE_STR ":" XSTRINGIFY(__LINE__)

#define log_debug(...) util_log(LOG_LEVEL_DEBUG, LOG_MODULE, LOG_TRACE_STR, __VA_ARGS__)
#define log_info(...) util_log(LOG_LEVEL_INFO, LOG_MODULE, LOG_TRACE_STR, __VA_ARGS__)
#define log_warn(...) util_log(LOG_LEVEL_WARN, LOG_MODULE, LOG_TRACE_STR, __VA_ARGS__)
#define log_error(...) util_log(LOG_LEVEL_ERROR, LOG_MODULE, LOG_TRACE_STR, __VA_ARGS__)
#define log_die(...) util_log(LOG_LEVEL_DIE, LOG_MODULE, LOG_TRACE_STR, __VA_ARGS__)

#else

#define log_debug(...)
#define log_info(...)
#define log_warn(...)
#define log_error(...)
#define log_die(...)

#endif

#define log_assert(x) \
    do { \
        if (!(x)) { \
            log_die(__FILE__, __LINE__, __FUNCTION__); \
        } \
    } while (0)

/**
 * Different log levels for logging
 */
enum util_log_level {
    LOG_LEVEL_DIE = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4
};

/**
 * Open a log file to write log output to in addition to stdout
 *
 * @param path Path of the log file (existing files are overwritten)
 */
void util_log_set_file(const char* path);

/**
 * Set the log level for logging
 *
 * @param new_level New log level
 */
void util_log_set_level(enum util_log_level new_level);

/**
 * Log a message
 *
 * Don't use this call to log something, use the macros instead
 *
 * @param level Log level of the message
 * @param module Name of the module where this function is called
 * @param trace Additional trace information (e.g. line number)
 * @param fmt Format string of log message
 * @param ... Arguments for format string
 */
void util_log(enum util_log_level level, const char* module, const char* trace, 
    const char* fmt, ...);

#endif