#define LOG_MODULE "util-log"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/defs.h"
#include "util/log.h"
#include "util/str.h"

static void util_log_format(enum util_log_level level, const char* trace, 
        const char* module, const char* fmt, va_list ap);
static void util_log_writer_console(void* ctx, enum util_log_level level, 
        const char* chars, size_t nchars);
static void util_log_writer_file(void* ctx, enum util_log_level level, 
        const char* chars, size_t nchars);

static enum util_log_level util_log_level = LOG_LEVEL_DEBUG;
static FILE* util_log_file;

void util_log_set_file(const char* path)
{
    if (path) {
        util_log_file = fopen(path, "w+");
        log_info("Open log file: %s", path);
    }
}

void util_log_set_level(enum util_log_level new_level)
{
    util_log_level = new_level;
}

void util_log(enum util_log_level level, const char* module, const char* trace, 
        const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    util_log_format(level, module, trace, fmt, ap);
    va_end(ap);   
}

static void util_log_format(enum util_log_level level, const char* module, 
        const char* trace, const char* fmt, va_list ap)
{
    static const char chars[] = "XEWID";

    char line[8192];
    char msg[8192];
    int result;

    util_str_vformat(msg, sizeof(msg), fmt, ap);
    result = util_str_format(line, sizeof(line), "[%c][%s][%s]: %s\n", 
            chars[level], module, trace, msg);

    if (level <= util_log_level) {
        util_log_writer_console(NULL, level, line, result);

        if (util_log_file != NULL) {
            util_log_writer_file(util_log_file, level, line, result);
        }
    }

    if (level == LOG_LEVEL_DIE) {
        abort();
    }
}

static void util_log_writer_console(void* ctx, enum util_log_level level, 
        const char* chars, size_t nchars)
{
    switch (level) {
        case LOG_LEVEL_DEBUG:
            printf("\033[%d;%dm%s\033[0m", 0, 37, chars);
            break;

        case LOG_LEVEL_INFO:
            printf("\033[%d;%dm%s\033[0m", 0, 34, chars);
            break;

        case LOG_LEVEL_WARN:
            printf("\033[%d;%dm%s\033[0m", 0, 33, chars);
            break;

        case LOG_LEVEL_ERROR:
            printf("\033[%d;%dm%s\033[0m", 0, 31, chars);
            break;

        case LOG_LEVEL_DIE:
            printf("\033[%d;%d;%dm%s\033[0m", 0, 33, 52, chars);
            break;

        default:
            break;
    }
}

static void util_log_writer_file(void* ctx, enum util_log_level level, 
        const char* chars, size_t nchars)
{
    fwrite(chars, 1, nchars, (FILE*) ctx);
    fflush((FILE*) ctx);
}