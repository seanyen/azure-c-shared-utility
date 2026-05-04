// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This header is a backward-compatibility shim that bridges the legacy xlogging API
// to the modern c-logging library. New code should use c_logging/logger.h directly.

#ifndef XLOGGING_H
#define XLOGGING_H

#ifdef __cplusplus
#include <cstdlib>
#include <cstdio>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

#include "macro_utils/macro_utils.h"

// These headers were historically included via xlogging.h; keep for backward compat
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/optimize_size.h"

// Legacy LOG_CATEGORY enum (used by consolelogger.h, etwlogger_driver.h)
typedef enum LOG_CATEGORY_TAG
{
    AZ_LOG_ERROR,
    AZ_LOG_INFO,
    AZ_LOG_TRACE
} LOG_CATEGORY;

// Legacy function pointer type.
// Renamed from LOGGER_LOG to avoid collision with c-logging's LOGGER_LOG macro.
typedef void(*XLOGGING_LOGGER_LOG)(LOG_CATEGORY log_category, const char* file, const char* func, int line, unsigned int options, const char* format, ...);
typedef void(*LOGGER_LOG_GETLASTERROR)(const char* file, const char* func, int line, const char* format, ...);

// Legacy constants (still used by consolelogger.c, adapters)
#define TEMP_BUFFER_SIZE 1024
#define MESSAGE_BUFFER_SIZE 260
#define LOG_NONE 0x00
#define LOG_LINE 0x01

#ifdef NO_LOGGING
/*no logging is useful when time and fprintf are mocked*/
/* Undef any macros previously defined by c-logging (logger_v1_v2.h) */
#undef LOG
#undef LogInfo
#undef LogBinary
#undef LogError
#undef LogLastError
#define LOG(...)
#define LogInfo(...)
#define LogBinary(...)
#define LogError(...)
#define LogLastError(...)
#define xlogging_get_log_function() NULL
#define xlogging_set_log_function(...)
#define LogErrorWinHTTPWithGetLastErrorAsString(...)
#define UNUSED(x) (void)(x)

#elif (defined MINIMAL_LOGERROR)
#define LOG(...)
#define LogInfo(...)
#define LogBinary(...)
#define LogError(...) printf("error %s: line %d\n",__FILE__,__LINE__);
#define xlogging_get_log_function() NULL
#define xlogging_set_log_function(...)
#define LogErrorWinHTTPWithGetLastErrorAsString(...)
#define UNUSED(x) (void)(x)

#elif defined(ESP8266_RTOS)
#include "c_types.h"
#define LogInfo(FORMAT, ...) do {    \
        static const char flash_str[] ICACHE_RODATA_ATTR STORE_ATTR = FORMAT;  \
        printf(flash_str, ##__VA_ARGS__);   \
        printf("\n");\
    } while((void)0,0)

#define LogError LogInfo

#else /* Normal build: use c-logging */

#include "c_logging/logger.h"

// Legacy LOG(category, options, format, ...) macro used by uamqp.
// Map to LogInfo since c-logging handles severity internally.
#define LOG(log_category, log_options, format, ...) LogInfo(format, ##__VA_ARGS__)

// LogError, LogInfo, LogVerbose, LogLastError, LogCritical, LogWarning
// are now provided by c_logging/logger_v1_v2.h (included via logger.h)

#ifdef __cplusplus
extern "C" {
#endif

// Legacy logging configuration functions.
// In the c-logging world, logging sinks are configured via logger_set_config().
// These are kept for link-time backward compatibility.
extern void xlogging_set_log_function(XLOGGING_LOGGER_LOG log_function);
extern XLOGGING_LOGGER_LOG xlogging_get_log_function(void);

#if defined(_MSC_VER)
extern void xlogging_set_log_function_GetLastError(LOGGER_LOG_GETLASTERROR log_function);
extern LOGGER_LOG_GETLASTERROR xlogging_get_log_function_GetLastError(void);
#endif

extern void LogBinary(const char* comment, const void* data, size_t size);

#ifdef WIN32
extern void xlogging_LogErrorWinHTTPWithGetLastErrorAsStringFormatter(int errorMessageID);

#if defined(_MSC_VER)
#define LogErrorWinHTTPWithGetLastErrorAsString(FORMAT, ...) do { \
                int errorMessageID = GetLastError(); \
                LogError(FORMAT, __VA_ARGS__); \
                xlogging_LogErrorWinHTTPWithGetLastErrorAsStringFormatter(errorMessageID); \
            } while((void)0,0)
#else
#define LogErrorWinHTTPWithGetLastErrorAsString(FORMAT, ...) do { \
                int errorMessageID = GetLastError(); \
                LogError(FORMAT, ##__VA_ARGS__); \
                xlogging_LogErrorWinHTTPWithGetLastErrorAsStringFormatter(errorMessageID); \
            } while((void)0,0)
#endif // _MSC_VER
#endif // WIN32

#ifdef __cplusplus
}
#endif

#endif /* NO_LOGGING / MINIMAL_LOGERROR / ESP8266_RTOS / normal */

#endif /* XLOGGING_H */
