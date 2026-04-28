// Copyright(C) Microsoft Corporation.All rights reserved.

#include <stddef.h>
#include "testrunnerswitcher.h"
#include "c_logging/logger.h"

int main(void)
{
    size_t failedTestCount = 0;
    (void)logger_init();
    RUN_TEST_SUITE(string_utils_int_tests, failedTestCount);
    logger_deinit();
    return (int)failedTestCount;
}
