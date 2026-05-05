// Copyright (c) Microsoft. All rights reserved.

#include <stddef.h>
#include "testrunnerswitcher.h"
#include "c_logging/logger.h"

int main(void)
{
    size_t failedTestCount = 0;
    (void)logger_init();
    RUN_TEST_SUITE(constbuffer_array_batcher_unittests, failedTestCount);
    logger_deinit();
    return (int)failedTestCount;
}
