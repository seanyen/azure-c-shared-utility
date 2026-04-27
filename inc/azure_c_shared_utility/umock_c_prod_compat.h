// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Compatibility shim: MOCKABLE_INTERFACE was removed from modern umock-c
// (Azure/umock-c commit 8faec2a). Re-provide the production-mode definition
// so that existing headers (constbuffer.h, memory_data.h, etc.) continue to work.

#ifndef UMOCK_C_PROD_COMPAT_H
#define UMOCK_C_PROD_COMPAT_H

#include "umock_c/umock_c_prod.h"

#ifndef MOCKABLE_INTERFACE
#define MOCKABLE_INTERFACE(interface_name, ...) \
    MU_FOR_EACH_1(EXPAND_PROD_ENTRY, __VA_ARGS__)
#endif

// IGNORED_PTR_ARG and IGNORED_NUM_ARG were removed from modern umock-c
// in favor of the unified IGNORED_ARG. Provide compat defines.
#ifndef IGNORED_PTR_ARG
#define IGNORED_PTR_ARG (NULL)
#endif
#ifndef IGNORED_NUM_ARG
#define IGNORED_NUM_ARG (0)
#endif

#endif /* UMOCK_C_PROD_COMPAT_H */
