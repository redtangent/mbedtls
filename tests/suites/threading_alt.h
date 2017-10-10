/**
 * \file threading_alt.h
 *
 * \brief Alternative threading implementation for test
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)

typedef struct _mbedtls_threading_mutex_t
{
    char is_initialised;
    char is_locked;
} mbedtls_threading_mutex_t;

#define MBEDTLS_MUTEX_INITIALIZER       { 0, 0 }

#endif /* MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT) */

#endif /* MBEDTLS_THREADING_ALT_H */
