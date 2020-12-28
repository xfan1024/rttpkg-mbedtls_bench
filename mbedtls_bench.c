/*
 * Copyright (c) 2020 xiaofan <xfan1024@live.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <rtthread.h>
#include <finsh.h>

#ifdef MBEDTLS_BENCH_CHECK_SHELL_STACK
#ifndef FINSH_THREAD_STACK_SIZE
#error "FINSH_THREAD_STACK_SIZE not defined"
#endif
#if FINSH_THREAD_STACK_SIZE < 3072
#error "suggest that shell stack size is not less than 3072"
#endif
#endif

static char *g_common_key = "55ca86552a4bc0fa5810fd1d27af968b50516dcf22ad5631eb1d8231b62440fb";

#define L(...) {__VA_ARGS__}

#ifdef MBEDTLS_BENCH_TEST_8K
#define TOP_ROW                 "type                     16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes\n"
#define SCORE_FMT_STR           "%-20s %12u %12u %12u %12u %12u\n"
#define SCORE_FMT_PAR(name, s)  name, (unsigned int)s[0], (unsigned int)s[1], \
                                (unsigned int)s[2], (unsigned int)s[3], (unsigned int)s[4]
static const uint16_t g_block_size[] = {16, 64, 256, 1024, 8192};
#define BENCH_BUF_IDATA_MAX     8192
#else
#define TOP_ROW                 "type                     16 bytes     64 bytes    256 bytes   1024 bytes\n"
#define SCORE_FMT_STR           "%-20s %12u %12u %12u %12u\n"
#define SCORE_FMT_PAR(name, s)  name, (unsigned int)s[0], (unsigned int)s[1], \
                                (unsigned int)s[2], (unsigned int)s[3]
static const uint16_t g_block_size[] = {16, 64, 256, 1024};
#define BENCH_BUF_IDATA_MAX     1024
#endif

#define BENCH_BUF_ODATA_MAX     (BENCH_BUF_IDATA_MAX+64)
#if 0
struct bench_buf
{
    char idata[BENCH_BUF_IDATA_MAX];
    char odata[BENCH_BUF_ODATA_MAX];
};

#else
struct bench_buf
{
    char buf[BENCH_BUF_ODATA_MAX];
};
#define idata buf
#define odata buf
#endif

#ifdef MBEDTLS_BENCH_SIMPLE
#include "mbedtls_bench_simple.impl.h"
#else
static inline bool bench_simple_run_by_name(const char *name, struct bench_buf *bb)
{
    return false;
}
#endif

#ifdef MBEDTLS_BENCH_CIPHER
#include "mbedtls_bench_cipher.impl.h"
#else
static inline bool bench_chiper_run_by_name(const char *name, struct bench_buf *bb)
{
    return false;
}
#endif

static void bench_from_name(const char *name, struct bench_buf *bb)
{
    if (bench_simple_run_by_name(name, bb) && name)
        return;

    if (bench_chiper_run_by_name(name, bb) && name)
        return;

    if (name)
        rt_kprintf("cannot found algorithm: %s\n", name);
}

static int cmd_mbedtls_bench(int argc, char **argv)
{
    struct bench_buf *bb = rt_malloc(sizeof(struct bench_buf));
    if (!bb)
    {
        rt_kprintf("allocate bench_buf fail\n");
#ifdef MBEDTLS_BENCH_TEST_8K
        rt_kprintf("consider to unset MBEDTLS_BENCH_TEST_8K to save memory\n");
#endif
        return -1;
    }
    rt_kprintf(TOP_ROW);
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            bench_from_name(argv[i], bb);
        }
    }
    else
    {
        bench_from_name(NULL, bb);
    }
    rt_free(bb);
    return 0;
}

FINSH_FUNCTION_EXPORT_ALIAS(cmd_mbedtls_bench, __cmd_mbedtls_bench, test mbedtls speed on your system);

