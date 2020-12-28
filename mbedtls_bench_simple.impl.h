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

#define BENCH_SIMPLE_KEYLEN_MAX 4

#include <mbedtls/config.h>

#ifdef MBEDTLS_AES_C

#include <mbedtls/aes.h>

static void bench_alg_fini_aes(void *context)
{
    mbedtls_aes_context *ctx = context;
    mbedtls_aes_free(ctx);
    free(ctx);
}

static void* bench_alg_init_aes(uint16_t keylen)
{
    mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));

    if (!ctx)
        goto err;
    mbedtls_aes_init(ctx);
    if (mbedtls_aes_setkey_enc(ctx, (const unsigned char*)g_common_key, (unsigned int)keylen))
        goto err;
    return ctx;

err:
    if (ctx)
        bench_alg_fini_aes(ctx);
    return NULL;
}

static void bench_alg_test_aes(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_aes_context *ctx = context;
    unsigned char iv[16];

    mbedtls_aes_crypt_cbc(ctx, MBEDTLS_AES_ENCRYPT, (size_t)blocksize, iv, (unsigned char*)bb->idata, (unsigned char*)bb->odata);
}

#endif // MBEDTLS_AES_C

#ifdef MBEDTLS_DES_C

#include <mbedtls/des.h>

static void bench_alg_fini_des(void *context)
{
    mbedtls_des_context *ctx = context;
    mbedtls_des_free(ctx);
    free(ctx);
}

static void* bench_alg_init_des(uint16_t keylen)
{
    mbedtls_des_context *ctx = malloc(sizeof(mbedtls_des_context));

    if (!ctx)
        goto err;
    mbedtls_des_init(ctx);
    if (mbedtls_des_setkey_enc(ctx, (const unsigned char*)g_common_key))
        goto err;
    return ctx;

err:
    if (ctx)
        bench_alg_fini_des(ctx);
    return NULL;
}

static void bench_alg_test_des(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_des_context *ctx = context;
    unsigned char iv[16];

    mbedtls_des_crypt_cbc(ctx, MBEDTLS_DES_ENCRYPT, (size_t)blocksize, iv, (unsigned char*)bb->idata, (unsigned char*)bb->odata);
}

#endif // MBEDTLS_DES_C

#ifdef MBEDTLS_MD5_C

#include <mbedtls/md5.h>

static void bench_alg_fini_md5(void *context)
{
    mbedtls_md5_context *ctx = context;
    mbedtls_md5_free(ctx);
    free(ctx);
}

static void* bench_alg_init_md5(uint16_t keylen)
{
    mbedtls_md5_context *ctx = malloc(sizeof(mbedtls_md5_context));

    if (!ctx)
        return NULL;
    mbedtls_md5_init(ctx);
    return ctx;
}

static void bench_alg_test_md5(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_md5_context *ctx = context;

    mbedtls_md5_update(ctx, (unsigned char*)bb->idata, blocksize);
    mbedtls_md5_finish(ctx, (unsigned char*)bb->odata);
}

#endif // MBEDTLS_MD5_C

#ifdef MBEDTLS_SHA1_C

#include <mbedtls/sha1.h>

static void bench_alg_fini_sha1(void *context)
{
    mbedtls_sha1_context *ctx = context;
    mbedtls_sha1_free(ctx);
    free(ctx);
}

static void* bench_alg_init_sha1(uint16_t keylen)
{
    mbedtls_sha1_context *ctx = malloc(sizeof(mbedtls_sha1_context));

    if (!ctx)
        return NULL;
    mbedtls_sha1_init(ctx);
    return ctx;
}

static void bench_alg_test_sha1(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_sha1_context *ctx = context;

    mbedtls_sha1_update(ctx, (unsigned char*)bb->idata, blocksize);
    mbedtls_sha1_finish(ctx, (unsigned char*)bb->odata);
}

#endif // MBEDTLS_SHA1_C

#ifdef MBEDTLS_SHA256_C

#include <mbedtls/sha256.h>

static void bench_alg_fini_sha256(void *context)
{
    mbedtls_sha256_context *ctx = context;
    mbedtls_sha256_free(ctx);
    free(ctx);
}

static void* bench_alg_init_sha256(uint16_t keylen)
{
    mbedtls_sha256_context *ctx = malloc(sizeof(mbedtls_sha256_context));

    if (!ctx)
        return NULL;
    mbedtls_sha256_init(ctx);
    return ctx;
}

static void bench_alg_test_sha256(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_sha256_context *ctx = context;

    mbedtls_sha256_update(ctx, (unsigned char*)bb->idata, blocksize);
    mbedtls_sha256_finish(ctx, (unsigned char*)bb->odata);
}

#endif // MBEDTLS_SHA256_C

#ifdef MBEDTLS_SHA512_C

#include <mbedtls/sha512.h>

static void bench_alg_fini_sha512(void *context)
{
    mbedtls_sha512_context *ctx = context;
    mbedtls_sha512_free(ctx);
    free(ctx);
}

static void* bench_alg_init_sha512(uint16_t keylen)
{
    mbedtls_sha512_context *ctx = malloc(sizeof(mbedtls_sha512_context));

    if (!ctx)
        return NULL;
    mbedtls_sha512_init(ctx);
    return ctx;
}

static void bench_alg_test_sha512(void *context, struct bench_buf *bb, uint32_t blocksize)
{
    mbedtls_sha512_context *ctx = context;

    mbedtls_sha512_update(ctx, (unsigned char*)bb->idata, blocksize);
    mbedtls_sha512_finish(ctx, (unsigned char*)bb->odata);
}

struct bench_simple_alg
{
    const char *name;
    void *(*fn_init)(uint16_t keylen);
    void (*fn_fini)(void *context);
    void (*fn_test)(void *context, struct bench_buf *bb, uint32_t blocksize);
    uint16_t keylen[BENCH_SIMPLE_KEYLEN_MAX];
    bool print_keylen;
};

#endif // MBEDTLS_SHA512_C

#define bench_simple_alg_define(alg, keylen_val, print_keylen_val) { \
    .name = #alg, \
    .fn_init = bench_alg_init_##alg, \
    .fn_fini = bench_alg_fini_##alg, \
    .fn_test = bench_alg_test_##alg, \
    .keylen = keylen_val, \
    .print_keylen = print_keylen_val, \
}

static struct bench_simple_alg g_simple_alg_list[] =
{
#ifdef MBEDTLS_AES_C
    bench_simple_alg_define(aes,  L(128, 192, 256), true),
#endif
#ifdef MBEDTLS_DES_C
    bench_simple_alg_define(des,  L(56), true),
#endif
#ifdef MBEDTLS_MD5_C
    bench_simple_alg_define(md5,  L(0), false),
#endif
#ifdef MBEDTLS_SHA1_C
    bench_simple_alg_define(sha1, L(0), false),
#endif
#ifdef MBEDTLS_SHA256_C
    bench_simple_alg_define(sha256, L(0), false),
#endif
#ifdef MBEDTLS_SHA512_C
    bench_simple_alg_define(sha512, L(0), false),
#endif
};

static size_t bench_simple_alg_internal(struct bench_simple_alg *alg, struct bench_buf *bb,
                                                uint16_t keylen, uint16_t block_size)
{
    void *context = alg->fn_init(keylen);
    if (!context)
    {
        rt_kprintf("init %s fail, keylen = %d\n", alg->name, (int)keylen);
        return 0;
    }

    // warm up
    alg->fn_test(context, bb, block_size);

    size_t cnt = 0;
    rt_tick_t end_tick = rt_tick_get() + rt_tick_from_millisecond(MBEDTLS_BENCH_TEST_SECOND * 1000);
    do
    {
        alg->fn_test(context, bb, block_size);
        cnt++;
    } while ((rt_base_t)(end_tick - rt_tick_get()) > 0);
    alg->fn_fini(context);
    return cnt / MBEDTLS_BENCH_TEST_SECOND;
}

static void bench_simple_alg_run(struct bench_simple_alg *alg, struct bench_buf *bb)
{
    size_t scores[sizeof(g_block_size) / sizeof(uint16_t)];

    for (unsigned int i = 0; i < BENCH_SIMPLE_KEYLEN_MAX; i++)
    {
        uint16_t keylen = alg->keylen[i];
        if (keylen == 0 && i)
            break;
        for (unsigned int j = 0; j < sizeof(g_block_size) / sizeof(uint16_t); j++)
        {
            scores[j] = bench_simple_alg_internal(alg, bb, keylen, g_block_size[j]);
        }

        char name[32];
        const char *alg_name = alg->name;
        if (alg->print_keylen)
        {
            rt_sprintf(name, "%s-%d", alg->name, (int)keylen);
            alg_name = name;
        }

        rt_kprintf(SCORE_FMT_STR, SCORE_FMT_PAR(alg_name, scores));
    }
}

static struct bench_simple_alg* bench_simple_alg_find(const char *name)
{
    for (unsigned int i = 0; i < sizeof(g_simple_alg_list) / sizeof(g_simple_alg_list[0]); i++)
    {
        if (strcmp(name, g_simple_alg_list[i].name) == 0)
            return &g_simple_alg_list[i];
    }
    return NULL;
}

bool bench_simple_run_by_name(const char *name, struct bench_buf *bb)
{
    struct bench_simple_alg *alg;

    if (name)
    {
        alg = bench_simple_alg_find(name);
        if (!alg)
            return false;
        bench_simple_alg_run(alg, bb);
        return true;
    }

    for (unsigned int i = 0; i < sizeof(g_simple_alg_list) / sizeof(g_simple_alg_list[0]); i++)
    {
        alg = &g_simple_alg_list[i];
        bench_simple_alg_run(alg, bb);
    }
    return sizeof(g_simple_alg_list) > 0;
}
