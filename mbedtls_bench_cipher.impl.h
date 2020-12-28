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

#define BENCH_CHIPER_KEYLEN_MAX 4
#define BENCH_CHIPER_MODE_MAX   4
#include <mbedtls/cipher.h>

static bool bench_cipher_test(mbedtls_cipher_context_t *ctx, struct bench_buf *bb, uint16_t block_size)
{
    size_t olen = BENCH_BUF_ODATA_MAX;
    if (mbedtls_cipher_reset(ctx))
    {
        rt_kprintf("%s: mbedtls_cipher_reset fail\n", mbedtls_cipher_get_name(ctx));
    }
    if (mbedtls_cipher_update(ctx, (unsigned char*)bb->idata, block_size, (unsigned char*)bb->odata, &olen))
    {
        rt_kprintf("%s: mbedtls_cipher_update fail\n", mbedtls_cipher_get_name(ctx));
        return false;
    }
    olen = BENCH_BUF_ODATA_MAX;
    if (mbedtls_cipher_finish(ctx, (unsigned char*)bb->odata, &olen))
    {
        rt_kprintf("%s: mbedtls_cipher_finish fail\n", mbedtls_cipher_get_name(ctx));
        return false;
    }
    return true;
}

static size_t bench_chiper_run_internal(const mbedtls_cipher_info_t *info, struct bench_buf *bb, uint16_t block_size)
{
    size_t cnt = 0;
    mbedtls_cipher_context_t ctx;

    // mbedtls_cipher_init(&ctx);
    if (mbedtls_cipher_setup(&ctx, info))
    {
        rt_kprintf("%s: mbedtls_cipher_setup fail\n", info->name);
        goto out;
    }

    int keylen = mbedtls_cipher_get_key_bitlen(&ctx);
    if (mbedtls_cipher_setkey(&ctx, (const unsigned char*)g_common_key, keylen, MBEDTLS_ENCRYPT))
    {
        rt_kprintf("%s: mbedtls_cipher_setkey fail, keylen = %d\n", info->name, keylen);
        goto out;
    }

    int ivlen = mbedtls_cipher_get_iv_size(&ctx);

    if (mbedtls_cipher_set_iv(&ctx, (const unsigned char*)g_common_key, ivlen))
    {
        rt_kprintf("%s: mbedtls_cipher_set_iv fail, ivlen = %d\n", info->name, ivlen);
        goto out;
    }

    // warm up
    if (!bench_cipher_test(&ctx, bb, block_size))
        goto out;

    rt_tick_t end_tick = rt_tick_get() + rt_tick_from_millisecond(MBEDTLS_BENCH_TEST_SECOND * 1000);
    do
    {
        if (!bench_cipher_test(&ctx, bb, block_size))
        {
            cnt = 0;
            goto out;
        }
        cnt++;
    } while ((rt_base_t)(end_tick - rt_tick_get()) > 0);

out:
    mbedtls_cipher_free(&ctx);
    return cnt / MBEDTLS_BENCH_TEST_SECOND;
}

static void bench_chiper_run(const mbedtls_cipher_info_t *info, struct bench_buf *bb)
{
    size_t scores[sizeof(g_block_size) / sizeof(uint16_t)];

    for (unsigned int j = 0; j < sizeof(g_block_size) / sizeof(uint16_t); j++)
    {
        scores[j] = bench_chiper_run_internal(info, bb, g_block_size[j]);
    }

    rt_kprintf(SCORE_FMT_STR, SCORE_FMT_PAR(info->name, scores));
}

bool bench_chiper_run_by_name(const char *name, struct bench_buf *bb)
{
    const mbedtls_cipher_info_t *info;
    size_t name_len = 0;

    if (name)
    {
        info = mbedtls_cipher_info_from_string(name);
        if (info)
        {
            if (info->mode == MBEDTLS_MODE_ECB || info->mode == MBEDTLS_MODE_CCM)
            {
                rt_kprintf("not support cipher: %s\n", info->name);
                return false;
            }
            bench_chiper_run(info, bb);
            return true;
        }
        name_len = strlen(name);
    }

    const int *cipher_list = mbedtls_cipher_list();
    bool ret = false;

    while (*cipher_list)
    {
        int id = *cipher_list++;
        info = mbedtls_cipher_info_from_type((mbedtls_cipher_type_t)id);
        if (name && (memcmp(name, info->name, name_len) != 0 || info->name[name_len] != '-'))
            continue;

        if (info->mode == MBEDTLS_MODE_ECB || info->mode == MBEDTLS_MODE_CCM)
        {
            // rt_kprintf("skip not support cipher: %s\n", info->name);
            continue;
        }

        if (info)
        {
            bench_chiper_run(info, bb);
            ret = true;
        }
    }

    return ret;
}
