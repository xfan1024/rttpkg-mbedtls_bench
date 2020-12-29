# mbedtls_bench

The project was developed for [RT-Thread](https://github.com/RT-Thread/rt-thread) operation system

## Introduction

The mbedtls_bench is a performance test tool of cryptographic algorithms of mbedtls.

The scores mean the amount of block data that can be processed, higher scores mean better performance.

## Scores

### qemu-vexpress-a9
``` text
type                     16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes
AES-128-CBC                352065       187244        65660        18410         2286
AES-192-CBC                340879       172487        58703        15246         1985
AES-256-CBC                315159       156482        50065        13554         1749
AES-128-CFB128             652588       226878        64864        16352         2118
AES-192-CFB128             615378       207584        56404        14560         1682
AES-256-CFB128             542006       184085        51524        13337         1614
AES-128-CTR                661576       234286        65780        16910         2109
AES-192-CTR                625593       204125        58875        15395         1840
AES-256-CTR                550803       184825        50331        13213         1635
AES-128-GCM                258679        71874        18265         4415          562
AES-192-GCM                251820        69352        17978         4484          548
AES-256-GCM                249674        64361        16906         4287          522
ARC4-128                  1317720       635173       211839        57615         6960
BLOWFISH-CBC               410390       211223        67923        18454         2299
BLOWFISH-CFB64             656589       226432        64471        16788         2162
BLOWFISH-CTR               636727       239898        65162        16861         2105
CAMELLIA-128-CBC           194712        89012        27491         7560          960
CAMELLIA-192-CBC           164935        70808        22406         5818          730
CAMELLIA-256-CBC           156308        71139        22492         6094          760
CAMELLIA-128-CFB128        379186       105391        28526         7300          926
CAMELLIA-192-CFB128        306257        91829        23118         5931          685
CAMELLIA-256-CFB128        301772        87918        22939         5897          724
CAMELLIA-128-CTR           371432       109094        27809         7317          903
CAMELLIA-192-CTR           304344        88976        23429         5892          721
CAMELLIA-256-CTR           293713        87726        23568         5868          727
CAMELLIA-128-GCM           196973        53969        13437         3409          419
CAMELLIA-192-GCM           172347        48622        12401         2954          369
CAMELLIA-256-GCM           176124        45859        12038         3086          371
DES-CBC                    367800       158448        49251        13045         1652
DES-EDE-CBC                150723        57467        16499         4261          526
DES-EDE3-CBC               153566        58653        16028         4172          535
```
