Import('RTT_ROOT')
Import('rtconfig')
from building import *

cwd     = GetCurrentDir()
src     = Glob('*.c')

group = DefineGroup('mbedtls_bench', src, depend = ['PKG_USING_MBEDTLS_BENCH'], CPPPATH = [])

Return('group')
