#!/bin/bash
set -u
export PATH=/mingw64/bin:$PATH
export TMPDIR=/c/msys64/tmp TMP=/c/msys64/tmp TEMP=/c/msys64/tmp
D=/d/nfc-tool/tools/src/mfoc-hardnested-a6007437405a0f18642a4bbca2eeba67c623d736
L=/d/nfc-tool/tools/src/libnfc-libnfc-1.8.0
B=/c/msys64/tmp/hn
cd "$D/src" || exit 1

FLAGS="-O2 -std=gnu99 -DWIN32 -DNDEBUG -DNOGDI -D_CRT_SECURE_NO_WARNINGS \
-DCONFFILES -DENVVARS -DHAVE_CONFIG_H -DLOG \
-Du_int8_t=uint8_t -Du_int16_t=uint16_t -DLZMA_API_STATIC -DX86_SIMD -DHAVE_ERRNO_H \
-iquote . -iquote hardnested -I$L/include -I$L -I$L/contrib/win32"

fail=0
compile() {
  local src="$1" out="$2" extra="${3:-}"
  if ! gcc $FLAGS $extra -c "$src" -o "$B/$out" 2> "$B/$out.log"; then
    echo "FAIL $src"
    grep -E 'error:|fatal error' "$B/$out.log" | head -5
    fail=1
  fi
}

compile mfoc.c mfoc.o
compile cmdhfmfhard.c cmdhfmfhard.o
compile crapto1.c crapto1.o
compile crypto1.c crypto1.o
compile mifare.c mifare.o
compile nfc-utils.c nfc-utils.o
compile parity.c parity.o
compile stdlib.c stdlib.o
compile ui.c ui.o
compile util.c util.o
compile util_posix.c util_posix.o
compile hardnested/hardnested_bruteforce.c hardnested_bruteforce.o
compile hardnested/hardnested_cpu_dispatch.c hardnested_cpu_dispatch.o
compile hardnested/tables.c tables.o
compile hardnested/hardnested_bf_core_NOSIMD.c hardnested_bf_core_NOSIMD.o
compile hardnested/hardnested_bitarray_core_NOSIMD.c hardnested_bitarray_core_NOSIMD.o
compile hardnested/hardnested_bf_core_SSE2.c hardnested_bf_core_SSE2.o "-msse2"
compile hardnested/hardnested_bitarray_core_SSE2.c hardnested_bitarray_core_SSE2.o "-msse2"
compile hardnested/hardnested_bf_core_AVX.c hardnested_bf_core_AVX.o "-mavx"
compile hardnested/hardnested_bitarray_core_AVX.c hardnested_bitarray_core_AVX.o "-mavx"
compile hardnested/hardnested_bf_core_AVX2.c hardnested_bf_core_AVX2.o "-mavx2"
compile hardnested/hardnested_bitarray_core_AVX2.c hardnested_bitarray_core_AVX2.o "-mavx2"
compile hardnested/hardnested_bf_core_AVX512.c hardnested_bf_core_AVX512.o "-mavx512f -mavx512bw"
compile hardnested/hardnested_bitarray_core_AVX512.c hardnested_bitarray_core_AVX512.o "-mavx512f -mavx512bw"

echo "objects: $(ls "$B"/*.o 2>/dev/null | wc -l)  fail=$fail"
exit $fail
