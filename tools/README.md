# tools — 外部破解程序

`bin/` 里的 `mfoc.exe`、`mfcuk.exe`、`libnfc.dll` 是本机从 `src/` 的源码编出来的,64 位 Windows 版本,只保留 PN532 UART 驱动。`bin/` 和 `src/` 都在 `.gitignore` 里,不随仓库分发。

## 版本

| 组件 | 版本 | 源码 |
|---|---|---|
| libnfc | 1.8.0 | https://github.com/nfc-tools/libnfc/tree/libnfc-1.8.0 |
| mfoc | 0.10.7 | https://github.com/nfc-tools/mfoc/tree/mfoc-0.10.7 |
| mfcuk | 0.3.8 | https://github.com/nfc-tools/mfcuk/tree/mfcuk-0.3.8 |
| mfoc-hardnested | 0.10.9(a6007437) | https://github.com/nfc-tools/mfoc-hardnested |

`bin/` 里除三个 exe 外还需要 `libnfc.dll`、`liblzma-5.dll`、`libwinpthread-1.dll`,以及 mfcuk 的 `data/`。整个目录约 1.9 MB。

mfcuk 的模板目录 `data/` 必须和 `mfcuk.exe` 放在一起,否则启动时会警告找不到模板。

## 环境

- MSYS2(`C:\msys64`),mingw-w64 gcc 16、cmake、ninja
- 只装了 64 位工具链

## 对上游源码的两处补丁

1. **libnfc `CMakeLists.txt`**:上游在 Windows 主机上强制 `-m32`,本机没有 32 位工具链,删掉这几行,改成 64 位。
2. **mfoc `src/mfoc.h` / `src/mfoc.c`**:`usage(FILE *, int errno)` 的参数名 `errno` 在 Windows 上会被宏展开,改成 `exitcode`。
3. **libnfc `LIBNFC_SYSCONFDIR`**:上游 CMake 在 Windows 分支里先生成 `config.h` 再设变量,导致宏为空;配置时显式传 `-DLIBNFC_SYSCONFDIR=...`。

## 构建步骤

libnfc:

```bash
export PATH=/mingw64/bin:$PATH
cd src/libnfc-libnfc-1.8.0
mkdir build-win && cd build-win
cmake -G Ninja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_C_FLAGS="-Wno-error=incompatible-pointer-types -Wno-error=int-conversion" \
  -DLIBNFC_SYSCONFDIR=D:/nfc-tool/tools/config \
  -DLIBNFC_DRIVER_PN53X_USB=OFF -DLIBNFC_DRIVER_ACR122_USB=OFF \
  -DLIBNFC_DRIVER_PCSC=OFF -DLIBNFC_DRIVER_ACR122_PCSC=OFF \
  -DLIBNFC_DRIVER_ACR122S=OFF -DLIBNFC_DRIVER_ARYGON=OFF \
  -DCMAKE_INSTALL_PREFIX=/d/nfc-tool/tools ..
ninja nfc
```

mfoc(在 `src/mfoc-mfoc-0.10.7/src` 下):

```bash
printf '#define PACKAGE_VERSION "0.10.7"\n' > config.h
gcc -O2 -std=c99 -o ../../../bin/mfoc.exe \
  mfoc.c crapto1.c crypto1.c mifare.c nfc-utils.c \
  -I. -I../../libnfc-libnfc-1.8.0/include -I../../libnfc-libnfc-1.8.0 \
  -I../../libnfc-libnfc-1.8.0/contrib/win32 \
  -L../../libnfc-libnfc-1.8.0/build-win/libnfc -lnfc -lws2_32
```

mfcuk(同样在源码的 `src/` 下,先单独编 libnfc 的 `utils/mifare.c` 和 `utils/nfc-utils.c` 成 .o,再一起链接):

```bash
printf '#define PACKAGE_NAME "mfcuk"\n#define PACKAGE_VERSION "0.3.8"\n' > config.h
gcc -O2 -std=c99 -DWIN32 -o ../../../bin/mfcuk.exe \
  mfcuk.c mfcuk_mifare.c mfcuk_utils.c mfcuk_finger.c \
  crapto1.c crypto1.c xgetopt.c mifare.o nfc-utils.o \
  -I. -I../../libnfc-libnfc-1.8.0/include -I../../libnfc-libnfc-1.8.0 \
  -I../../libnfc-libnfc-1.8.0/contrib/win32 \
  -L../../libnfc-libnfc-1.8.0/build-win/libnfc -lnfc -lws2_32
```

最后把 `libnfc.dll` 和 mfcuk 的 `data/` 一起放进 `bin/`。

mfoc-hardnested:

```bash
# 源码解压后,先在仓库根目录生成 config.h(mingw 分支读取的是它)
cp src/config_w.h config.h
bash tools/build-mfoc-hardnested.sh     # 直接用 MSYS2 的 bash 跑
```

脚本里几个关键点:

- 头文件用 `-iquote` 而不是 `-I` 指向源码目录,否则项目自带的 `windows.h` 会把系统 `windows.h` 挡掉
- SIMD 变体分别用 `-msse2`、`-mavx`、`-mavx2`、`-mavx512f -mavx512bw` 编译,运行时由 `hardnested_cpu_dispatch` 选择
- 链接 `-lnfc -llzma -lwinpthread -lws2_32 -lm`,产物约 1.1 MB

mfoc-hardnested 的源码不需要打补丁,只需要 `config.h` 和正确的 include 顺序。

## 验证

```bash
cd tools/bin
./mfoc.exe -h
LIBNFC_DEVICE=pn532_uart:COM3:115200 ./mfoc.exe -O test.mfd
LIBNFC_DEVICE=pn532_uart:COM3:115200 ./mfcuk.exe -C -R 0:A -S 250 -s 250
```

读卡器被网页服务占用时,先停服务或让网页断开,否则 libnfc 打不开串口。

## 许可证

三个都是 GPL-2.0-or-later(libnfc 是 LGPL-3.0-or-later)。`bin/` 不随仓库分发;如果要打包发给别人,必须同时提供这里对应的源码和许可证文本,详见仓库根目录的 `THIRD_PARTY_NOTICES.md`。
