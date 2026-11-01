# 第三方软件声明

本仓库只有自己的 Python 代码和网页，不包含、也不打包下面任何二进制或它们的源码。这些程序由使用者自己从源码编译，放在仓库的 `tools/bin`（源码放在 `tools/src`，两者都不进 git）。如果你把它们跟本工具一起分发，需要自己履行对应的许可证义务。

| 组件 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| mfoc | 0.10.7 | GPL-2.0-or-later | nested 攻击，恢复 MIFARE Classic 密钥并输出 dump |
| mfcuk | 0.3.8 | GPL-2.0-or-later | darkside 攻击 |
| mfoc-hardnested | 0.10.9 | GPL-2.0-or-later | hardnested 攻击 |
| libnfc | 1.8.0 | LGPL-3.0-or-later | 上面三个程序的运行时依赖（`libnfc.dll`） |
| liblzma | 5.8.4 | 0BSD（部分文件 GPLv2 / 公有领域） | mfoc-hardnested 的运行时依赖（`liblzma-5.dll`），随 MSYS2 的 xz 包 |
| libwinpthread | mingw-w64 | MIT | mingw-w64 运行时依赖（`libwinpthread-1.dll`） |
| crypto1_bs | — | MIT（两个文件为 GPLv2） | hardnested 暴力破解代码来源 |
| crapto1 | — | GPL-2.0-or-later | Crypto1 算法，随 mfoc / mfoc-hardnested 源码 |
| nfc-mfsetuid | 1.8.0 | BSD-2-Clause | 改 MIFARE 1K 的 UID，本工具没有调用 |
| pyserial | 3.5 | BSD-3-Clause | Python 串口库，pip 装，不在本仓库 |

## 各自的位置

- **mfoc**：<https://github.com/nfc-tools/mfoc/tree/mfoc-0.10.7>，提交 `290a0759`。`COPYING` 是 GPLv2，`src/mfoc.c` 头部写的是 "either version 2 of the License, or (at your option) any later version"，所以按 GPL-2.0-or-later 处理。GitHub 上标的 GPL-2.0 不排除 later。
- **mfcuk**：<https://github.com/nfc-tools/mfcuk/tree/mfcuk-0.3.8>，提交 `0c5aff4a`，同样带 "or any later version"。
- **mfoc-hardnested**：<https://github.com/nfc-tools/mfoc-hardnested/tree/a6007437>。里面还包含 Aram Verstegen 的 MIT 许可 bitsliced brute forcer 代码，分发这个二进制时要把那段版权和许可声明留着。
- **libnfc**：<https://github.com/nfc-tools/libnfc/releases/tag/libnfc-1.8.0>，提交 `f02ff514`。`COPYING` 是 LGPLv3，源码头写 "either version 3 of the License, or (at your option) any later version"。
- **crypto1_bs**：<https://github.com/aczid/crypto1_bs>。README 写明除 `pwpiwi_proxmark3_hard_nested.patch` 和 `libnfc_crypto1_crack.c`（GPLv2）外都是 MIT。它不是本工具直接调用的程序，代码已经并进 mfoc-hardnested。
- **crapto1**：没有独立上游仓库，看 mfoc-hardnested 的 `src/crapto1.c` / `src/crapto1.h`，许可 GPL-2.0-or-later。它和 CraptEV1 不是同一个东西，本仓库没打包 CraptEV1。
- **nfc-mfsetuid**：<https://github.com/nfc-tools/libnfc/tree/libnfc-1.8.0/examples>，BSD-2-Clause（只针对 examples，libnfc 库本身还是 LGPL）。

## 自己的代码

用 **GPL-3.0**，与 mfoc / mfcuk / mfoc-hardnested 保持一致，整包分发时不用再区分许可证。调用外部程序用的是 `subprocess`，命令行传参、读 stdout，不链接、不 import、不共享内存；这些外部程序仍各自适用它们自己的许可证，源码地址见上表。打包分发时，`tools/bin` 里的二进制和 `tools/src` 里对应的源码要一起给。

现在整包都是 GPLv3：分发时把 `tools/bin` 的二进制、`tools/src` 的对应源码和许可证文本一起给出即可，不需要再单独讨论"我们的代码和 GPL 二进制是两件事"。

## 如果要打包二进制一起发

- GPL-2.0-or-later 的部分：给对应源码（含自己打的补丁）、GPLv2 全文、版权声明；改过的文件要标出来改了哪里；给构建/安装脚本；别加跟 GPL 冲突的 EULA。不想带源码的话，至少给三年有效的书面获取要约。
- LGPL-3.0 的 libnfc：带 LGPLv3/GPLv3 文本，醒目声明用了 libnfc，给 libnfc 源码，并保证用户能换成自己改过的 `libnfc.dll`。改成静态链接的话要提供能重新链接的材料。
- mfoc 是 GPL-2.0-or-later、libnfc 是 LGPL-3.0，最稳的做法是把这俩的组合按 GPL-3.0 分发。
- **BSD-2 的 nfc-mfsetuid**：本工具没有编译也没有调用它；万一以后打包进来，保留版权声明、两条条件和免责声明。
