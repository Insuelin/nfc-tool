# nfc-tool

中文 | [English](README.en.md)

本地 PN532 读卡工作台。Python 直接实现 PN532 的 HSU 串口协议，不依赖 libnfc 就能读卡；浏览器页面负责操作，跑在 `127.0.0.1`。Windows 自用。

## 支持的读卡器

- PN532 模块，HSU/UART 模式（实测 CH340 转串口，v1.6 固件）
- 串口 115200 8N1，默认 COM3
- 不支持 ACR122U / PCSC，也不支持 PN532 的 I2C、SPI 接法

## 支持的卡片

| 卡型 | SAK | 块数 | 读取 | 写入 |
|---|---:|---:|---|---|
| MIFARE Classic 1K | 0x08 | 64 | 密钥已知时可读 | 可写 |
| MIFARE Classic 4K | 0x18 | 256 | 密钥已知时可读 | 可写 |
| MIFARE Mini | 0x09 | 20 | 密钥已知时可读 | 可写 |
| 其他 ISO/IEC 14443A 卡 | 其他 | — | 只能读到 UID/ATQA/SAK | 不支持 |

不支持：125 kHz ID 卡、ISO 15693、UHF、DESFire / NTAG / Ultralight 的存储操作、NFC-B/F/V、卡模拟与嗅探。

## 魔法卡

| 卡型 | 改写块 0 的方式 | 次数 |
|---|---|---|
| UID (Gen1A) | 0x40 / 0x43 后门 | 可反复写 |
| CUID (Gen2) | 普通认证后写 | 可反复写 |
| FUID | 普通认证后写 | 只有一次，写完全锁定 |
| UFUID | 普通认证后写 | 锁定前可反复写；本工具没有锁定/解锁命令 |
| 原卡 | 不可写 | — |

只有 Gen1A 能无损判定出来（`0x40`/`0x43` 有应答）。CUID、FUID、UFUID 和原卡在读取层长得一样，只能靠写块 0 试；这个测试对 FUID 是消耗性的，会花掉唯一那次写入。

## 功能

- 连接/断开、查固件版本
- 读卡：UID、ATQA、SAK、卡型、块 0、类型判定，一次读完整卡
- 密钥扫描：内置 20 个常见出厂/厂商密钥，先试 Key A 再试 Key B
- 整卡 dump：没密钥的扇区留空（全零）
- 整卡写回：跳过没密钥的扇区，尾块最后写，每块写后回读校验
- 写块 0：Gen1A 走后门，CUID/FUID/UFUID 走普通认证写入，写完自动判断可反复写还是只能写一次
- 破解：调用外部的 mfoc（nested）、mfcuk（darkside）、mfoc-hardnested（hardnested）
- 源卡 / 目标卡两个槽位，分别看密钥和数据
- 保存/加载 `.mfd`，十六进制和 ASCII 对照
- 命令行：`inspect_card.py`（读完整张卡）、`diag.py`（开 RF 场轮询找卡）

## 依赖

- Python 3.10+（开发机是 3.14）
- `pyserial`
- 外部破解程序：`mfoc.exe`、`mfcuk.exe`、`mfoc-hardnested.exe` 和 `libnfc.dll`，默认放在仓库的 `tools/bin`，由 `tools/src` 里的源码编译得到（这些二进制不进 git）

破解时会自动设 `LIBNFC_DEVICE=pn532_uart:COM3:115200`，运行期间读卡器由外部程序独占。

## 用法

```
pip install pyserial
python app.py
```

浏览器打开 <http://127.0.0.1:8770>，选串口，连接，然后读卡。

命令行：

```
python inspect_card.py COM3
python diag.py COM3
```

## 已知限制

- 只走 ISO/IEC 14443A 106 kbps；卡型只按 SAK 判断，MIFARE Plus 或兼容卡如果也报 0x08/0x18 会被当成 Classic，能不能认证没验证过。
- 密钥只有内置的 20 个，不支持自定义字典。
- dump 里没有密钥的扇区是全零，写回时也会跳过这些扇区。
- 非 Gen1A 写块 0 需要先有扇区 0 的密钥。
- 访问位不一致的扇区会整扇区跳过。
- 写尾块（含新密钥）后回读校验用的还是旧密钥，可能误报“回读不一致”。这种时候以卡里实际数据为准。
- 破解需要独占串口，跑的时候页面读不了卡；外部程序目录固定为 `tools/bin`，波特率固定 115200。
- 页面只监听 `127.0.0.1`，没有鉴权，别往公网暴露。

## 许可证

本项目代码用 **GPL-3.0**，见 [LICENSE](LICENSE)。选 GPLv3 是因为要带着 mfoc / mfcuk / mfoc-hardnested 这些 GPL 程序一起分发，统一成 GPL 最省事。第三方程序和许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 免责声明

只拿它读自己拥有或已获授权测试的卡。别用在没授权的门禁卡、交通卡、支付卡或别人的卡上。用破解工具产生的后果自己承担。
