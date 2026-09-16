# HookScanTool

**Windows 进程 Hook 扫描器** — 检测运行中 Windows 进程里的 IAT、EAT 与内联 Hook。

English documentation: [README.md](README.md)。

## 概述

HookScanTool 是一款 Windows 安全/恶意软件分析工具，用于扫描运行中进程的 API Hook，支持检测三类 Hook：

- **IAT Hook** — 导入地址表篡改(函数指针被重定向到其他模块)
- **EAT Hook** — 导出地址表篡改(内存中的导出 RVA 与磁盘不一致)
- **内联 Hook** — 函数序言补丁(JMP/CALL/PUSH+RET/MOV+JMP 跳转到其他模块)

工具将内存中的函数代码与磁盘 DLL 逐字节比对，并使用 [Zydis](https://github.com/zyantific/zydis) 做指令级反汇编。Hook 链路会穿越多级 JMP/CALL 间接跳转，揭示最终目标。Hook 目标地址所属模块可通过用户提供的 SHA-256 签名库标注为已知模块(如安全软件的合法 Hook)。

## 功能

- **GUI 模式** — Dear ImGui + DirectX 11 界面：进程树、模块分流面板、Hook 列表、链路查看器、一键后台恢复
- **CLI 模式** — 命令行扫描，支持 JSON/CSV/SARIF 输出与自动恢复
- **持续监控** — `--watch` 模式轮询进程，发现新增 Hook 立即告警
- **全量扫描** — `--deep` 模式并行扫描所有可访问进程
- **选择性扫描** — 侦察模块列表带可疑度评分，可只扫可疑模块
- **模块分流** — 可疑度评分体系(路径、名称、WoW64 启发式)
- **Hook 链路追踪** — 跟随 JMP/CALL/PUSH+RET/MOV+JMP 间接跳转到最终目标
- **Hook 恢复** — 线程挂起、写入前 TOCTOU 校验、写入后回读校验、部分写入失败自动回滚
- **签名检测** — SHA-256 已知签名库，标注属于已知模块的 Hook 目标
- **WoW64 支持** — 64 位扫描器经 `NtWow64ReadVirtualMemory64` 扫描 32 位进程
- **API Set 感知** — `api-ms-*` 导入会解析到归属模块并用其导出表验证
- **JSON / CSV / SARIF 导出** — 带 `schema_version` 版本号、UTF-8 安全、严格解析器可读

## 构建

### 环境要求

- **编译器**：MSVC 2022+(或 MinGW-w64 GCC)
- **CMake**:3.20+
- **依赖**：Zydis 4.0.0 + Zycore、Dear ImGui 1.91.8(已在 `deps/` 内，许可证见各目录)

### MSVC 构建

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### MinGW 构建

```bash
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

或使用脚本:`./build.sh [msvc|mingw]`(VS Insiders 需设 `VS_GEN="Visual Studio 18 2026"`)。

### 产物

| 目标 | 路径 | 说明 |
|------|------|------|
| `hookscan_cli.exe` | `build/Release/`(MSVC)或 `build/`(MinGW) | 命令行工具 |
| `hookscantool.exe` | 同上 | GUI 程序 |

## 运行测试

```bash
cmake -B build -DHOOKSCAN_BUILD_TESTS=ON   # 按需追加生成器/架构参数
cmake --build build --config Release
./build/Release/hookscan_test.exe          # MinGW 为 ./build/hookscan_test.exe
```

共 207 个测试，覆盖 PE 解析、模块评分、内联指令匹配、CLI 参数解析、JSON/CSV/SARIF 写出、EAT 别名匹配与签名子系统。

## 使用

### GUI

以**管理员身份**运行 `hookscantool.exe` 可获得完整进程访问能力。

1. 在进程树(左侧)选择目标进程
2. 点击 **Scan Selected** 全量扫描，或在模块分流面板勾选指定模块
3. 在 Hook 列表中查看检测结果，用 **Export JSON/CSV** 导出报告
4. 点击某个 Hook 查看链路追踪(右下)
5. 用 **Restore Hook** 恢复原始字节(后台执行，UI 不卡顿)

### CLI

```bash
# 列出运行中的进程
hookscan_cli.exe --list

# 扫描指定进程
hookscan_cli.exe 1234

# 扫描并写出报告(JSON / CSV / SARIF 相互独立)
hookscan_cli.exe 1234 --json report.json --csv report.csv --sarif report.sarif

# 列出模块及可疑度评分
hookscan_cli.exe 1234 --modules

# 过滤模块:s=只看可疑,a=全部,m=非微软
hookscan_cli.exe 1234 --modules --filter s

# 按索引扫描指定模块
hookscan_cli.exe 1234 --scan-module 5

# 恢复某个检测到的 Hook(会二次确认)
hookscan_cli.exe 1234 --restore 0

# 监控进程:默认每 30 秒重扫,只告警"新增"Hook
hookscan_cli.exe 1234 --watch
hookscan_cli.exe 1234 --watch --interval 10 --json watch.json

# 并行扫描所有可访问进程(默认 4 个工作线程)
hookscan_cli.exe --deep
hookscan_cli.exe --deep --jobs 8 --filter s --json deep.json   # 只列出有 Hook 的进程

# 加载已知签名库(默认读取当前目录的 signatures.txt)
hookscan_cli.exe 1234 --sigs signatures.txt
```

**--watch 退出码**:`0` 正常停止,`1` 发现过新 Hook(便于接入脚本/CI),`2` 目标进程丢失。

## JSON 输出

报告为带 schema 版本的 UTF-8 JSON:

```json
{
  "schema_version": 1,
  "pid": 1234,
  "process_name": "target.exe",
  "hook_count": 1,
  "modules_scanned": 14,
  "scan_time_ms": 210,
  "truncated": false,
  "hooks": [
    {
      "module": "user32.dll",
      "function": "MessageBoxW",
      "type": "INLINE",
      "original_addr": "0x00007FFA12345678",
      "current_addr": "0x00007FFA98765432",
      "restorable": true,
      "signature": "",
      "chain_depth": 2,
      "original_bytes": "48894C2408",
      "hooked_bytes": "E9CD123400",
      "chain": [
        {"address": "0x00007FFA98765432", "disasm": "jmp 0x..."}
      ]
    }
  ]
}
```

`--deep` 输出 `{"schema_version": 1, "process_count": N, "processes": [ ... ]}`,内含同样的报告对象。

## 签名库

签名库是纯文本文件(默认 `signatures.txt`,格式见 `signatures.example.txt`):

```
# <DLL 文件的 sha256> <标签>
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 our-edit-hook-dll
```

当检测到的 Hook 目标地址落在某个模块内、且该模块的 SHA-256 与库中条目匹配时，该 Hook 会被打上对应标签(CLI 表格与 JSON 的 `signature` 字段可见)。计算哈希:`certutil -hashfile some.dll SHA256`。

## 可疑度评分

| 判据 | 分值 |
|------|------|
| 模块不在 Windows/Program Files | +30 |
| 名称可疑(hook、inject、patch 等) | +40 |
| 64 位进程中的 WoW64 DLL | +20 |

0-30:低风险 | 31-60:可疑 | 61-80:高危 | 81-100:严重

## 已知限制

- **内联检测深度** — 只比较每个函数的前 5 条指令，落在序言窗口之后的 Hook 不会被发现。
- **EAT 与内联的分工** — EAT 扫描只比对导出 RVA;只补丁函数体、不改导出表的 Hook 由内联扫描负责。
- **API Set 按地址验证** — 若 api-ms 导入被劫持到同归属模块的**另一个合法导出地址**，仅凭地址无法与正常转发区分。
- **截断** — Hook 缓冲写满时报告会置 `"truncated": true`,结果可能不完整。

## 管理员权限与杀软说明

- 不提权时，本会话之外的大部分进程返回 `ENGINE_ACCESS_DENIED`。完整覆盖请以**管理员身份**运行 CLI/GUI。
- 读写其他进程内存的工具天然容易被杀软启发式拦截。若被隔离，请与 Release 页公布的 SHA-256 校验和比对确认后再加白名单。

## 错误码

| 错误码 | 含义 |
|--------|------|
| `ENGINE_OK` (0) | 成功 |
| `ENGINE_ACCESS_DENIED` (-1) | 无法打开进程(请以管理员运行) |
| `ENGINE_PROCESS_NOT_FOUND` (-2) | 进程或模块未找到 |
| `ENGINE_NO_MEMORY` (-6) | 内存不足 |
| `ENGINE_SCAN_FAILED` (-7) | 通用扫描失败 |

`ENGINE_READ_ERROR`/`ENGINE_WRITE_ERROR`/`ENGINE_PACKED_DLL` 为保留码(见 `src/engine/types.h`):扫描器层面的读失败按"无 Hook"处理,加壳镜像通过每条 Hook 的 `restorable: false` 体现。

## 架构

```
src/
├── engine/          # 扫描引擎(纯 C)
│   ├── engine.h/.c        # 公共 API:扫描、侦察、恢复、JSON/CSV/SARIF 导出
│   ├── types.h            # 共享类型定义 + 错误码
│   ├── pe_parser.h/.c     # PE 头解析(内存态 + 磁盘)
│   ├── process_enum.h/.c  # 进程/模块枚举
│   ├── iat_scanner.h/.c   # IAT Hook 检测
│   ├── eat_scanner.h/.c   # EAT Hook 检测
│   ├── inline_scanner.h/.c# 内联 Hook 检测
│   ├── chain_tracer.h/.c  # Hook 链路追踪
│   ├── restore.h/.c       # Hook 恢复
│   ├── wow64.h/.c         # WoW64 支持
│   ├── sigcheck.h/.c      # 已知签名库(SHA-256,BCrypt)
│   └── module_scorer.h/.c # 可疑度评分
├── cli/
│   ├── main.c       # CLI 入口
│   └── args.c/.h    # 参数解析(有单测)
└── gui/
    ├── main.cpp             # GUI 入口 + 主循环
    ├── ui_process_tree.cpp  # 进程树面板
    ├── ui_module_list.cpp   # 模块分流面板
    ├── ui_hook_list.cpp     # Hook 列表面板 + 报告导出
    ├── ui_chain_view.cpp    # 链路查看面板
    └── ui_restore.cpp       # 恢复面板(后台线程)
```

### 扫描流水线

1. **侦察** — 枚举进程模块并为每个模块计算可疑度
2. **IAT 扫描** — 校验每个导入的函数指针是否落在预期 DLL 地址范围内(跟随导出转发；api-ms 导入用归属模块导出表验证)
3. **EAT 扫描** — 内存导出 RVA 与磁盘导出 RVA 比对(正确处理同名导出别名)
4. **内联扫描** — 用 Zydis 反汇编每个导出函数的前几条指令并与磁盘比对
5. **链路追踪** — 跟随 JMP/CALL/PUSH+RET/MOV+JMP 间接跳转到最终目标
6. **签名标注** — 对每个 Hook 目标所属模块计算 SHA-256 并查库标注

## 许可证

MIT — 见 [LICENSE](LICENSE)。第三方依赖(Zydis、Zycore、Dear ImGui)以各自的 MIT 许可证随仓库 vendor 于 `deps/` 目录。
