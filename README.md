# snowtrace-scan

> 在雪地里，一切经过都会留下痕迹。——名字借自《三体·黑暗森林》的雪地工程（the Snow Project）
>
> APK 也是一片雪地：SDK 再会藏，穿过 dex 总会留下类名与库文件的足迹。snowtrace 只负责把这些足迹如实拓印下来。

**事实层 Android APK 扫描器**：静态扫描 APK，输出带完整证据链的第三方 SDK / 权限 / 组件发现报告。只陈述事实，不做合规判定——判定交给下游合规引擎。

## 设计原则

1. **只报事实层**：每项发现必须带证据（命中多少个类 + 样例类名 / `.so` 文件名 / 精确字符串常量），不出合规结论。
2. **三级置信度**：
   - 确定（L1）：dex 类名前缀明文命中（≥3 段包名）/ 原生库文件名命中
   - 推断（L2）：短前缀命中（1-2 段，仅限人工可信名单）、字符串常量精确匹配
   - 存疑（L3）：启发式（v0 不输出）
3. **防误报硬门槛**：不足 3 段且不在可信名单的前缀不参与归属——这一条直接消灭了初版 `com.google` 被 15 个 Google 系 SDK 主张的 13 项假阳性。

## 输出形态

一次扫描产出三份报告（写入 `--out-dir`，默认 `reports/`）：

| 文件 | 用途 |
|---|---|
| `<apk>.md` | 人读报告：Manifest 安全标志、组件 exported 统计、SDK 发现表（含样例类名证据）、权限清单 |
| `<apk>.json` | 完整结构化事实数据 |
| `<apk>.pcc.json` | **PCC `android_static` 导入格式**：可直接喂给下游隐私合规引擎（SDK 指纹命中明细 + exported 组件计数 + 危险权限信号），打通「扫 APK → 进合规引擎 → 出评分报告」流水线 |

## Quick Start

依赖：`androguard`（`pip install androguard`）+ 自备指纹库。

```bash
python scan.py /path/to/app.apk \
  --db sdklib.db \
  --whitelist common_sdks.json
```

指纹库通过三种方式解析（优先级从高到低）：

1. `--db` / `--whitelist` 显式传入；
2. 环境变量 `SNOWTRACE_SDK_DB` / `SNOWTRACE_WHITELIST`；
3. 仓库内 `data/sdklib.db` 与 `data/whitelist/common_sdks.json`。

> **指纹库说明**：SDK 指纹库（sqlite：`sdks(name, vendor, category, package_prefixes)` 表 + JSON 白名单：`name/vendor/category/packages/strings`）目前由使用者自备；项目自带的指纹数据整理完毕后会在本仓库放出。

## 准确率（ground truth 回归）

以开源播客客户端 AntennaPod 3.11.4 的 `build.gradle` 依赖清单为固定真值集，详见 [ACCURACY](ACCURACY.md)：

- **9 项发现，0 误报**（其中 2 项为 build.gradle 未直接声明、dex 中真实存在的传递依赖）
- **4 项漏报**，全部为指纹库覆盖缺口，修复路径是补指纹而非放松匹配规则
- 每次改规则必须重跑该回归集，误报/漏报变化可审计

## 已知局限（v0）

- 静态特征匹配：不检测动态加载（DexClassLoader 下载代码）、JNI/反射调用。
- 召回率由指纹库覆盖决定；漏报靠补指纹解决，不靠放松匹配规则。
- 「确定」只说明类名证据确凿，不代表 SDK 被实际调用（静态事实 ≠ 运行时行为）。
- 报告只陈述事实；SDK 是否违规取决于其版本、配置与使用方式。

## 愿景

对标 Kaamel（App 隐私合规自动化）的事实层：先让「APK 里到底有什么」变得可复现、可审计，
合规判定、评分、整改建议都建立在证据之上。
