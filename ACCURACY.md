# snowtrace-scan · P0 验证记录（Ground Truth）

日期：2026-09-04
样本：`antennapod_3.11.4.apk`（12.3 MB，开源播客客户端，依赖可审计）
真值来源：AntennaPod GitHub 仓库 3.11.4 标签各模块 build.gradle（已逐一核对）

## 扫描结果总览

- dex 类总数：11,343（3 个 dex）
- 第三方 SDK 发现：9 项（确定 4 / 推断 5），原生库命中 0
- 权限清单：11 项（仅陈述）
- 字符串线索：0 项（符合预期：该应用无任何追踪 SDK 常量）

## 真值对照表

| 扫描发现 | 置信度 | build.gradle 声明位置 | 结论 |
|---|---|---|---|
| RxJava / RxjavaFX | 确定（io.reactivex.rxjava3，740 类） | app: `io.reactivex.rxjava3:rxjava/rxandroid` | ✅ 真阳性 |
| Glide | 确定（com.bumptech.glide，582 类） | app: `com.github.bumptech.glide:glide` | ✅ 真阳性 |
| Apache Commons | 确定（org.apache.commons，111 类） | app/net.sync: `commons-lang3`、`commons-io` | ✅ 真阳性 |
| EventBus | 确定（org.greenrobot.eventbus，34 类） | 多模块声明 | ✅ 真阳性 |
| ExoPlayer / Media3 | 推断（androidx.media3，1471 类） | playback/service: `androidx.media3:media3-exoplayer/ui` | ✅ 真阳性 |
| WorkManager | 推断（androidx.work，442 类） | net/sync/service: `androidx.work:work-runtime` | ✅ 真阳性 |
| okhttp | 推断（okhttp3，283 类） | app 等: `com.squareup.okhttp3:okhttp` | ✅ 真阳性 |
| retrofit | 推断（retrofit2，139 类） | 未直接声明，dex 中真实存在 | ✅ 事实成立（传递依赖） |
| Kotlin Coroutines | 推断（kotlinx.coroutines，288 类） | 未直接声明，dex 中真实存在 | ✅ 事实成立（传递依赖） |

**误报（False Positive）：0**（初版规则曾产生 13 项误报，均由「短前缀 + 脏指纹」导致，已通过 ≥3 段前缀规则与人工可信名单修复，见下）

**漏报（False Negative）：4**（全部为指纹库覆盖缺口，非匹配逻辑错误）

| 漏报 | 原因 | 修复路径 |
|---|---|---|
| jsoup（org.jsoup，HTML 解析库） | DB 有 `jsoup` 条目但 package_prefixes 为空 | 补 DB 指纹（crawler 管线任务） |
| balloon（com.skydoves.balloon） | DB 无此 SDK | 同上 |
| SearchPreference（com.bytehamster） | DB 无此 SDK | 同上 |
| RecyclerViewSwipeDecorator | DB 无此 SDK | 同上 |

## 准确性设计（防「扫不准闹笑话」的机制）

1. **只报事实层**：每项发现必须带证据（命中类数 + 样例类名 / .so 文件名 / 精确字符串），
   不出合规结论；报告末尾固定附局限声明。
2. **置信度分级**：
   - 确定：dex 类名前缀 ≥3 段包名明文命中（如 `com.bumptech.glide`）；
   - 推断：1-2 段短前缀且仅在人工可信名单内（如 `okhttp3`、`androidx.media3`）、
     或白名单高信号字符串精确匹配；
   - 存疑（启发式）：v0 不输出。
3. **短前缀硬门槛**：不足 3 段且不在可信名单的前缀不参与归属——
   这一条直接消灭了初版 `com.google` 被 15 个 Google 系 SDK 主张的 13 项假阳性。
4. **确定性去重**：同一命中前缀多个 SDK 名主张时，白名单来源优先；
   推断级短前缀被确定级更长前缀覆盖时并入为别名（RxJava → RxjavaFX aka）。
5. **ground truth 回归**：开源样本（AntennaPod）+ 官方依赖清单作为固定回归集，
   每次改规则必须重跑对照，误报/漏报变化可审计。

## 已知局限（v0）

- 不检测动态加载（DexClassLoader 下载代码）、JNI/反射调用。
- 指纹库覆盖决定召回：DB 3316 条中 2079 条有可用前缀；漏报靠补指纹解决，不靠放松匹配规则。
- 「确定」只说明类名证据确凿，不代表 SDK 被实际调用（静态事实 ≠ 运行时行为）。
