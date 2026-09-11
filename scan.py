#!/usr/bin/env python3
"""
snowtrace-scan — 事实层 APK 扫描器

名字来自《三体·黑暗森林》的雪地工程：在雪地里，一切经过都会留下痕迹。
APK 也是一片雪地——SDK 再会藏，穿过 dex 总会留下类名与库文件的足迹。

设计原则：
1. 只报事实层：APK 里有什么，全部带证据，不做合规判定。
2. 三级置信度：
   - 确定（L1）：dex 类名前缀明文命中（≥3 段包名）/ 原生库文件名命中
   - 推断（L2）：短前缀命中（1-2 段）、字符串/域名命中
   - 存疑（L3）：启发式（v0 不输出）
3. 每个发现必须带证据：命中了多少个类、样例类名、命中的 .so 文件名等。

用法：
    python scan.py <apk路径> [--db sdklib.db] [--whitelist common_sdks.json]
    [--out-dir reports] [--pcc/--no-pcc]
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

_REPO_DATA = Path(__file__).parent / "data"
_LOCAL_SDK_DB = "/Users/xuzhujie/Documents/MyProjects/SDK-Library/data/sdklib.db"
_LOCAL_WHITELIST = "/Users/xuzhujie/Documents/MyProjects/SDK-Library/data/whitelist/common_sdks.json"
DEFAULT_DB = os.environ.get("SNOWTRACE_SDK_DB") or (
    _LOCAL_SDK_DB if Path(_LOCAL_SDK_DB).exists() else str(_REPO_DATA / "sdklib.db")
)
DEFAULT_WHITELIST = os.environ.get("SNOWTRACE_WHITELIST") or (
    _LOCAL_WHITELIST if Path(_LOCAL_WHITELIST).exists() else str(_REPO_DATA / "whitelist" / "common_sdks.json")
)

# ── 原生库名 → SDK 映射（人工维护的小表，证据 = .so 文件名本身）────────────
NATIVE_LIB_TABLE = {
    "libagora-rtc-sdk": ("Agora RTC", "agora.io", "rtc"),
    "libagora-ffmpeg": ("Agora RTC", "agora.io", "rtc"),
    "libBugly": ("腾讯 Bugly", "Tencent", "crash"),
    "libbugly": ("腾讯 Bugly", "Tencent", "crash"),
    "libwechatmm": ("微信 OpenSDK", "Tencent", "social"),
    "libwechatsdk": ("微信 OpenSDK", "Tencent", "social"),
    "libumeng": ("友盟", "Alibaba", "analytics"),
    "libapp.so": ("Flutter", "Google", "framework"),
    "libflutter": ("Flutter", "Google", "framework"),
    "libreactnativejni": ("React Native", "Meta", "framework"),
    "libhermes": ("Hermes JS Engine", "Meta", "framework"),
    "libjsc": ("JavaScriptCore", "WebKit", "framework"),
    "libfbjni": ("fbjni (React Native)", "Meta", "framework"),
    "libfolly": ("Folly (React Native)", "Meta", "framework"),
    "libcrashlytics": ("Firebase Crashlytics", "Google", "crash"),
    "libfirebase": ("Firebase", "Google", "analytics"),
    "libgcore": ("Google Core", "Google", "other"),
    "libpairipcore": ("Stripe 支付", "Stripe", "payment"),
    "libjl_mp3_dec": ("穿山甲 Pangle", "字节跳动", "ads"),
    "libpangle": ("穿山甲 Pangle", "字节跳动", "ads"),
    "libsscronet": ("Cronet 网络栈", "Google", "network"),
    "libtnet": ("阿里百川 tnet", "Alibaba", "network"),
    "libsgmain": ("阿里聚安全", "Alibaba", "security"),
    "libsecurityguard": ("阿里聚安全", "Alibaba", "security"),
    "libalisecurity": ("阿里聚安全", "Alibaba", "security"),
    "libwindmill": ("字节 Windmill", "字节跳动", "other"),
    "libbdasr": ("百度语音", "Baidu", "other"),
    "libBaiduMapSDK": ("百度地图", "Baidu", "map"),
    "liblocSDK": ("百度定位", "Baidu", "location"),
    "libAMapSDK": ("高德地图", "阿里巴巴", "map"),
    "libamap": ("高德地图", "阿里巴巴", "map"),
    "libgsbaidu": ("百度统计", "Baidu", "analytics"),
    "libdu": ("百度 DU SDK", "Baidu", "other"),
    "libheytap": ("OPPO HeyTap", "OPPO", "push"),
    "libmivenpush": ("vivo Push", "vivo", "push"),
    "libmi_push": ("小米 Push", "小米", "push"),
    "libxpush": ("信鸽推送", "Tencent", "push"),
    "libhyphenate": ("环信 IM", "环信", "im"),
    "libRongIM": ("融云 IM", "融云", "im"),
    "libjnidispatch": ("JNA", "JNA", "other"),
    "libsqlcipher": ("SQLCipher", "Zetetic", "database"),
    "librealm": ("Realm DB", "MongoDB", "database"),
    "libobjectbox": ("ObjectBox", "ObjectBox", "database"),
    "libopencv": ("OpenCV", "OpenCV", "other"),
    "libffmpeg": ("FFmpeg", "FFmpeg", "media"),
    "libexoplayer": ("ExoPlayer", "Google", "media"),
    "libijkffmpeg": ("ijkplayer", "bilibili", "media"),
    "libijkplayer": ("ijkplayer", "bilibili", "media"),
    "libliteav": ("腾讯云 TRTC/播放器", "Tencent", "rtc"),
    "libtxffmpeg": ("腾讯视频播放器", "Tencent", "media"),
    "libmars": ("微信 Mars", "Tencent", "network"),
    "libmmkv": ("MMKV", "Tencent", "database"),
    "libmmkvdemo": ("MMKV", "Tencent", "database"),
}

# 短前缀人工可信名单：这些 1-2 段前缀指向唯一知名库，命中为「推断」级
SHORT_PREFIX_ALLOWLIST = {
    "okhttp3": "okhttp",
    "okhttp3.": "okhttp",
    "retrofit2": "Retrofit",
    "okio": "Okio",
    "androidx.media3": "ExoPlayer / Media3",
    "kotlinx.coroutines": "Kotlin Coroutines",
    "com.facebook": "Facebook SDK",
}

MIN_SEGMENTS = 3  # 少于 3 段且不在白名单内的前缀不用于正向归属，避免 "com.google" 级误报


def load_fingerprints(db_path: str, whitelist_path: str) -> list[dict]:
    """从 sdklib.db + 白名单 JSON 加载指纹，按规范化名称去重合并。"""
    by_name: dict[str, dict] = {}

    def add_entry(name, vendor, category, prefixes, source_id, strings=None):
        key = re.sub(r"\s+", " ", name.strip().lower())
        if not key:
            return
        ent = by_name.setdefault(key, {
            "name": name.strip(), "vendor": vendor or "", "category": category or "other",
            "prefixes": set(), "sources": set(), "strings": set(),
        })
        # 白名单来源的名称更规范，用它替换 DB 里的显示名
        if source_id.startswith("whitelist:"):
            ent["name"] = name.strip()
        for p in prefixes or []:
            p = p.strip().strip(".")
            if p and len(p) >= 5:
                ent["prefixes"].add(p)
        for s in strings or []:
            # 只保留高信号字符串常量：长度 ≥12 且含 - _ : / 之一，避免 "ads"、"google.com" 这类噪音
            if isinstance(s, str) and len(s) >= 12 and any(c in s for c in "-_:/"):
                ent["strings"].add(s)
        ent["sources"].add(source_id)

    db = sqlite3.connect(db_path)
    cur = db.cursor()
    for name, vendor, cat, prefixes in cur.execute(
        "SELECT name, vendor, category, package_prefixes FROM sdks"
    ):
        try:
            plist = json.loads(prefixes) if prefixes else []
        except Exception:
            continue
        add_entry(name, vendor, cat, plist, f"sdklib.db:{name}")

    if Path(whitelist_path).exists():
        wl = json.loads(Path(whitelist_path).read_text())
        for item in wl:
            add_entry(item.get("name", ""), item.get("vendor"), item.get("category"),
                      item.get("packages"), f"whitelist:{item.get('sdk_id', '')}",
                      strings=item.get("strings"))

    # 丢弃既无前缀又无字符串的条目
    return [e for e in by_name.values() if e["prefixes"] or e["strings"]]


def all_segments(prefix: str) -> int:
    return len([s for s in prefix.split(".") if s])


# 短前缀人工可信名单：1-2 段但指向唯一知名库，命中为「推断」级
SHORT_PREFIX_ALLOWLIST = {
    "okhttp3": "okhttp",
    "retrofit2": "Retrofit",
    "okio": "Okio",
    "androidx.media3": "ExoPlayer / Media3",
    "kotlinx.coroutines": "Kotlin Coroutines",
    "com.facebook": "Facebook SDK",
    "io.reactivex": "RxJava",
    "com.stripe": "Stripe",
    "com.alipay": "支付宝",
    "com.unity3d": "Unity3D",
    "com.umeng": "友盟",
    "androidx.work": "WorkManager",
    "org.jsoup": "jsoup",
}

MIN_SEGMENTS = 3  # 少于 3 段且不在名单内的前缀不用于正向归属，避免 "com.google" 级误报


def usable_prefixes(ent: dict) -> list[tuple[str, str]]:
    """返回 [(prefix, confidence)]，只保留 ≥3 段或在人工可信名单内的前缀。"""
    out = []
    for p in ent["prefixes"]:
        if all_segments(p) >= MIN_SEGMENTS:
            out.append((p, "确定"))
        elif p in SHORT_PREFIX_ALLOWLIST:
            out.append((p, "推断"))
    return out


def match_prefixes(classes: list[str], fingerprints: list[dict]):
    """对排序后的类名列表做前缀区间匹配。返回 {sdk_key: match_info}"""
    classes.sort()
    results: dict[str, dict] = {}
    for ent in fingerprints:
        cands = usable_prefixes(ent)
        if not cands:
            continue
        best = None  # (prefix, count, samples, conf)
        for prefix, conf in cands:
            lo = bisect.bisect_left(classes, prefix)
            hi = bisect.bisect_right(classes, prefix + "\xff")
            count, samples = 0, []
            for cls in classes[lo:hi]:
                if cls == prefix or cls.startswith(prefix + ".") or cls.startswith(prefix + "$"):
                    count += 1
                    if len(samples) < 3:
                        samples.append(cls)
            if count and (best is None or (count, len(prefix)) > (best[1], len(best[0]))):
                best = (prefix, count, samples, conf)
        if best:
            prefix, count, samples, conf = best
            results[id(ent)] = {
                "sdk": ent, "matched_prefix": prefix, "class_count": count,
                "samples": samples, "confidence": conf,
                "evidence": f"dex 类名前缀 `{prefix}` 命中 {count} 个类",
            }
    return results


def dedup_by_prefix(matches: dict) -> list[dict]:
    """同一命中前缀被多个 SDK 名主张时合并：优先白名单来源，其次名字最短者。
    另外：推断级短前缀若被确定级更长前缀完全覆盖（同族库），并入后者并记为别名。"""
    groups: dict[str, list[dict]] = {}
    for m in matches.values():
        groups.setdefault(m["matched_prefix"], []).append(m)
    merged = []
    for prefix, ms in groups.items():
        ms.sort(key=lambda m: (
            0 if any(s.startswith("whitelist:") for s in m["sdk"]["sources"]) else 1,
            len(m["sdk"]["name"]),
        ))
        keep = ms[0]
        aliases = sorted({m["sdk"]["name"] for m in ms[1:]})
        if aliases:
            keep["aliases"] = aliases
        merged.append(keep)

    final = []
    for m in merged:
        container = next((o for o in merged
                          if o is not m
                          and m["confidence"] == "推断"
                          and o["confidence"] == "确定"
                          and o["matched_prefix"].startswith(m["matched_prefix"] + ".")
                          and m["class_count"] <= o["class_count"]), None)
        if container:
            container.setdefault("aliases", [])
            if m["sdk"]["name"] not in container["aliases"]:
                container["aliases"].append(m["sdk"]["name"])
            continue
        final.append(m)
    return final


def match_native_libs(so_files: list[str]) -> list[dict]:
    hits = []
    for so in so_files:
        base = so.rsplit("/", 1)[-1]
        for key, (name, vendor, cat) in NATIVE_LIB_TABLE.items():
            if key.lower() in base.lower():
                hits.append({
                    "name": name, "vendor": vendor, "category": cat,
                    "confidence": "确定",
                    "evidence": f"原生库文件 `{so}`",
                })
                break
    # 去重
    seen, out = set(), []
    for h in hits:
        if h["name"] not in seen:
            seen.add(h["name"])
            out.append(h)
    return out


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyze_manifest(apk) -> tuple[dict, dict]:
    """提取 manifest 安全标志 + 组件 exported 统计。

    返回 (flags, exported_stats)：
    - flags 只包含 APK 里实际声明的属性（缺失的键不出现，避免下游误判）。
    - exported_stats 每类组件: total / exported_true / exported_false /
      implicit（缺 exported 属性但有 intent-filter，API<31 默认为 true）/
      missing_no_filter（缺属性且无 intent-filter）。
    """
    flags: dict = {}
    keys = ("activities", "services", "receivers", "providers")
    stats = {k: {"total": 0, "exported_true": 0, "exported_false": 0,
                 "implicit": 0, "missing_no_filter": 0} for k in keys}
    try:
        root = apk.get_android_manifest_xml()
        app = root.find("application")
        if app is None:
            return flags, stats
        for attr in ("debuggable", "allowBackup", "usesCleartextTraffic"):
            v = app.get(ANDROID_NS + attr)
            if v is not None:
                flags[attr] = v.strip().lower() in ("true", "1")
        for tag, key in (("activity", "activities"), ("service", "services"),
                         ("receiver", "receivers"), ("provider", "providers")):
            for el in app.findall(tag):
                st = stats[key]
                st["total"] += 1
                v = el.get(ANDROID_NS + "exported")
                has_filter = el.find("intent-filter") is not None
                if v is None:
                    if has_filter:
                        st["implicit"] += 1
                    else:
                        st["missing_no_filter"] += 1
                elif v.strip().lower() in ("true", "1"):
                    st["exported_true"] += 1
                else:
                    st["exported_false"] += 1
    except Exception as e:
        print(f"[warn] manifest 标志提取失败: {e}", file=sys.stderr)
    return flags, stats


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def scan(apk_path: str, db_path: str, whitelist_path: str) -> dict:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(apk_path)
    manifest_flags, exported_stats = analyze_manifest(apk)
    report = {
        "apk": str(apk_path),
        "package": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": sorted(set(apk.get_permissions())),
        "components": {
            "activities": len(apk.get_activities()),
            "services": len(apk.get_services()),
            "receivers": len(apk.get_receivers()),
            "providers": len(apk.get_providers()),
        },
        "manifest_flags": manifest_flags,
        "exported_components": exported_stats,
        "total_classes": 0,
        "sdk_findings": [],
        "native_findings": [],
        "limitations": [
            "仅做静态特征匹配：dex 类名前缀、原生库文件名、字符串。不检测动态加载（DexClassLoader 下载代码）、JNI 反射调用。",
            "短前缀（1-2 段包名）命中为「推断」级，可能与 App 自身代码混淆重名，需人工复核样例类名。",
            "报告只陈述事实，不做合规判定；SDK 是否违规取决于其版本、配置与使用方式。",
            "扫描名单遵循隔离原则：不扫描在职雇主同赛道竞对产品。",
        ],
    }

    # 1. 提取全部 dex 类名
    classes: list[str] = []
    dex_names = [f for f in apk.get_files() if f.endswith(".dex")]
    for dname in dex_names:
        try:
            d = DEX(apk.get_file(dname))
            classes.extend((c[1:] if c.startswith("L") else c).replace("/", ".").rstrip(";")
                           for c in d.get_classes_names())
        except Exception as e:
            print(f"[warn] 解析 {dname} 失败: {e}", file=sys.stderr)
    report["total_classes"] = len(classes)
    report["dex_files"] = dex_names

    # 2. 加载指纹并匹配 + 同前缀多主张合并
    fingerprints = load_fingerprints(db_path, whitelist_path)
    matches = dedup_by_prefix(match_prefixes(classes, fingerprints))

    findings = []
    for m in matches:
        sdk = m["sdk"]
        findings.append({
            "name": sdk["name"],
            "vendor": sdk["vendor"],
            "category": sdk["category"],
            "confidence": m["confidence"],
            "matched_prefix": m["matched_prefix"],
            "class_count": m["class_count"],
            "sample_classes": m["samples"],
            "evidence": m["evidence"],
            "sources": sorted(sdk["sources"])[:3],
            "aliases": m.get("aliases", []),
        })
    findings.sort(key=lambda f: ({"确定": 0, "推断": 1}[f["confidence"]], -f["class_count"]))
    report["sdk_findings"] = findings

    # 3. 原生库
    so_files = [f for f in apk.get_files() if f.endswith(".so")]
    report["native_findings"] = match_native_libs(so_files)
    report["native_lib_count"] = len(so_files)
    report["native_lib_names"] = sorted({s.rsplit("/", 1)[-1] for s in so_files})[:30]

    # 4. 字符串线索（白名单高信号常量的精确匹配，推断级；dex 前缀已命中的 SDK 不再重复）
    string_findings = []
    try:
        dex_strings = set()
        for dname in dex_names:
            d = DEX(apk.get_file(dname))
            for s in d.get_strings():
                dex_strings.add(s.decode("utf-8", "ignore") if isinstance(s, bytes) else s)
        matched_sdk_keys = {id(m["sdk"]) for m in matches}
        for ent in fingerprints:
            if id(ent) in matched_sdk_keys or not ent["strings"]:
                continue
            hits = sorted(s for s in ent["strings"] if s in dex_strings)[:2]
            if hits:
                string_findings.append({
                    "name": ent["name"], "vendor": ent["vendor"], "category": ent["category"],
                    "confidence": "推断",
                    "evidence": "dex 字符串精确匹配: " + " ; ".join(f"`{h}`" for h in hits),
                })
        string_findings.sort(key=lambda f: f["name"])
    except Exception as e:
        print(f"[warn] 字符串提取失败: {e}", file=sys.stderr)
    report["string_findings"] = string_findings

    return report


def emit_pcc_static(r: dict) -> dict:
    """生成 PCC android_static 导入格式。

    契约依据 Privacy-Compliance-Center/privacy_agent_core/android_tool_import.py
    的 normalize_static_json：
    - tool / package_name / version_name / version_code / min_sdk_version / target_sdk_version
    - permissions[] → 权限清单 + 危险权限审查信号
    - sdks[] → SDK 清单已盘点信号（空清单也算盘点完成）
    - sdk_fingerprint_matches[] → 指纹命中明细（snowtrace 的证据层）
    - manifest{debuggable,allowBackup,usesCleartextTraffic} → 只放 APK 实际声明的键
    - components.{activities,services,receivers,providers} → PCC 按【exported 计数】解读
    - implicit_exported_* / missing_exported_* → 组件 exported 属性分类计数
    """
    ec = r["exported_components"]
    sdk_matches = []
    for f in r["sdk_findings"]:
        sdk_matches.append({
            # PCC release gate 契约：sdk_id + status + confidence(0..1 float)
            "sdk_id": re.sub(r"\s+", "_", f["name"])[:64],
            "name": f["name"],
            "vendor": f["vendor"], "category": f["category"],
            "status": "unknown",  # 事实层不做合规判定
            "confidence": 0.99 if f["confidence"] == "确定" else 0.5,
            "confidence_label": f["confidence"],
            "match_type": "dex_class_prefix",
            "matched_prefix": f["matched_prefix"], "class_count": f["class_count"],
            "sample_classes": f["sample_classes"],
        })
    for f in r["native_findings"]:
        sdk_matches.append({
            "sdk_id": re.sub(r"\s+", "_", f["name"])[:64],
            "name": f["name"],
            "vendor": f["vendor"], "category": f["category"],
            "status": "unknown",
            "confidence": 0.99,
            "confidence_label": f["confidence"],
            "match_type": "native_lib",
            "evidence": f["evidence"],
        })
    payload = {
        "tool": "snowtrace",
        "tool_version": "0.2",
        "package_name": r["package"],
        "version_name": r.get("version_name") or "",
        "version_code": _to_int(r.get("version_code")) or 0,
        "min_sdk_version": _to_int(r.get("min_sdk")),
        "target_sdk_version": _to_int(r.get("target_sdk")),
        "permissions": r["permissions"],
        "sdks": [f["name"] for f in r["sdk_findings"]] + [f["name"] for f in r["native_findings"]],
        "sdk_fingerprint_matches": sdk_matches,
        "manifest": r["manifest_flags"],
        "components": {
            "activities": ec["activities"]["exported_true"],
            "services": ec["services"]["exported_true"],
            "receivers": ec["receivers"]["exported_true"],
            "providers": ec["providers"]["exported_true"],
        },
        "implicit_exported_activities": ec["activities"]["implicit"],
        "implicit_exported_services": ec["services"]["implicit"],
        "implicit_exported_receivers": ec["receivers"]["implicit"],
        "implicit_exported_providers": ec["providers"]["implicit"],
        "missing_exported_activities": ec["activities"]["missing_no_filter"],
        "missing_exported_services": ec["services"]["missing_no_filter"],
        "missing_exported_receivers": ec["receivers"]["missing_no_filter"],
        "missing_exported_providers": ec["providers"]["missing_no_filter"],
        "component_totals": {k: v["total"] for k, v in ec.items()},
        "notes": [
            "snowtrace 事实层扫描：只陈述 APK 内可见特征，不做合规判定。",
            "components.* 为显式 exported=true 计数；implicit_* 为缺 exported 属性但带 intent-filter（API<31 默认导出）；missing_* 为缺属性且无 intent-filter。",
            "扫描名单遵循隔离原则：不扫描在职雇主同赛道竞对产品。",
        ],
    }
    # None 值字段会让下游 gate 计算混乱，直接剔除
    return {k: v for k, v in payload.items() if v is not None}


def render_markdown(r: dict) -> str:
    lines = []
    lines.append(f"# 隐私体检报告（事实层 · P0）\n")
    lines.append(f"**被测应用**：`{r['package']}` v{r['version_name']} (versionCode {r['version_code']})")
    lines.append(f"**文件**：`{Path(r['apk']).name}`")
    lines.append(f"**dex 文件数**：{len(r['dex_files'])}　**类总数**：{r['total_classes']:,}　**原生库数**：{r['native_lib_count']}")
    lines.append(f"**minSdk / targetSdk**：{r['min_sdk']} / {r['target_sdk']}")
    lines.append(f"**组件**：Activity {r['components']['activities']} · Service {r['components']['services']} · Receiver {r['components']['receivers']} · Provider {r['components']['providers']}\n")
    mf = r.get("manifest_flags", {})
    ec = r.get("exported_components", {})
    if mf or ec:
        lines.append("### Manifest 安全标志与组件导出面\n")
        if mf:
            lines.append("| 属性 | 取值 |")
            lines.append("|---|---|")
            zh = {"debuggable": "可调式", "allowBackup": "允许备份", "usesCleartextTraffic": "允许明文流量"}
            for k, v in mf.items():
                lines.append(f"| {zh.get(k, k)} (`{k}`) | {'开启' if v else '关闭'} |")
            lines.append("")
        lines.append("| 组件类型 | 总数 | 显式 exported=true | 显式 false | 隐式导出* | 缺声明无过滤器 |")
        lines.append("|---|---|---|---|---|---|")
        zh2 = {"activities": "Activity", "services": "Service", "receivers": "Receiver", "providers": "Provider"}
        for k, st in ec.items():
            lines.append(f"| {zh2.get(k, k)} | {st['total']} | {st['exported_true']} | {st['exported_false']} "
                         f"| {st['implicit']} | {st['missing_no_filter']} |")
        lines.append("\n\\* 隐式导出 = manifest 未声明 exported 属性但带 intent-filter，在 API 31 以下默认导出。\n")
    lines.append("---\n")
    lines.append(f"## 一、发现的第三方 SDK（dex 类名前缀匹配，{len(r['sdk_findings'])} 项）\n")
    lines.append("| 置信度 | SDK | 厂商 | 分类 | 命中类数 | 证据（样例类名） |")
    lines.append("|---|---|---|---|---|---|")
    for f in r["sdk_findings"]:
        samples = "<br>".join(f"`{s}`" for s in f["sample_classes"])
        name = f['name'] + (f"<br><sub> aka {'、'.join(f['aliases'])}</sub>" if f.get("aliases") else "")
        lines.append(f"| {f['confidence']} | {name} | {f['vendor'] or '-'} | {f['category']} "
                     f"| {f['class_count']} | {samples} |")
    if not r["sdk_findings"]:
        lines.append("| - | 无 | | | | |")
    lines.append("")
    if r["native_findings"]:
        lines.append("## 二、原生库发现（文件名级证据）\n")
        lines.append("| 置信度 | SDK | 厂商 | 证据 |")
        lines.append("|---|---|---|---|")
        for f in r["native_findings"]:
            lines.append(f"| {f['confidence']} | {f['name']} | {f['vendor']} | {f['evidence']} |")
        lines.append("")
    lines.append(f"## 三、权限清单（{len(r['permissions'])} 项，仅陈述）\n")
    for p in r["permissions"]:
        lines.append(f"- `{p}`")
    lines.append("")
    if r.get("string_findings"):
        lines.append(f"## 四、字符串线索（白名单常量精确匹配，{len(r['string_findings'])} 项，推断级）\n")
        lines.append("| SDK | 厂商 | 证据 |")
        lines.append("|---|---|---|")
        for f in r["string_findings"]:
            lines.append(f"| {f['name']} | {f['vendor'] or '-'} | {f['evidence']} |")
        lines.append("")
    lines.append("---\n")
    lines.append("## 已知局限与声明\n")
    for l in r["limitations"]:
        lines.append(f"- {l}")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="snowtrace-scan: 事实层 APK 扫描器")
    ap.add_argument("apk")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--whitelist", default=DEFAULT_WHITELIST)
    ap.add_argument("--out-dir", default=str(Path(__file__).parent / "reports"))
    ap.add_argument("--pcc", action=argparse.BooleanOptionalAction, default=True,
                    help="同时输出 PCC android_static 导入格式（默认开启，--no-pcc 关闭）")
    args = ap.parse_args()

    report = scan(args.apk, args.db, args.whitelist)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(args.apk).stem
    json_path = out_dir / f"{stem}.json"
    md_path = out_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    md_path.write_text(render_markdown(report))
    paths = [md_path, json_path]
    if args.pcc:
        pcc_path = out_dir / f"{stem}.pcc.json"
        pcc_path.write_text(json.dumps(emit_pcc_static(report), ensure_ascii=False, indent=2))
        paths.append(pcc_path)

    det = [f for f in report["sdk_findings"] if f["confidence"] == "确定"]
    inf = [f for f in report["sdk_findings"] if f["confidence"] == "推断"]
    print(f"完成：类 {report['total_classes']:,} | 确定级 {len(det)} 项 | 推断级 {len(inf)} 项 | 原生库 {len(report['native_findings'])} 项")
    for p in paths:
        print(f"输出：{p}")


if __name__ == "__main__":
    main()
