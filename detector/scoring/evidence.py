"""V2 evidence-chain decision engine.

The legacy numeric score remains available for shadow comparison, but this
module is the source of truth for the final verdict.
"""
from collections import OrderedDict, Counter
import json
from pathlib import Path

RULE_CONFIG_PATH = Path(__file__).resolve().parents[2] / "evidence_rules.json"
LEVEL_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}
LEVEL_SEVERITY = {"E0": "context", "E1": "weak", "E2": "medium", "E3": "strong", "E4": "critical"}
VERDICT_TO_RISK = {
    "PHISHING": "高置信钓鱼",
    "MALWARE": "恶意软件",
    "SCAM": "诈骗",
    "HIGH_RISK": "高风险",
    "SUSPICIOUS": "可疑",
    "SAFE": "安全",
    "UNKNOWN": "未知",
}
VERDICT_PRIORITY = {"PHISHING": 5, "MALWARE": 4, "SCAM": 3, "HIGH_RISK": 2, "SUSPICIOUS": 1}


def load_evidence_config(path=RULE_CONFIG_PATH):
    try:
        with Path(path).open("r", encoding="utf-8-sig") as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"V2 证据规则加载失败 {path}: {exc}") from exc
    if not isinstance(config, dict) or not config.get("version") or not isinstance(config.get("rules"), list):
        raise ValueError("V2 证据规则必须包含 version 和 rules 数组")
    seen = set()
    for rule in config["rules"]:
        required = {"id", "name", "stage", "severity", "evidence_group", "browser_required"}
        if not isinstance(rule, dict) or not required.issubset(rule):
            raise ValueError("V2 证据规则字段不完整")
        if rule["id"] in seen:
            raise ValueError(f"V2 证据规则 ID 重复: {rule['id']}")
        if rule["evidence_group"] not in config.get("groups", {}):
            raise ValueError(f"无效证据组: {rule['evidence_group']}")
        if rule["severity"] not in config.get("levels", {}).values():
            raise ValueError(f"无效规则强度: {rule['severity']}")
        seen.add(rule["id"])
    return config


RULE_CONFIG = load_evidence_config()
RULE_VERSION = RULE_CONFIG["version"]
RULE_CATALOG = {rule["id"]: rule for rule in RULE_CONFIG["rules"]}


def _item(rule_id, level, description, detail=None, verdict=None):
    meta = RULE_CATALOG.get(rule_id, {})
    item = {
        "rule_id": rule_id,
        "group": meta.get("evidence_group", "G1"),
        "level": level,
        "severity": LEVEL_SEVERITY[level],
        "stage": meta.get("stage", "decision"),
        "description": description,
        "rule_version": RULE_VERSION,
    }
    direct_verdict = verdict or meta.get("verdict")
    if direct_verdict:
        item["verdict"] = direct_verdict
    if detail:
        item["detail"] = detail
    return item


def _add(groups, item):
    groups[item["group"]].append(item)


def _max_level(entries):
    return max((LEVEL_RANK[item["level"]] for item in entries), default=-1)


def evaluate_evidence(*, brand=None, page=None, signals=None, url_signals=None,
                      link_analysis=None, hard_rules=None, blocked=False,
                      infrastructure=None):
    """Build independent E0-E4/G1-G7 evidence and return a V2 verdict."""
    brand, page = brand or {}, page or {}
    signals, url_signals = signals or {}, url_signals or {}
    links, hard_rules = link_analysis or {}, hard_rules or []
    infrastructure = infrastructure or {}
    infra = infrastructure.get('signals') or {}
    groups = OrderedDict((name, []) for name in ("G1", "G2", "G3", "G4", "G5", "G6", "G7"))
    non_official = bool(brand.get("brand_name") and not brand.get("is_official"))
    sensitive = any(
        page.get(key)
        for key in (
            "credential_collection", "otp_collection", "payment_collection",
            "wallet_seed", "personal_info_collection",
        )
    )
    has_icp_filing = bool(
        (infrastructure.get("icp_filing") or {}).get("has_filing")
    )
    critical_brand_match = bool(
        brand.get("homograph")
        or brand.get("character_substitution")
        or brand.get("mixed_script")
        or brand.get("fake_official_subdomain")
        or (brand.get("has_punycode") and brand.get("high_similarity"))
    )
    logo_match = bool(page.get("logo_impersonation"))
    # Brand similarity alone is not page impersonation. It can raise the
    # collection severity only when the page actually claims the brand or the
    # domain is a high-confidence homograph/substitution.
    impersonating = bool(
        non_official
        and (
            page.get("page_impersonation")
            or logo_match
            or (critical_brand_match and sensitive)
        )
    )

    if blocked:
        _add(groups, _item("REP-601", "E4", "命中本地恶意网址库", verdict="PHISHING"))
    if signals.get("domain_age_days") is not None:
        _add(groups, _item("DOMAIN-010", "E0", "域龄仅作为上下文，不参与恶意判定", f"age_days={signals['domain_age_days']}"))
    if signals.get("unnecessary_hyphens") == -1:
        _add(groups, _item("DOMAIN-011", "E1", "域名包含可疑横杠结构"))
    if signals.get("whois_unavailable") == -1:
        _add(groups, _item("INFRA-501", "E0", "WHOIS/RDAP 信息不可用，仅作为上下文"))
    if url_signals.get("userinfo"):
        _add(groups, _item("URL-003", "E2", "URL 包含可能误导真实主机的 userinfo"))
    if signals.get("ip_host") == -1:
        _add(groups, _item("URL-004", "E2", "URL 使用 IP 地址作为主机"))
    if url_signals.get("non_standard_port"):
        _add(groups, _item("URL-005", "E1", "URL 使用非标准端口"))
    if url_signals.get("suspicious_redirect_param"):
        _add(groups, _item("URL-010", "E1", "URL 跳转参数包含外部目标"))

    if non_official and brand.get("high_similarity"):
        # Ordinary edit-distance/substring matches are only medium evidence.
        # Strong evidence is reserved for homographs, substitutions, and fake
        # official subdomains (or an equivalent Punycode signal).
        level = "E3" if critical_brand_match else "E2"
        _add(groups, _item("BRAND-101", level, "域名高度相似于品牌官方资产", f"brand={brand.get('brand_name')}; method={brand.get('matched_by', '')}"))
    elif non_official:
        _add(groups, _item("BRAND-001", "E2", "URL 或页面关联品牌，但注册域不是官方资产", f"brand={brand.get('brand_name')}"))
    if non_official and brand.get("multiple_brands") and sensitive:
        _add(groups, _item("BRAND-120", "E2", "同一目标组合多个品牌身份"))

    if page.get("page_brands") and non_official:
        _add(groups, _item("CONTENT-201", "E2", "页面标题、标题栏或图片声明品牌", ", ".join(page["page_brands"])))
    if page.get("page_impersonation") and non_official:
        _add(groups, _item("CONTENT-202", "E3", "页面内容冒用品牌官方身份"))
    logo = page.get("logo_impersonation")
    if isinstance(logo, dict) and non_official:
        _add(groups, _item(
            "CONTENT-205", "E3", "页面 favicon 与品牌官方 favicon 视觉一致",
            f"brand={logo.get('brand')}; distance={logo.get('distance')}; "
            f"threshold={logo.get('threshold')}",
        ))
    if page.get("scam_keywords"):
        scam_count = len(page["scam_keywords"])
        scam_level = "E3" if sensitive else ("E2" if scam_count >= 2 else "E1")
        _add(groups, _item("CONTENT-203", scam_level, "页面包含客服、中奖、退款等诈骗话术", ", ".join(page["scam_keywords"])))
    strong_scam = page.get("scam_strong") or []
    scam_collects = bool(
        page.get("payment_collection") or page.get("personal_info_collection")
    )
    if strong_scam and scam_collects and (
        len(strong_scam) >= 2
        or (len(strong_scam) >= 1 and scam_count >= 3)
        or (len(strong_scam) >= 1 and non_official)
    ):
        # Report HR-007: prize/freeze scam templates combined with payment
        # or identity collection are a direct SCAM decision.
        _add(groups, _item(
            "SCAM-701", "E4", "诈骗话术模板配合支付或个人信息采集",
            ", ".join(strong_scam[:4]), "SCAM",
        ))
    if page.get("sensitive_keywords") and non_official:
        _add(groups, _item("CONTENT-204", "E2", "非官方品牌页面出现登录、验证或支付话术", ", ".join(page["sensitive_keywords"])))

    collection_level = "E3" if impersonating else "E1" if brand.get("is_official") else "E2"
    for key, rule_id, description in (
        ("credential_collection", "FORM-301", "页面收集账号或密码"),
        ("otp_collection", "FORM-305", "页面收集 OTP 或验证码"),
        ("payment_collection", "FORM-306", "页面收集支付或银行卡信息"),
        ("personal_info_collection", "FORM-308", "页面收集身份证或个人身份信息"),
    ):
        if page.get(key):
            _add(groups, _item(rule_id, collection_level, description))
    if page.get("wallet_seed"):
        _add(groups, _item("FORM-307", "E4", "页面收集私钥、助记词或恢复短语", verdict="PHISHING"))

    if page.get("external_form_actions"):
        level = "E4" if sensitive else "E2"
        _add(groups, _item("FORM-302", level, "表单向外部注册域提交数据", "; ".join(page["external_form_actions"]), "PHISHING" if sensitive else None))
    if page.get("same_domain_sensitive_form") and impersonating:
        _add(groups, _item("FORM-303", "E4", "仿冒品牌站在同域接收敏感表单", verdict="PHISHING"))
    elif page.get("same_domain_sensitive_form") and non_official:
        _add(groups, _item("FORM-303", "E3", "非官方品牌站在同域接收敏感表单"))
    if page.get("external_script_targets"):
        level = "E4" if sensitive else "E2"
        _add(groups, _item("FORM-304", level, "脚本向外部注册域发送请求", "; ".join(page["external_script_targets"]), "PHISHING" if sensitive else None))
    if page.get("dangerous_download"):
        if impersonating and not sensitive:
            # Malware distribution in a brand-impersonation context is a
            # direct MALWARE verdict (report HR-006) unless credential
            # collection already makes it phishing (higher priority).
            _add(groups, _item(
                "BEH-403", "E4", "仿冒品牌页面诱导下载可执行文件或安装包",
                "; ".join(
                    target.get("url", "")
                    for target in (page.get("download_targets") or [])
                    if target.get("type") in ("executable", "installer")
                )[:400],
                "MALWARE",
            ))
        else:
            _add(groups, _item("BEH-401", "E3" if impersonating else "E2", "页面提供可执行文件或安装包下载"))
    if page.get("dynamic_redirect") or links.get("short_url_count"):
        _add(groups, _item("BEH-402", "E1", "页面存在动态跳转或短链接"))
    if page.get("external_iframes"):
        _add(groups, _item("BEH-410", "E2", "页面加载外部注册域 iframe", "; ".join(page["external_iframes"])))

    # G7 infrastructure signals (L2 layer). These never fire unless the
    # local knowledge base or CT analysis produced a concrete hit.
    if infra.get("shared_ip_with_known_bad"):
        _add(groups, _item(
            "INFRA-502", "E3", "解析 IP 与已知恶意基础设施重合",
            infra.get("shared_ip_detail"),
        ))
    if infra.get("cert_shared_with_suspicious") or infra.get("cert_brand_san"):
        level = "E3" if infra.get("cert_brand_san") else "E2"
        detail = "; ".join(
            (infra.get("cert_suspicious_domains") or [])
            + (infra.get("cert_brand_domains") or [])
        )
        _add(groups, _item("INFRA-503", level, "证书 SAN 与可疑域名或品牌域名关联", detail))
    if infra.get("abusive_asn"):
        _add(groups, _item("INFRA-504", "E2", "域名托管在已知滥用自治域 (ASN)", infra.get("abusive_asn_detail")))
    if infra.get("free_dns_provider"):
        _add(groups, _item("INFRA-505", "E1", "域名使用免费动态 DNS 服务", infra.get("free_dns_detail")))

    for rule in hard_rules:
        verdict = rule.get("verdict")
        level = "E4" if verdict else "E3"
        _add(groups, _item(rule.get("id", "HARD-RULE"), level, rule.get("detail", "命中 Hard Rule"), verdict=verdict))

    evidence = [entry for entries in groups.values() for entry in entries]
    group_strength = {group: _max_level(entries) for group, entries in groups.items() if entries}
    strong_groups = {group for group, rank in group_strength.items() if rank >= LEVEL_RANK["E3"]}
    medium_groups = {group for group, rank in group_strength.items() if rank >= LEVEL_RANK["E2"]}
    weak_groups = {group for group, rank in group_strength.items() if rank >= LEVEL_RANK["E1"]}
    direct = [item.get("verdict") for item in evidence if item["level"] == "E4" and item.get("verdict")]
    hard = [rule.get("verdict") for rule in hard_rules if rule.get("verdict")]
    direct_verdicts = [value for value in direct + hard if value]

    attack_groups = {"G5", "G6"}
    has_attack_group = bool(strong_groups & attack_groups)
    if direct_verdicts:
        # E4 rules and the local malicious URL database always win, including
        # when the domain has an ICP filing.
        verdict = max(direct_verdicts, key=lambda value: VERDICT_PRIORITY.get(value, 0))
    elif len(strong_groups) >= 2 and has_attack_group:
        verdict = "PHISHING"
    elif len(strong_groups) >= 2:
        # Two non-attack strong groups are insufficient for an automatic block.
        verdict = "HIGH_RISK"
    elif strong_groups and len(medium_groups - strong_groups) >= 1:
        verdict = "HIGH_RISK"
    elif strong_groups or len(medium_groups) >= 2:
        verdict = "SUSPICIOUS"
    elif medium_groups:
        verdict = "SUSPICIOUS"
    elif len(weak_groups) >= 2:
        verdict = "SUSPICIOUS"
    elif evidence:
        verdict = "UNKNOWN"
    else:
        verdict = "SAFE"

    # A verified filing is a trust/context signal, not an exemption. It
    # suppresses only heuristic brand/content combinations; direct attack
    # evidence above remains PHISHING.
    if has_icp_filing and not direct_verdicts and not has_attack_group and verdict in ("PHISHING", "HIGH_RISK"):
        verdict = "SUSPICIOUS"

    max_rank = max(group_strength.values(), default=-1)
    if verdict == "SAFE":
        confidence = 0.85
    elif verdict == "UNKNOWN":
        confidence = 0.35
    else:
        confidence = min(0.99, 0.42 + 0.12 * len(medium_groups) + 0.08 * max(0, max_rank))
        if verdict == "SUSPICIOUS": confidence = min(confidence, 0.69)
        if verdict == "HIGH_RISK": confidence = max(confidence, 0.75)
        if verdict in ("PHISHING", "MALWARE", "SCAM"): confidence = max(confidence, 0.90 if direct_verdicts else 0.82)

    counts = Counter(item["level"] for item in evidence)
    return {
        "engine_version": RULE_VERSION,
        "verdict": verdict,
        "risk_level": VERDICT_TO_RISK[verdict],
        "confidence": round(confidence, 2),
        "evidence": evidence,
        "evidence_groups": {key: value for key, value in groups.items() if value},
        "group_strength": {key: f"E{value}" for key, value in group_strength.items()},
        "strong_groups": sorted(strong_groups),
        "evidence_summary": {level: counts.get(level, 0) for level in LEVEL_RANK},
    }
