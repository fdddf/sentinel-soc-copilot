"""Parse MITRE ATT&CK (STIX 2.1) and SigmaHQ rules into plain Python structures."""
from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent.parent / "data"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


@dataclass
class Technique:
    attack_id: str
    name: str
    description: str
    tactics: list[str]
    url: str


@dataclass
class Group:
    attack_id: str
    name: str
    aliases: list[str]
    description: str
    techniques: set[str] = field(default_factory=set)
    software: set[str] = field(default_factory=set)


@dataclass
class Software:
    attack_id: str
    name: str
    kind: str
    techniques: set[str] = field(default_factory=set)


@dataclass
class Mitigation:
    attack_id: str
    name: str
    description: str
    techniques: set[str] = field(default_factory=set)


@dataclass
class Attack:
    techniques: dict[str, Technique]
    groups: dict[str, Group]
    software: dict[str, Software]
    mitigations: dict[str, Mitigation]
    tactics: dict[str, str]  # shortname -> display name


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def load_attack() -> Attack:
    objs = json.loads((DATA / "enterprise-attack.json").read_text())["objects"]
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_stix = {o["id"]: o for o in live}

    techniques: dict[str, Technique] = {}
    groups: dict[str, Group] = {}
    software: dict[str, Software] = {}
    mitigations: dict[str, Mitigation] = {}
    tactics: dict[str, str] = {}

    for o in live:
        t = o["type"]
        eid = _ext_id(o)
        if t == "attack-pattern" and eid:
            techniques[eid] = Technique(
                attack_id=eid,
                name=o["name"],
                description=_clean(o.get("description", "")),
                tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])
                         if p.get("kill_chain_name") == "mitre-attack"],
                url=_url(o),
            )
        elif t == "intrusion-set" and eid:
            groups[eid] = Group(eid, o["name"], o.get("aliases", []), _clean(o.get("description", "")))
        elif t in ("malware", "tool") and eid:
            software[eid] = Software(eid, o["name"], t)
        elif t == "course-of-action" and eid:
            mitigations[eid] = Mitigation(eid, o["name"], _clean(o.get("description", "")))
        elif t == "x-mitre-tactic":
            tactics[o["x_mitre_shortname"]] = o["name"]

    # Parent technique names make sub-techniques readable: "OS Credential Dumping: LSASS Memory"
    for tid, tech in techniques.items():
        if "." in tid and tid.split(".")[0] in techniques:
            tech.name = f"{techniques[tid.split('.')[0]].name}: {tech.name}"

    for r in live:
        if r["type"] != "relationship":
            continue
        src, dst = by_stix.get(r["source_ref"]), by_stix.get(r["target_ref"])
        if not src or not dst:
            continue
        s_id, d_id = _ext_id(src), _ext_id(dst)
        rel = r["relationship_type"]
        if rel == "uses" and d_id in techniques:
            if s_id in groups:
                groups[s_id].techniques.add(d_id)
            elif s_id in software:
                software[s_id].techniques.add(d_id)
        elif rel == "uses" and s_id in groups and d_id in software:
            groups[s_id].software.add(d_id)
        elif rel == "mitigates" and s_id in mitigations and d_id in techniques:
            mitigations[s_id].techniques.add(d_id)

    return Attack(techniques, groups, software, mitigations, tactics)


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    attack_ids: list[str]
    logsource: str
    keywords: list[str]
    raw: str
    path: str


def _flatten_values(node) -> list[str]:
    if isinstance(node, dict):
        out = []
        for v in node.values():
            out.extend(_flatten_values(v))
        return out
    if isinstance(node, list):
        out = []
        for v in node:
            out.extend(_flatten_values(v))
        return out
    if isinstance(node, (str, int)):
        return [str(node)]
    return []


def load_sigma(prefix: str = "sigma-master/rules/windows/") -> list[SigmaRule]:
    rules: list[SigmaRule] = []
    with zipfile.ZipFile(DATA / "sigma.zip") as zf:
        for name in zf.namelist():
            if not (name.startswith(prefix) and name.endswith(".yml")):
                continue
            raw = zf.read(name).decode("utf-8", errors="replace")
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or "title" not in doc:
                continue
            tags = doc.get("tags") or []
            attack_ids = sorted({t.split(".", 1)[1].upper() for t in tags
                                 if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
            detection = dict(doc.get("detection") or {})
            detection.pop("condition", None)
            ls = doc.get("logsource") or {}
            rules.append(SigmaRule(
                rule_id=str(doc.get("id", name)),
                title=doc["title"],
                description=_clean(str(doc.get("description", ""))),
                level=str(doc.get("level", "medium")),
                attack_ids=attack_ids,
                logsource="/".join(str(ls[k]) for k in ("product", "category", "service") if k in ls),
                keywords=[k for k in _flatten_values(detection) if len(k) > 2][:40],
                raw=raw,
                path=name.removeprefix("sigma-master/"),
            ))
    return rules
