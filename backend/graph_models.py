"""Cognee DataPoint schema for the threat knowledge graph.

The graph is built deterministically from ATT&CK's own relationships (no LLM extraction),
so every edge is traceable to MITRE data. Cognee stores nodes/edges in its graph store and
indexes the `index_fields` into Qdrant through the community Qdrant adapter.
"""
from __future__ import annotations

from uuid import NAMESPACE_OID, uuid5

from cognee.infrastructure.engine import DataPoint


def node_id(kind: str, key: str):
    return uuid5(NAMESPACE_OID, f"soc-copilot:{kind}:{key}")


class Tactic(DataPoint):
    shortname: str
    name: str
    metadata: dict = {"index_fields": ["name"]}


class Technique(DataPoint):
    attack_id: str
    name: str
    summary: str
    in_tactic: list[Tactic] = []
    metadata: dict = {"index_fields": ["name", "summary"]}


class Software(DataPoint):
    attack_id: str
    name: str
    kind: str
    uses: list[Technique] = []
    metadata: dict = {"index_fields": ["name"]}


class ThreatGroup(DataPoint):
    attack_id: str
    name: str
    aliases: str
    uses: list[Technique] = []
    uses_software: list[Software] = []
    metadata: dict = {"index_fields": ["name"]}


class Mitigation(DataPoint):
    attack_id: str
    name: str
    mitigates: list[Technique] = []
    metadata: dict = {"index_fields": ["name"]}


class Asset(DataPoint):
    hostname: str
    segment: str
    role: str
    metadata: dict = {"index_fields": ["hostname"]}


class Incident(DataPoint):
    name: str
    summary: str
    observed: list[Technique] = []
    affected: list[Asset] = []
    attributed_to: list[ThreatGroup] = []
    metadata: dict = {"index_fields": ["summary"]}
