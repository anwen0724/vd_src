from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .config import PermissionChainGraphConfig
from .graph_index import ChainGraphIndex
from .schema import ChainSourceLocation, PermissionChain
from .target_loader import seed_node_ids, target_ref


@dataclass
class ChainSearchDiagnostics:
    chain_id: str
    seed_target_id: str
    seed_node_count: int
    visited_node_count: int
    visited_edge_count: int
    source_location_count: int
    truncated_nodes: bool = False
    truncated_edges: bool = False
    missing_seed_nodes: list[str] = field(default_factory=list)


def build_chains(
    targets: list[dict[str, Any]],
    graph_index: ChainGraphIndex,
    config: PermissionChainGraphConfig,
) -> tuple[list[PermissionChain], list[ChainSearchDiagnostics]]:
    chains: list[PermissionChain] = []
    diagnostics: list[ChainSearchDiagnostics] = []
    for index, target in enumerate(targets[: config.max_chains_per_repo], start=1):
        chain_id = f"CHAIN-{index:04d}"
        chain, diag = build_chain_for_target(chain_id, target, graph_index, config)
        chains.append(chain)
        diagnostics.append(diag)
    return chains, diagnostics


def build_chain_for_target(
    chain_id: str,
    target: dict[str, Any],
    graph_index: ChainGraphIndex,
    config: PermissionChainGraphConfig,
) -> tuple[PermissionChain, ChainSearchDiagnostics]:
    seeds = seed_node_ids(target, include_access_nodes=config.include_target_access_nodes)
    missing = [node_id for node_id in seeds if graph_index.maybe_node(node_id) is None]
    visited_nodes, visited_edges = _bounded_search(seeds, graph_index, config)
    formal_nodes = [node for node_id in sorted(visited_nodes) if (node := graph_index.formal_node(node_id)) is not None]
    formal_edges = [edge for edge_id in sorted(visited_edges) if (edge := graph_index.formal_edge(edge_id)) is not None]
    truncated_nodes = len(formal_nodes) > config.max_nodes_per_chain
    truncated_edges = len(formal_edges) > config.max_edges_per_chain
    formal_nodes = _rank_nodes(formal_nodes)[: config.max_nodes_per_chain]
    kept_node_ids = {node.node_id for node in formal_nodes}
    formal_edges = [
        edge
        for edge in _rank_edges(formal_edges)
        if edge.src in kept_node_ids and edge.dst in kept_node_ids
    ][: config.max_edges_per_chain]
    locations = _source_locations(formal_nodes, formal_edges, graph_index)
    chain = PermissionChain(
        chain_id=chain_id,
        seed_targets=[target_ref(target)],
        nodes=formal_nodes,
        edges=formal_edges,
        source_locations=locations,
    )
    diag = ChainSearchDiagnostics(
        chain_id=chain_id,
        seed_target_id=str(target.get("target_id", "")),
        seed_node_count=len(seeds),
        visited_node_count=len(formal_nodes),
        visited_edge_count=len(formal_edges),
        source_location_count=len(locations),
        truncated_nodes=truncated_nodes,
        truncated_edges=truncated_edges,
        missing_seed_nodes=missing,
    )
    return chain, diag


def _bounded_search(
    seeds: list[str],
    graph_index: ChainGraphIndex,
    config: PermissionChainGraphConfig,
) -> tuple[set[str], set[str]]:
    visited_nodes: set[str] = set()
    visited_edges: set[str] = set()
    queue = deque((node_id, 0) for node_id in seeds if graph_index.maybe_node(node_id))
    while queue:
        node_id, depth = queue.popleft()
        if node_id in visited_nodes:
            continue
        visited_nodes.add(node_id)
        if depth >= config.max_depth:
            continue
        adjacent = _rank_raw_edges(graph_index.adjacent_edges(node_id))[: config.max_frontier_per_depth]
        for edge in adjacent:
            edge_id = edge.get("id")
            src = edge.get("from")
            dst = edge.get("to")
            if edge_id:
                visited_edges.add(str(edge_id))
            for next_id in [src, dst, *graph_index.edge_instance_node_ids(edge)]:
                if next_id and next_id not in visited_nodes and graph_index.maybe_node(str(next_id)):
                    queue.append((str(next_id), depth + 1))
    return visited_nodes, visited_edges


def _rank_raw_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(edge: dict[str, Any]) -> tuple[int, str]:
        weight = {"connects": 0, "writes": 1, "reads": 2}.get(str(edge.get("type")), 3)
        return (weight, str(edge.get("id", "")))

    return sorted(edges, key=key)


def _rank_nodes(nodes):
    def key(node):
        weight = {"Signal": 0, "StmtSummary": 1, "Instance": 2, "Module": 3}.get(node.kind, 4)
        return (weight, node.module, node.node_id)

    return sorted(nodes, key=key)


def _rank_edges(edges):
    def key(edge):
        weight = {"connects": 0, "writes": 1, "reads": 2}.get(edge.kind, 3)
        return (weight, edge.edge_id)

    return sorted(edges, key=key)


def _source_locations(nodes, edges, graph_index: ChainGraphIndex) -> list[ChainSourceLocation]:
    by_key: dict[tuple[str, int, int], dict[str, set[str]]] = {}
    for node in nodes:
        if node.loc is None:
            continue
        key = (node.loc.file, node.loc.line_start, node.loc.line_end)
        by_key.setdefault(key, {"nodes": set(), "edges": set()})["nodes"].add(node.node_id)
    for edge in edges:
        raw_edge = graph_index.maybe_edge(edge.edge_id)
        if not raw_edge:
            continue
        for node_id in graph_index.edge_instance_node_ids(raw_edge):
            loc = graph_index.source_loc(node_id)
            if loc is None:
                continue
            key = (loc.file, loc.line_start, loc.line_end)
            by_key.setdefault(key, {"nodes": set(), "edges": set()})["edges"].add(edge.edge_id)
    locations = []
    for index, (key, refs) in enumerate(sorted(by_key.items()), start=1):
        file, line_start, line_end = key
        locations.append(
            ChainSourceLocation(
                loc_id=f"LOC-{index:04d}",
                file=file,
                line_start=line_start,
                line_end=line_end,
                node_ids=sorted(refs["nodes"]),
                edge_ids=sorted(refs["edges"]),
            )
        )
    return locations

