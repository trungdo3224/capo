"""Knowledge Graph Manager — per-target graph of pentest findings.

Manages two kinds of nodes concurrently:
- **State nodes** (source="state") — auto-synced from StateManager data
  (ports, users, credentials, hashes, domains, vhosts, directories, shares,
  domain_info). Cannot be deleted by user.
- **Manual nodes** (source="manual") — user-created findings, notes, attack
  path annotations.  Fully editable and deletable.

All nodes are connectable via edges.  Stored in ``graph.json`` alongside
``state.json`` in each target workspace.
"""

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

from capo.errors import GraphError

GRAPH_SCHEMA_VERSION = 1

# Mapping of common credential service names → nmap service name variants.
# Used when linking credential nodes to service nodes during auto-sync.
SERVICE_ALIASES: dict[str, set[str]] = {
    "smb": {"microsoft-ds", "smb", "netbios-ssn", "cifs"},
    "microsoft-ds": {"microsoft-ds", "smb", "netbios-ssn", "cifs"},
    "netbios-ssn": {"microsoft-ds", "smb", "netbios-ssn", "cifs"},
    "ssh": {"ssh", "openssh"},
    "rdp": {"rdp", "ms-wbt-server"},
    "ms-wbt-server": {"rdp", "ms-wbt-server"},
    "winrm": {"winrm", "wsman", "http-alt"},
    "wsman": {"winrm", "wsman"},
    "ldap": {"ldap", "ldaps"},
    "ldaps": {"ldap", "ldaps"},
    "mssql": {"mssql", "ms-sql-s", "ms-sql"},
    "ms-sql-s": {"mssql", "ms-sql-s", "ms-sql"},
    "mysql": {"mysql", "mariadb"},
    "ftp": {"ftp", "ftps"},
    "http": {"http", "http-proxy", "http-alt"},
    "https": {"https", "ssl/http"},
    "kerberos": {"kerberos", "kerberos-sec"},
    "kerberos-sec": {"kerberos", "kerberos-sec"},
    "dns": {"dns", "domain"},
    "domain": {"dns", "domain"},
    "smtp": {"smtp", "smtps"},
    "imap": {"imap", "imaps"},
    "pop3": {"pop3", "pop3s"},
    "vnc": {"vnc", "vnc-http"},
    "psexec": {"microsoft-ds", "smb", "netbios-ssn", "cifs"},
    "wmi": {"microsoft-ds", "smb"},
}


def _services_match(cred_service: str, node_service: str) -> bool:
    """Check if a credential's service name matches a service node's name.

    Handles nmap naming inconsistencies via SERVICE_ALIASES.
    """
    if not cred_service or not node_service:
        return False
    cs = cred_service.lower().strip()
    ns = node_service.lower().strip()
    if cs == ns:
        return True
    aliases = SERVICE_ALIASES.get(cs)
    return ns in aliases if aliases else False


class GraphManager:
    """Manages per-target knowledge graph stored in graph.json."""

    def __init__(self):
        self._workspace: Path | None = None
        self._target: str | None = None
        self._data: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load_for_target(self, workspace: Path, target: str):
        """Load (or create) the graph for a specific target workspace."""
        self._workspace = workspace
        self._target = target
        self._load()

    def _graph_file(self) -> Path:
        return self._workspace / "graph.json"

    def _lock(self) -> FileLock:
        return FileLock(str(self._graph_file()) + ".lock", timeout=5)

    def _fresh_graph(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "target": self._target,
            "nodes": [],
            "edges": [],
            "updated_at": now,
        }

    def _load(self):
        gf = self._graph_file()
        if gf.exists():
            try:
                self._data = json.loads(gf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = self._fresh_graph()
        else:
            self._data = self._fresh_graph()

    def _save(self):
        if self._workspace is None:
            return
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        gf = self._graph_file()
        with self._lock():
            tmp = gf.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")
            shutil.move(str(tmp), str(gf))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _node_by_id(self, node_id: str) -> dict | None:
        for n in self._data["nodes"]:
            if n["id"] == node_id:
                return n
        return None

    def _edge_by_id(self, edge_id: str) -> dict | None:
        for e in self._data["edges"]:
            if e["id"] == edge_id:
                return e
        return None

    def _node_by_source_key(self, source_key: str) -> dict | None:
        for n in self._data["nodes"]:
            if n.get("source") == "state" and n.get("source_key") == source_key:
                return n
        return None

    def _find_edge(self, source_id: str, target_id: str, relationship: str) -> dict | None:
        for e in self._data["edges"]:
            if (e["source"] == source_id
                    and e["target"] == target_id
                    and e.get("relationship") == relationship):
                return e
        return None

    def _make_node(self, *, node_type: str, label: str, source: str,
                   source_key: str = "", properties: dict | None = None,
                   x: float | None = None, y: float | None = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": str(uuid.uuid4()),
            "type": node_type,
            "label": label,
            "source": source,
            "source_key": source_key,
            "properties": properties or {},
            "x": x,
            "y": y,
            "created_at": now,
            "updated_at": now,
        }

    def _make_edge(self, *, source_id: str, target_id: str, label: str = "",
                   relationship: str = "related_to", directed: bool = True,
                   source_origin: str = "state") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": str(uuid.uuid4()),
            "source": source_id,
            "target": target_id,
            "label": label,
            "relationship": relationship,
            "directed": directed,
            "source_origin": source_origin,
            "created_at": now,
        }

    # ------------------------------------------------------------------
    # Public: read
    # ------------------------------------------------------------------

    def get_graph(self) -> dict:
        """Return the full graph data (nodes + edges)."""
        return self._data

    # ------------------------------------------------------------------
    # Public: sync from state
    # ------------------------------------------------------------------

    def sync_from_state(self, state_data: dict):
        """Synchronise state nodes with current state.json data.

        Creates, updates, and removes ``source="state"`` nodes to match.
        Never touches ``source="manual"`` nodes or user-created edges.
        """
        changed = False
        existing_keys: dict[str, dict] = {}
        for n in self._data["nodes"]:
            if n.get("source") == "state":
                existing_keys[n["source_key"]] = n

        wanted_keys: set[str] = set()

        # --- Central target node ---
        ip = state_data.get("ip", state_data.get("target", ""))
        hostname = state_data.get("hostname", "")
        os_info = state_data.get("os", "")
        if ip:
            key = f"target:{ip}"
            wanted_keys.add(key)
            label = ip
            if hostname:
                label = f"{ip} ({hostname})"
            props = {"ip": ip, "hostname": hostname, "os": os_info}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label or existing["properties"] != props:
                    existing["label"] = label
                    existing["properties"] = props
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="target", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True

        target_node = self._node_by_source_key(f"target:{ip}") if ip else None

        # --- Ports → service nodes ---
        for p in state_data.get("ports", []):
            port = p.get("port", 0)
            proto = p.get("protocol", "tcp")
            svc = p.get("service", "")
            ver = p.get("version", "")
            key = f"port:{port}/{proto}"
            wanted_keys.add(key)
            label = f"{svc or 'unknown'} :{port}" if svc else f":{port}"
            if ver:
                label += f" ({ver})"
            props = {"port": port, "protocol": proto, "service": svc, "version": ver}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label or existing["properties"] != props:
                    existing["label"] = label
                    existing["properties"] = props
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="service", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge: target → service
                if target_node:
                    edge = self._make_edge(
                        source_id=target_node["id"], target_id=node["id"],
                        label="", relationship="has_service",
                    )
                    self._data["edges"].append(edge)

        # --- Users → user nodes ---
        for username in state_data.get("users", []):
            key = f"user:{username}"
            wanted_keys.add(key)
            if key not in existing_keys:
                node = self._make_node(
                    node_type="user", label=username, source="state",
                    source_key=key, properties={"username": username},
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge: target → user
                if target_node:
                    edge = self._make_edge(
                        source_id=target_node["id"], target_id=node["id"],
                        label="", relationship="has_user",
                    )
                    self._data["edges"].append(edge)

        # --- Credentials → credential nodes ---
        for cred in state_data.get("credentials", []):
            user = cred.get("username", "")
            svc = cred.get("service", "")
            key = f"cred:{user}:{svc}"
            wanted_keys.add(key)
            label = f"{user}:{svc}" if svc else user
            props = {"username": user, "service": svc}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label:
                    existing["label"] = label
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="credential", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge: credential → matching service node(s)
                if svc:
                    for svc_node in self._data["nodes"]:
                        if (svc_node.get("source") == "state"
                                and svc_node["type"] == "service"
                                and _services_match(svc, svc_node["properties"].get("service", ""))):
                            if not self._find_edge(node["id"], svc_node["id"], "authenticates_as"):
                                edge = self._make_edge(
                                    source_id=node["id"], target_id=svc_node["id"],
                                    label="", relationship="authenticates_as",
                                )
                                self._data["edges"].append(edge)
                            break

                # Auto-edge: user → credential (owns_credential)
                if user:
                    user_node = self._node_by_source_key(f"user:{user}")
                    if user_node and not self._find_edge(user_node["id"], node["id"], "owns_credential"):
                        edge = self._make_edge(
                            source_id=user_node["id"], target_id=node["id"],
                            label="", relationship="owns_credential",
                        )
                        self._data["edges"].append(edge)

        # --- Hashes → hash nodes ---
        for h in state_data.get("hashes", []):
            user = h.get("username", "") if isinstance(h, dict) else ""
            hash_type = h.get("type", "unknown") if isinstance(h, dict) else "unknown"
            hash_val = h.get("hash", str(h)) if isinstance(h, dict) else str(h)
            key = f"hash:{user}:{hash_type}:{hash_val[:32]}" if user else f"hash:{hash_val[:32]}"
            wanted_keys.add(key)
            label = f"{user}:{hash_type}" if user else f"{hash_type}:{hash_val[:16]}..."
            props = {"username": user, "hash_type": hash_type, "hash": hash_val}

            if key not in existing_keys:
                node = self._make_node(
                    node_type="hash", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge: user → hash (has_hash)
                if user:
                    user_node = self._node_by_source_key(f"user:{user}")
                    if user_node:
                        edge = self._make_edge(
                            source_id=user_node["id"], target_id=node["id"],
                            label="", relationship="has_hash",
                        )
                        self._data["edges"].append(edge)

        # --- Domains → domain nodes ---
        for domain in state_data.get("domains", []):
            key = f"domain:{domain}"
            wanted_keys.add(key)
            if key not in existing_keys:
                node = self._make_node(
                    node_type="domain", label=domain, source="state",
                    source_key=key, properties={"domain": domain},
                )
                self._data["nodes"].append(node)
                changed = True
                if target_node:
                    edge = self._make_edge(
                        source_id=node["id"], target_id=target_node["id"],
                        label="", relationship="resolves_to",
                    )
                    self._data["edges"].append(edge)

        # --- Vhosts → vhost nodes ---
        for vhost in state_data.get("vhosts", []):
            key = f"vhost:{vhost}"
            wanted_keys.add(key)
            if key not in existing_keys:
                node = self._make_node(
                    node_type="vhost", label=vhost, source="state",
                    source_key=key, properties={"vhost": vhost},
                )
                self._data["nodes"].append(node)
                changed = True
                if target_node:
                    edge = self._make_edge(
                        source_id=node["id"], target_id=target_node["id"],
                        label="", relationship="resolves_to",
                    )
                    self._data["edges"].append(edge)

        # --- Directories → directory nodes ---
        for d in state_data.get("directories", []):
            path = d.get("path", "") if isinstance(d, dict) else str(d)
            status = d.get("status", 200) if isinstance(d, dict) else 200
            key = f"dir:{path}"
            wanted_keys.add(key)
            label = f"{path} [{status}]"
            props = {"path": path, "status": status}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label:
                    existing["label"] = label
                    existing["properties"] = props
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="directory", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge to HTTP service (port 80 or 443)
                http_node = (
                    self._node_by_source_key("port:443/tcp")
                    or self._node_by_source_key("port:80/tcp")
                    or self._node_by_source_key("port:8080/tcp")
                    or self._node_by_source_key("port:8443/tcp")
                )
                if http_node:
                    edge = self._make_edge(
                        source_id=http_node["id"], target_id=node["id"],
                        label="", relationship="exposes",
                    )
                    self._data["edges"].append(edge)

        # --- Shares → share nodes ---
        for share in state_data.get("shares", []):
            name = share.get("name", "")
            key = f"share:{name}"
            wanted_keys.add(key)
            perms = share.get("permissions", "")
            label = f"{name} ({perms})" if perms else name
            props = {"name": name, "permissions": perms, "comment": share.get("comment", "")}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label:
                    existing["label"] = label
                    existing["properties"] = props
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="share", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge to SMB service node (port 445)
                smb_node = self._node_by_source_key("port:445/tcp")
                if smb_node:
                    edge = self._make_edge(
                        source_id=smb_node["id"], target_id=node["id"],
                        label="", relationship="exposes",
                    )
                    self._data["edges"].append(edge)

        # --- domain_info → domain controller node ---
        di = state_data.get("domain_info", {})
        dc_ip = di.get("dc_ip", "")
        domain_name = di.get("domain_name", "")
        dns_name = di.get("dns_name", "")
        if dc_ip:
            key = f"dc:{dc_ip}"
            wanted_keys.add(key)
            label = f"DC {dc_ip}"
            if dns_name:
                label += f" ({dns_name})"
            props = {"dc_ip": dc_ip, "domain_name": domain_name, "dns_name": dns_name}

            existing = existing_keys.get(key)
            if existing:
                if existing["label"] != label or existing["properties"] != props:
                    existing["label"] = label
                    existing["properties"] = props
                    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            else:
                node = self._make_node(
                    node_type="dc", label=label, source="state",
                    source_key=key, properties=props,
                )
                self._data["nodes"].append(node)
                changed = True
                # Auto-edge: domain → dc (member_of)
                if domain_name:
                    domain_node = self._node_by_source_key(f"domain:{domain_name}")
                    if domain_node:
                        edge = self._make_edge(
                            source_id=domain_node["id"], target_id=node["id"],
                            label="", relationship="member_of",
                        )
                        self._data["edges"].append(edge)
                # Auto-edge: target → dc (connects_to)
                if target_node:
                    edge = self._make_edge(
                        source_id=target_node["id"], target_id=node["id"],
                        label="", relationship="connects_to",
                    )
                    self._data["edges"].append(edge)

        # --- Remove stale state nodes ---
        # A state node is "stale" if its source_key is no longer in state.
        # If the node has manual edges attached, keep it (don't destroy
        # user's work) — only remove its auto-created edges.
        # If it has no manual edges, remove it entirely.
        stale_candidates: dict[str, dict] = {}
        for key, node in existing_keys.items():
            if key not in wanted_keys:
                stale_candidates[node["id"]] = node

        if stale_candidates:
            # Find which stale nodes have manual edges connected
            has_manual_edge: set[str] = set()
            for e in self._data["edges"]:
                is_manual = e.get("source_origin") == "manual"
                if is_manual:
                    if e["source"] in stale_candidates:
                        has_manual_edge.add(e["source"])
                    if e["target"] in stale_candidates:
                        has_manual_edge.add(e["target"])

            # Nodes safe to fully remove (no manual edges attached)
            remove_ids = set(stale_candidates.keys()) - has_manual_edge
            # Nodes to keep but strip auto-edges from
            keep_stale_ids = has_manual_edge

            if remove_ids:
                self._data["nodes"] = [
                    n for n in self._data["nodes"] if n["id"] not in remove_ids
                ]
                self._data["edges"] = [
                    e for e in self._data["edges"]
                    if e["source"] not in remove_ids and e["target"] not in remove_ids
                ]
                changed = True

            # For kept stale nodes: remove only auto-created edges
            if keep_stale_ids:
                self._data["edges"] = [
                    e for e in self._data["edges"]
                    if not (
                        e.get("source_origin") == "state"
                        and (e["source"] in keep_stale_ids or e["target"] in keep_stale_ids)
                    )
                ]
                changed = True

        if changed:
            self._save()

    # ------------------------------------------------------------------
    # Public: manual node CRUD
    # ------------------------------------------------------------------

    def add_node(self, node_type: str, label: str,
                 properties: dict | None = None,
                 x: float | None = None, y: float | None = None) -> dict:
        """Create a manual node. Returns the created node."""
        node = self._make_node(
            node_type=node_type, label=label, source="manual",
            properties=properties, x=x, y=y,
        )
        self._data["nodes"].append(node)
        self._save()
        return node

    def update_node(self, node_id: str, **updates) -> dict:
        """Update a node's mutable fields.

        State nodes: only ``label``, ``x``, ``y`` are writable.
        Manual nodes: ``label``, ``type``, ``properties``, ``x``, ``y``.
        """
        node = self._node_by_id(node_id)
        if not node:
            raise GraphError(f"Node {node_id!r} not found")

        is_state = node.get("source") == "state"
        allowed = {"label", "x", "y"} if is_state else {"label", "type", "properties", "x", "y"}

        for k, v in updates.items():
            if k in allowed and v is not None:
                node[k] = v
        node["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._save()
        return node

    def delete_node(self, node_id: str):
        """Delete a manual node and all connected edges.

        Raises ValueError for state-sourced nodes.
        """
        node = self._node_by_id(node_id)
        if not node:
            raise GraphError(f"Node {node_id!r} not found")
        if node.get("source") == "state":
            raise GraphError("Cannot delete state-synced nodes")

        self._data["nodes"] = [n for n in self._data["nodes"] if n["id"] != node_id]
        self._data["edges"] = [
            e for e in self._data["edges"]
            if e["source"] != node_id and e["target"] != node_id
        ]
        self._save()

    # ------------------------------------------------------------------
    # Public: edge CRUD
    # ------------------------------------------------------------------

    def add_edge(self, source_id: str, target_id: str, label: str = "",
                 relationship: str = "related_to", directed: bool = True) -> dict:
        """Create an edge between any two nodes. Returns the created edge."""
        if source_id == target_id:
            raise GraphError("Self-edges are not allowed")
        if not self._node_by_id(source_id):
            raise GraphError(f"Source node {source_id!r} not found")
        if not self._node_by_id(target_id):
            raise GraphError(f"Target node {target_id!r} not found")
        if self._find_edge(source_id, target_id, relationship):
            raise GraphError(f"Edge with relationship {relationship!r} already exists between these nodes")

        edge = self._make_edge(
            source_id=source_id, target_id=target_id,
            label=label, relationship=relationship, directed=directed,
            source_origin="manual",
        )
        self._data["edges"].append(edge)
        self._save()
        return edge

    def update_edge(self, edge_id: str, **updates) -> dict:
        """Update an edge's label or relationship."""
        edge = self._edge_by_id(edge_id)
        if not edge:
            raise GraphError(f"Edge {edge_id!r} not found")
        for k in ("label", "relationship", "directed"):
            if k in updates and updates[k] is not None:
                edge[k] = updates[k]
        self._save()
        return edge

    def delete_edge(self, edge_id: str):
        """Delete any edge by id."""
        before = len(self._data["edges"])
        self._data["edges"] = [e for e in self._data["edges"] if e["id"] != edge_id]
        if len(self._data["edges"]) == before:
            raise GraphError(f"Edge {edge_id!r} not found")
        self._save()

    # ------------------------------------------------------------------
    # Public: positions
    # ------------------------------------------------------------------

    def update_positions(self, positions: list[dict]):
        """Bulk update node x/y positions.

        ``positions`` is a list of ``{"id": ..., "x": ..., "y": ...}``.
        """
        id_map = {n["id"]: n for n in self._data["nodes"]}
        for pos in positions:
            node = id_map.get(pos.get("id", ""))
            if node:
                node["x"] = pos.get("x")
                node["y"] = pos.get("y")
        self._save()

    # ------------------------------------------------------------------
    # Public: clear
    # ------------------------------------------------------------------

    def clear_manual(self):
        """Remove all manual nodes and their edges. State nodes survive."""
        manual_ids = {n["id"] for n in self._data["nodes"] if n.get("source") == "manual"}
        self._data["nodes"] = [n for n in self._data["nodes"] if n.get("source") != "manual"]
        # Remove edges where either endpoint was manual, or user-created edges
        self._data["edges"] = [
            e for e in self._data["edges"]
            if e["source"] not in manual_ids and e["target"] not in manual_ids
        ]
        self._save()
