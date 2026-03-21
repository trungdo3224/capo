"""API for exposing C.A.P.O. state and configuration."""

import re
import yaml
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from capo import config
from capo.campaign import CampaignManager
from capo.config import CORS_ALLOWED_ORIGINS
from capo.errors import GraphError, SessionError
from capo.state import StateManager

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Auto-sync writeup sources on server startup."""
    try:
        from capo.modules.writeup_sync import writeup_sync_manager
        writeup_sync_manager.sync()
    except Exception:
        pass  # Don't block startup if sync fails
    yield


app = FastAPI(
    title="Capo Studio API",
    description="C.A.P.O Studio — state, suggestions, and cheatsheet management",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ConfigModel(BaseModel):
    capo_home: str
    workspaces_dir: str
    campaigns_dir: str
    custom_cheatsheets_dir: str
    config_file: str

class StateModel(BaseModel):
    current_target: str | None
    workspace_dir: str | None
    active_campaign: str | None

class EngagementStatus(BaseModel):
    target: str | None
    campaign: str | None
    state: dict[str, Any] | None

class GraphNodeCreate(BaseModel):
    type: str
    label: str
    properties: dict[str, Any] = {}
    x: float | None = None
    y: float | None = None

class GraphNodeUpdate(BaseModel):
    label: str | None = None
    type: str | None = None
    properties: dict[str, Any] | None = None
    x: float | None = None
    y: float | None = None

class GraphEdgeCreate(BaseModel):
    source: str
    target: str
    label: str = ""
    relationship: str = "related_to"
    directed: bool = True

class GraphEdgeUpdate(BaseModel):
    label: str | None = None
    relationship: str | None = None
    directed: bool | None = None

class PositionUpdate(BaseModel):
    id: str
    x: float
    y: float

class SessionCreate(BaseModel):
    name: str
    target_ip: str
    domain: str = ""
    campaign: str = ""

class ManualCommandLog(BaseModel):
    command: str
    tool: str = "manual"

class CommandKeyToggle(BaseModel):
    is_key: bool

class FindingCreate(BaseModel):
    title: str
    description: str = ""
    command_id: int | None = None
    category: str = "general"
    severity: str = "info"

# ---------------------------------------------------------------------------
# Helpers: YAML file management (cheatsheets / methodologies)
# ---------------------------------------------------------------------------

_FILENAME_RE = re.compile(r'^[a-zA-Z0-9_-]+\.yaml$')


def _validate_filename(filename: str) -> None:
    if not _FILENAME_RE.match(filename):
        raise HTTPException(status_code=400, detail=f"Invalid filename: {filename!r}")


def _list_files(core_dir: Path, custom_dir: Path) -> list[str]:
    """Merge YAML filenames from core and custom dirs; custom overrides core on collision."""
    files: dict[str, None] = {}
    for d in (core_dir, custom_dir):
        if d.exists():
            for p in sorted(d.glob("*.yaml")):
                files[p.name] = None
    return list(files)


def _load_yaml(core_dir: Path, custom_dir: Path, filename: str) -> dict:
    """Load a YAML file, checking custom dir first then core dir."""
    for d in (custom_dir, core_dir):
        path = d / filename
        if path.exists():
            with path.open(encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    raise HTTPException(status_code=404, detail=f"{filename!r} not found")


def _save_yaml(custom_dir: Path, filename: str, data: dict) -> None:
    """Save data as YAML to the custom dir (copy-on-write; never touches core files)."""
    custom_dir.mkdir(parents=True, exist_ok=True)
    path = custom_dir / filename
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

# ---------------------------------------------------------------------------
# Helpers: Suggestions
# ---------------------------------------------------------------------------

def _inject(text: str, sm: StateManager) -> str:
    """Replace {VAR} placeholders using a StateManager instance."""
    from capo.utils.inject import inject_vars
    return inject_vars(text, state_manager=sm)


def _load_suggestion_rules():
    """Load SuggestionRule objects from core_rules/ and writeup_rules/."""
    from capo.modules.suggestion_rules import SuggestionRule
    rules = []
    rule_dirs = [
        Path(__file__).parent / "core_rules",
        config.WRITEUP_RULES_DIR,
    ]
    for rules_dir in rule_dirs:
        if not rules_dir.exists():
            continue
        for rule_file in sorted(rules_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    rules.extend(SuggestionRule(item) for item in data)
            except Exception:
                pass
    return rules


def _build_suggestions(sm: StateManager) -> dict:
    """Compute all active suggestions for the current target state."""
    if not sm.target:
        return {"target": None, "port_triggers": [], "contextual": [], "rule_suggestions": []}

    state_data = sm.state
    open_ports = sm.get_open_ports()

    # --- 1. Port-based triggers ---
    from capo.modules.triggers import get_merged_triggers
    merged = get_merged_triggers()
    port_triggers = []
    for port in sorted(open_ports):
        for trigger in merged.get(port, []):
            port_triggers.append({
                "port": port,
                "title": trigger["title"],
                "commands": [_inject(s, sm) for s in trigger["suggestions"]],
            })

    # --- 2. Contextual suggestions ---
    contextual = []

    # AD environment heuristic
    ad_ports = {88, 389, 636, 445, 135, 139}
    if len(ad_ports & set(open_ports)) >= 3:
        domain = sm.get_var("DOMAIN") or ""
        users = state_data.get("users", [])
        if domain and users:
            contextual.append({
                "title": "Active Directory environment with known users",
                "commands": [
                    f"capo query asrep-roast  (AS-REP Roasting — {len(users)} users)",
                    "capo query kerberoast   (Enumerate SPNs)",
                    "capo query bloodhound   (Run BloodHound collection)",
                ],
            })

    # Web findings
    for d in state_data.get("directories", []):
        path = d.get("path", "").lower()
        if "wp-" in path:
            contextual.append({"title": "WordPress detected!", "commands": [
                _inject("wpscan --url http://{IP} -e ap,at,u", sm), "capo query wordpress"
            ]})
            break
        if "cgi-bin" in path:
            contextual.append({"title": "CGI-bin found — Check Shellshock", "commands": [
                "capo query shellshock"
            ]})
            break

    # Credentials → access suggestions
    creds = state_data.get("credentials", [])
    if creds:
        port_set = set(open_ports)
        cmds = []
        if 5985 in port_set: cmds.append(_inject("evil-winrm -i {IP} -u {USER} -p {PASS}", sm))
        if 22 in port_set:   cmds.append(_inject("ssh {USER}@{IP}", sm))
        if 3389 in port_set: cmds.append(_inject("xfreerdp /v:{IP} /u:{USER} /p:{PASS}", sm))
        if cmds:
            contextual.append({"title": f"Found {len(creds)} credential(s) — Try access", "commands": cmds})

    # Applicable methodologies not yet started
    try:
        from capo.modules.methodology import methodology_engine
        methodology_engine.load_all()
        progress = state_data.get("methodology_progress", {})
        meth_cmds = [
            f"capo methodology start {m.name}  ({m.display_name})"
            for m in methodology_engine.get_applicable()
            if m.name not in progress
        ]
        if meth_cmds:
            contextual.append({"title": "Applicable methodology workflows", "commands": meth_cmds})
    except Exception:
        pass

    # --- 3. Rule-based suggestions (YAML rules) ---
    rules = _load_suggestion_rules()
    rule_suggestions = []
    for rule in sorted(rules, key=lambda r: str(r.priority)):
        if rule.evaluate(state_data):
            rule_suggestions.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "priority": rule.priority,
                "command": _inject(rule.command_template, sm),
                "source": rule.source_reference,
            })

    return {
        "target": sm.target,
        "port_triggers": port_triggers,
        "contextual": contextual,
        "rule_suggestions": rule_suggestions,
    }

# ---------------------------------------------------------------------------
# Existing endpoints
# ---------------------------------------------------------------------------

@app.get("/api/config", response_model=ConfigModel)
def get_config():
    """Get core Capo configuration paths."""
    return ConfigModel(
        capo_home=str(config.CAPO_HOME),
        workspaces_dir=str(config.WORKSPACES_DIR),
        campaigns_dir=str(config.CAMPAIGNS_DIR),
        custom_cheatsheets_dir=str(config.CUSTOM_CHEATSHEETS_DIR),
        config_file=str(config.CONFIG_FILE)
    )

@app.get("/api/state", response_model=StateModel)
def get_state():
    """Get current active state (target, workspace, campaign)."""
    sm = StateManager()
    cm = CampaignManager()
    ws = sm.workspace
    return StateModel(
        current_target=sm.target,
        workspace_dir=str(ws) if ws else None,
        active_campaign=cm.name
    )

# ---------------------------------------------------------------------------
# Cheatsheets
# ---------------------------------------------------------------------------

@app.get("/api/cheatsheets", response_model=list[str])
def list_cheatsheets():
    """List all available cheatsheet filenames (core + custom)."""
    return _list_files(config.CORE_CHEATSHEETS_DIR, config.CUSTOM_CHEATSHEETS_DIR)


@app.get("/api/cheatsheets/{filename}")
def get_cheatsheet(filename: str):
    """Load a cheatsheet YAML file and return it as JSON."""
    _validate_filename(filename)
    return _load_yaml(config.CORE_CHEATSHEETS_DIR, config.CUSTOM_CHEATSHEETS_DIR, filename)


@app.post("/api/cheatsheets/{filename}", status_code=204)
def save_cheatsheet(filename: str, data: dict):
    """Save an edited cheatsheet. Always writes to the custom dir."""
    _validate_filename(filename)
    _save_yaml(config.CUSTOM_CHEATSHEETS_DIR, filename, data)
    return Response(status_code=204)

# ---------------------------------------------------------------------------
# Methodologies
# ---------------------------------------------------------------------------

@app.get("/api/methodologies", response_model=list[str])
def list_methodologies():
    """List all available methodology filenames (core + custom)."""
    return _list_files(config.CORE_METHODOLOGIES_DIR, config.CUSTOM_METHODOLOGIES_DIR)


@app.get("/api/methodologies/{filename}")
def get_methodology(filename: str):
    """Load a methodology YAML file and return it as JSON."""
    _validate_filename(filename)
    return _load_yaml(config.CORE_METHODOLOGIES_DIR, config.CUSTOM_METHODOLOGIES_DIR, filename)


@app.post("/api/methodologies/{filename}", status_code=204)
def save_methodology(filename: str, data: dict):
    """Save an edited methodology. Always writes to the custom dir."""
    _validate_filename(filename)
    _save_yaml(config.CUSTOM_METHODOLOGIES_DIR, filename, data)
    return Response(status_code=204)

# ---------------------------------------------------------------------------
# Engagement status
# ---------------------------------------------------------------------------

@app.get("/api/engagement/status", response_model=EngagementStatus)
def get_engagement_status():
    """Get active engagement: target, campaign, and full state data."""
    sm = StateManager()
    cm = CampaignManager()
    return EngagementStatus(
        target=sm.target,
        campaign=cm.name,
        state=sm.state if sm.target else None,
    )

# ---------------------------------------------------------------------------
# Suggestions
# ---------------------------------------------------------------------------

@app.get("/api/suggestions")
def get_suggestions():
    """Get all active context-aware suggestions for the current target."""
    sm = StateManager()
    return _build_suggestions(sm)

# ---------------------------------------------------------------------------
# Custom triggers management
# ---------------------------------------------------------------------------

@app.get("/api/triggers/custom")
def get_custom_triggers():
    """Return custom triggers as a port→entries dict."""
    if not config.CUSTOM_TRIGGERS_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(config.CUSTOM_TRIGGERS_FILE.read_text(encoding="utf-8")) or {}
        return data.get("triggers", {})
    except yaml.YAMLError:
        return {}


@app.post("/api/triggers/custom", status_code=204)
def save_custom_triggers(triggers: dict):
    """Save custom triggers (port→entries dict) back to custom_triggers.yaml."""
    config.CAPO_HOME.mkdir(parents=True, exist_ok=True)
    content = yaml.dump(
        {"triggers": triggers},
        allow_unicode=True, default_flow_style=False, sort_keys=False
    )
    config.CUSTOM_TRIGGERS_FILE.write_text(content, encoding="utf-8")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Knowledge Graph
# ---------------------------------------------------------------------------

def _get_graph_manager():
    """Instantiate a GraphManager for the current target workspace."""
    from capo.graph import GraphManager
    sm = StateManager()
    if not sm.target or not sm.workspace:
        raise HTTPException(status_code=400, detail="No active target")
    gm = GraphManager()
    gm.load_for_target(sm.workspace, sm.target)
    return gm, sm


@app.get("/api/graph")
def get_graph():
    """Return the full knowledge graph, auto-synced from current state."""
    gm, sm = _get_graph_manager()
    gm.sync_from_state(sm.state)
    return gm.get_graph()


@app.post("/api/graph/nodes")
def create_graph_node(body: GraphNodeCreate):
    """Create a manual node."""
    gm, _ = _get_graph_manager()
    node = gm.add_node(
        node_type=body.type, label=body.label,
        properties=body.properties, x=body.x, y=body.y,
    )
    return node


@app.put("/api/graph/nodes/{node_id}")
def update_graph_node(node_id: str, body: GraphNodeUpdate):
    """Update a node (state nodes: position/label only)."""
    gm, _ = _get_graph_manager()
    try:
        return gm.update_node(node_id, **body.model_dump(exclude_none=True))
    except GraphError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/api/graph/nodes/{node_id}", status_code=204)
def delete_graph_node(node_id: str):
    """Delete a manual node and its edges. Rejects state nodes."""
    gm, _ = _get_graph_manager()
    try:
        gm.delete_node(node_id)
    except GraphError as exc:
        raise HTTPException(status_code=400 if "state-synced" in str(exc) else 404, detail=str(exc))
    return Response(status_code=204)


@app.post("/api/graph/edges")
def create_graph_edge(body: GraphEdgeCreate):
    """Create an edge between any two nodes."""
    gm, _ = _get_graph_manager()
    try:
        return gm.add_edge(
            source_id=body.source, target_id=body.target,
            label=body.label, relationship=body.relationship,
            directed=body.directed,
        )
    except GraphError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/graph/edges/{edge_id}")
def update_graph_edge(edge_id: str, body: GraphEdgeUpdate):
    """Update an edge's label or relationship."""
    gm, _ = _get_graph_manager()
    try:
        return gm.update_edge(edge_id, **body.model_dump(exclude_none=True))
    except GraphError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/api/graph/edges/{edge_id}", status_code=204)
def delete_graph_edge(edge_id: str):
    """Delete an edge."""
    gm, _ = _get_graph_manager()
    try:
        gm.delete_edge(edge_id)
    except GraphError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(status_code=204)


@app.post("/api/graph/positions", status_code=204)
def save_graph_positions(positions: list[PositionUpdate]):
    """Bulk update node positions (for drag persistence)."""
    gm, _ = _get_graph_manager()
    gm.update_positions([p.model_dump() for p in positions])
    return Response(status_code=204)


@app.post("/api/graph/clear", status_code=204)
def clear_graph():
    """Clear manual nodes and their edges. State nodes survive."""
    gm, _ = _get_graph_manager()
    gm.clear_manual()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _get_session_db():
    from capo.modules.session_db import SessionDB
    return SessionDB()


@contextmanager
def _temporary_session(db, name: str):
    """Activate *name* for the duration of the block, then restore the previous session."""
    prev_name = db.active_session_name
    db.activate_session(name)
    try:
        yield db
    finally:
        if prev_name and prev_name != name:
            db.activate_session(prev_name)
        elif not prev_name:
            db.deactivate_session()


@app.get("/api/sessions")
def list_sessions():
    """List all sessions."""
    db = _get_session_db()
    sessions = db.list_sessions()
    # Attach command count to each session
    for s in sessions:
        summary = db.session_summary(s["name"])
        s["total_commands"] = summary.get("total_commands", 0)
        s["key_steps"] = summary.get("key_steps", 0)
        s["findings_count"] = summary.get("findings_count", 0)
    return sessions


@app.post("/api/sessions")
def create_session(body: SessionCreate):
    """Create a new session and activate it."""
    db = _get_session_db()
    try:
        session = db.create_session(body.name, body.target_ip, body.domain, body.campaign)
    except SessionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    db.activate_session(body.name)
    # Also set target + campaign via managers
    sm = StateManager()
    sm.set_target(body.target_ip)
    if body.domain:
        sm.add_domain(body.domain)
    if body.campaign:
        cm = CampaignManager()
        cm.set_campaign(body.campaign)
    return session


@app.get("/api/sessions/active")
def get_active_session():
    """Get the currently active session with summary."""
    db = _get_session_db()
    session = db.get_active_session()
    if not session:
        return None
    return db.session_summary(session["name"])


@app.post("/api/sessions/{name}/activate")
def activate_session(name: str):
    """Switch to an existing session."""
    db = _get_session_db()
    try:
        session = db.activate_session(name)
    except SessionError as e:
        raise HTTPException(status_code=404, detail=str(e))
    sm = StateManager()
    sm.set_target(session["target_ip"])
    if session.get("domain"):
        sm.add_domain(session["domain"])
    if session.get("campaign"):
        cm = CampaignManager()
        cm.set_campaign(session["campaign"])
    return session


@app.get("/api/sessions/{name}")
def get_session(name: str):
    """Get session detail with summary."""
    db = _get_session_db()
    summary = db.session_summary(name)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")
    return summary


@app.delete("/api/sessions/{name}", status_code=204)
def delete_session(name: str):
    """Delete a session and all its data."""
    db = _get_session_db()
    try:
        db.delete_session(name)
    except SessionError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return Response(status_code=204)


@app.get("/api/sessions/{name}/commands")
def list_session_commands(
    name: str,
    key_only: bool = False,
    tool: str | None = None,
):
    """List commands for a session."""
    db = _get_session_db()
    return db.list_commands(session_name=name, key_only=key_only, tool=tool)


@app.post("/api/sessions/{name}/commands")
def log_manual_command(name: str, body: ManualCommandLog):
    """Log a manual command to a session."""
    db = _get_session_db()
    session = db.get_session(name)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")
    with _temporary_session(db, name):
        cmd_id = db.record_command(tool=body.tool, command=body.command, source="manual")
    return {"id": cmd_id}


@app.put("/api/sessions/commands/{cmd_id}/key")
def toggle_command_key(cmd_id: int, body: CommandKeyToggle):
    """Toggle the key flag on a command."""
    db = _get_session_db()
    cmd = db.get_command(cmd_id)
    if not cmd:
        raise HTTPException(status_code=404, detail=f"Command #{cmd_id} not found")
    db.mark_key(cmd_id, body.is_key)
    return {"id": cmd_id, "is_key": body.is_key}


@app.get("/api/sessions/{name}/findings")
def list_session_findings(name: str):
    """List findings for a session."""
    db = _get_session_db()
    return db.list_findings(session_name=name)


@app.post("/api/sessions/{name}/findings")
def create_finding(name: str, body: FindingCreate):
    """Create a finding for a session."""
    db = _get_session_db()
    session = db.get_session(name)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")
    with _temporary_session(db, name):
        fid = db.add_finding(
            title=body.title,
            description=body.description,
            command_id=body.command_id,
            category=body.category,
            severity=body.severity,
        )
    return {"id": fid}


@app.delete("/api/sessions/findings/{finding_id}", status_code=204)
def delete_finding(finding_id: int):
    """Delete a finding."""
    db = _get_session_db()
    db.delete_finding(finding_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Frontend static file serving
# ---------------------------------------------------------------------------

@app.get("/")
def serve_index():
    return FileResponse(_FRONTEND_DIR / "index.html")

app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("capo.api:app", host="127.0.0.1", port=8000, reload=True)
