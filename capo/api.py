"""API for exposing C.A.P.O. state and configuration."""

import re
import yaml
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from capo import config
from capo.campaign import CampaignManager
from capo.state import StateManager

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

app = FastAPI(title="Capo Studio API", description="C.A.P.O Studio — state, suggestions, and cheatsheet management")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    current_target: Optional[str]
    workspace_dir: Optional[str]
    active_campaign: Optional[str]

class EngagementStatus(BaseModel):
    target: Optional[str]
    campaign: Optional[str]
    state: Optional[dict[str, Any]]

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
    for var in re.findall(r"\{(\w+)\}", text):
        val = sm.get_var(var)
        if val:
            text = text.replace(f"{{{var}}}", val)
    return text


def _load_suggestion_rules():
    """Load SuggestionRule objects from core_rules/."""
    from capo.modules.suggestion_rules import SuggestionRule
    rules = []
    rules_dir = Path(__file__).parent / "core_rules"
    if not rules_dir.exists():
        return rules
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
                "wpscan --url http://{IP} -e ap,at,u", "capo query wordpress"
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
# Frontend static file serving
# ---------------------------------------------------------------------------

@app.get("/")
def serve_index():
    return FileResponse(_FRONTEND_DIR / "index.html")

app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("capo.api:app", host="127.0.0.1", port=8000, reload=True)
