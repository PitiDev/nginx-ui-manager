import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

DATA_DIR   = Path(os.getenv("DATA_DIR", "/data"))
NODES_FILE = DATA_DIR / "nodes.json"


def _read() -> list[dict]:
    try:
        return json.loads(NODES_FILE.read_text())
    except Exception:
        return []


def _write(nodes: list[dict]) -> None:
    NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    NODES_FILE.write_text(json.dumps(nodes, indent=2))


def list_nodes() -> list[dict]:
    return _read()


def get_node(node_id: str) -> Optional[dict]:
    return next((n for n in _read() if n["id"] == node_id), None)


def create_node(data: dict) -> tuple[bool, str]:
    name = data.get("name", "").strip()
    host = data.get("host", "").strip()
    if not name or not host:
        return False, "Name and host are required"
    nodes = _read()
    node: dict = {
        "id":              str(uuid.uuid4()),
        "name":            name,
        "host":            host,
        "port":            int(data.get("port") or 22),
        "username":        (data.get("username") or "root").strip(),
        "auth_type":       data.get("auth_type", "password"),
        "password":        data.get("password", ""),
        "ssh_key":         data.get("ssh_key", ""),
        "sudo_password":   data.get("sudo_password", ""),
        "sites_available": data.get("sites_available") or "/etc/nginx/sites-available",
        "sites_enabled":   data.get("sites_enabled")   or "/etc/nginx/sites-enabled",
        "created_at":      datetime.utcnow().isoformat(),
    }
    nodes.append(node)
    _write(nodes)
    return True, f"Node '{name}' added"


def update_node(node_id: str, data: dict) -> tuple[bool, str]:
    nodes = _read()
    for i, n in enumerate(nodes):
        if n["id"] == node_id:
            name = (data.get("name") or n["name"]).strip()
            nodes[i] = {
                **n,
                "name":            name,
                "host":            (data.get("host") or n["host"]).strip(),
                "port":            int(data.get("port") or n.get("port", 22)),
                "username":        (data.get("username") or n["username"]).strip(),
                "auth_type":       data.get("auth_type", n["auth_type"]),
                "sites_available": data.get("sites_available") or n["sites_available"],
                "sites_enabled":   data.get("sites_enabled")   or n["sites_enabled"],
            }
            # Keep existing credentials unless new ones are provided
            if data.get("password"):
                nodes[i]["password"] = data["password"]
            if data.get("ssh_key"):
                nodes[i]["ssh_key"] = data["ssh_key"]
            if data.get("sudo_password"):
                nodes[i]["sudo_password"] = data["sudo_password"]
            _write(nodes)
            return True, f"Node '{name}' updated"
    return False, "Node not found"


def delete_node(node_id: str) -> tuple[bool, str]:
    nodes = _read()
    filtered = [n for n in nodes if n["id"] != node_id]
    if len(filtered) == len(nodes):
        return False, "Node not found"
    _write(filtered)
    return True, "Node deleted"
