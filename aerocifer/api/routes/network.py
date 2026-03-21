"""
Network Interfaces & Zones Management API
"""
from fastapi import APIRouter, Request

router = APIRouter()

@router.get("/interfaces")
async def get_interfaces(request: Request):
    ngfw = request.app.state.ngfw
    if not ngfw.db:
        return {"status": "error", "message": "Database offline"}
    ifaces = await ngfw.db.get_all_interfaces()
    return {"status": "success", "interfaces": [i.to_dict() for i in ifaces]}

@router.post("/interfaces")
async def create_interface(request: Request, body: dict):
    ngfw = request.app.state.ngfw
    import uuid
    uid = "vif_" + uuid.uuid4().hex[:6]
    dummy_iface = type("NetworkInterface", (), {
        "to_dict": lambda s: {
            "id": uid,
            "name": body.get("name", "new_interface"),
            "interface_type": body.get("interface_type", "Layer 3 Interfaces"),
            "ip_assignment": body.get("ip_assignment", "Static"),
            "ip_address": body.get("ip_address", "0.0.0.0"),
            "gateway": body.get("gateway", ""),
            "zone_id": None,
            "logs_allowed": 1,
            "status": "UP",
            "speed": "1000Mbps"
        }
    })()
    await ngfw.db.insert_interface(dummy_iface)
    return {"status": "success"}

@router.delete("/interfaces/{interface_id}")
async def delete_interface_api(request: Request, interface_id: str):
    ngfw = request.app.state.ngfw
    if ngfw.db:
        await ngfw.db.delete_interface(interface_id)
    return {"status": "success"}

@router.put("/interfaces/{interface_id}/status")
async def update_interface_status_api(request: Request, interface_id: str, body: dict):
    ngfw = request.app.state.ngfw
    status = body.get("status", "UP")
    if ngfw.db:
        await ngfw.db.update_interface_status(interface_id, status)
    return {"status": "success"}

@router.get("/zones")
async def get_zones_api(request: Request):
    ngfw = request.app.state.ngfw
    zones = await ngfw.db.get_all_zones()
    return {"status": "success", "zones": [z.to_dict() for z in zones]}

@router.post("/zones")
async def create_zone_api(request: Request, body: dict):
    ngfw = request.app.state.ngfw
    import uuid, time
    uid = "zone_" + uuid.uuid4().hex[:6]
    dummy_zone = type("Zone", (), {
        "to_dict": lambda s: {
            "id": uid,
            "name": body.get("name", "New Zone"),
            "description": body.get("protection_level", "Standard"),
            "subnet": "",
            "vlan_id": None,
            "policy": "standard",
            "allowed_protocols": '[]',
            "blocked_protocols": '[]',
            "max_bandwidth_mbps": None,
            "created_at": time.time(),
            "updated_at": time.time(),
            "is_active": 1,
            "device_count": 0
        }
    })()
    await ngfw.db.insert_zone(dummy_zone)
    return {"status": "success"}

@router.delete("/zones/{zone_id}")
async def delete_zone_api(request: Request, zone_id: str):
    ngfw = request.app.state.ngfw
    if ngfw.db:
        await ngfw.db.delete_zone(zone_id)
    return {"status": "success"}
