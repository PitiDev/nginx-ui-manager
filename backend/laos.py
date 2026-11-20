"""Lao PDR province lookup + aggregation for the Security Monitor's Laos map.

Province of a geolocated client = the province polygon containing its
coordinates (same boundary file the browser draws, so map and table agree),
falling back to the GeoIP region name, then to the nearest province.

Accuracy note: IP geolocation inside Laos is coarse — most mobile/broadband
carriers egress through Vientiane, so the majority of Lao users resolve to
Vientiane Capital regardless of where they physically are.
"""

import json
import math
import re
from functools import lru_cache
from pathlib import Path

GEOJSON = Path(__file__).resolve().parent.parent / "frontend" / "static" / "vendor" / "lao-provinces.geojson"

# ISO 3166-2:LA → (English, Lao)
PROVINCES = {
    "LA-VT": ("Vientiane Capital", "ນະຄອນຫຼວງວຽງຈັນ"),
    "LA-PH": ("Phongsaly", "ຜົ້ງສາລີ"),
    "LA-LM": ("Luang Namtha", "ຫຼວງນ້ຳທາ"),
    "LA-OU": ("Oudomxay", "ອຸດົມໄຊ"),
    "LA-BK": ("Bokeo", "ບໍ່ແກ້ວ"),
    "LA-LP": ("Luang Prabang", "ຫຼວງພະບາງ"),
    "LA-HO": ("Houaphanh", "ຫົວພັນ"),
    "LA-XA": ("Xayaboury", "ໄຊຍະບູລີ"),
    "LA-XI": ("Xiengkhouang", "ຊຽງຂວາງ"),
    "LA-VI": ("Vientiane Province", "ແຂວງວຽງຈັນ"),
    "LA-BL": ("Bolikhamxay", "ບໍລິຄຳໄຊ"),
    "LA-KH": ("Khammouane", "ຄຳມ່ວນ"),
    "LA-SV": ("Savannakhet", "ສະຫວັນນະເຂດ"),
    "LA-SL": ("Salavan", "ສາລະວັນ"),
    "LA-XE": ("Sekong", "ເຊກອງ"),
    "LA-CH": ("Champasak", "ຈຳປາສັກ"),
    "LA-AT": ("Attapeu", "ອັດຕະປື"),
    "LA-XN": ("Xaisomboun", "ໄຊສົມບູນ"),
}

# GeoIP region spellings seen in DB-IP / MaxMind → ISO
_REGION_ALIASES = {
    "vientiane prefecture": "LA-VT", "vientiane capital": "LA-VT", "vientiane municipality": "LA-VT",
    "vientiane": "LA-VI", "vientiane province": "LA-VI",
    "champasak": "LA-CH", "champassak": "LA-CH", "savannakhet": "LA-SV", "luang prabang": "LA-LP",
    "louangphabang": "LA-LP", "xiangkhoang": "LA-XI", "xiangkhouang": "LA-XI", "xiengkhouang": "LA-XI",
    "xiagnabouli": "LA-XA", "xaignabouli": "LA-XA", "xayaboury": "LA-XA", "sainyabuli": "LA-XA",
    "bokeo": "LA-BK", "bolikhamsai": "LA-BL", "bolikhamxay": "LA-BL", "borikhamxay": "LA-BL",
    "salavan": "LA-SL", "saravane": "LA-SL", "xaisomboun": "LA-XN", "saysomboun": "LA-XN",
    "khammouane": "LA-KH", "khammouan": "LA-KH", "attapeu": "LA-AT", "attapu": "LA-AT",
    "sekong": "LA-XE", "xekong": "LA-XE", "oudomxay": "LA-OU", "oudomxai": "LA-OU", "udomxai": "LA-OU",
    "luang namtha": "LA-LM", "louangnamtha": "LA-LM", "phongsaly": "LA-PH", "phongsali": "LA-PH",
    "houaphan": "LA-HO", "houaphanh": "LA-HO", "hua phan": "LA-HO",
}

_shapes = None  # list of (iso, bbox, polygons[[outer, *holes]], centroid)


def _load():
    global _shapes
    if _shapes is not None:
        return _shapes
    _shapes = []
    try:
        data = json.loads(GEOJSON.read_text())
    except (OSError, ValueError):
        return _shapes
    for f in data["features"]:
        g = f["geometry"]
        polys = [g["coordinates"]] if g["type"] == "Polygon" else g["coordinates"]
        xs = [p[0] for poly in polys for p in poly[0]]
        ys = [p[1] for poly in polys for p in poly[0]]
        bbox = (min(xs), min(ys), max(xs), max(ys))
        centroid = (sum(xs) / len(xs), sum(ys) / len(ys))
        _shapes.append((f["properties"]["iso"], bbox, polys, centroid))
    return _shapes


def _in_ring(x, y, ring) -> bool:
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i]
        xj, yj = ring[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _norm(s: str) -> str:
    return re.sub(r"\s+(province|prefecture)$", "", (s or "").strip().lower()) if s else ""


@lru_cache(maxsize=8192)
def province_of(lat: float, lon: float, region: str = "") -> str | None:
    """ISO code of the province containing (lat, lon)."""
    shapes = _load()
    for iso, (x0, y0, x1, y1), polys, _ in shapes:
        if x0 <= lon <= x1 and y0 <= lat <= y1:
            for poly in polys:
                if _in_ring(lon, lat, poly[0]) and not any(_in_ring(lon, lat, h) for h in poly[1:]):
                    return iso
    r = (region or "").strip().lower()
    if r in _REGION_ALIASES:
        return _REGION_ALIASES[r]
    if _norm(region) in _REGION_ALIASES:
        return _REGION_ALIASES[_norm(region)]
    # just outside a simplified border (e.g. on the Mekong): nearest centroid
    if shapes and 13.5 <= lat <= 22.6 and 100 <= lon <= 108:
        return min(shapes, key=lambda s: math.hypot(s[3][0] - lon, s[3][1] - lat))[0]
    return None


def summarize(clients: list) -> dict:
    """clients: [{ip, hits, threat_hits, score, is_attacker, geo}] → per-province
    and per-location aggregates for clients geolocated to Laos."""
    prov = {iso: {"iso": iso, "name": en, "name_lo": lo, "users": 0, "requests": 0,
                  "threats": 0, "attackers": 0, "score": 0, "cities": {}}
            for iso, (en, lo) in PROVINCES.items()}
    points: dict = {}
    total_users = total_req = 0
    for c in clients:
        g = c.get("geo")
        if not g or g.get("cc") != "LA" or g.get("lat") is None:
            continue
        iso = province_of(round(g["lat"], 3), round(g["lon"], 3), g.get("region") or "")
        if not iso:
            continue
        total_users += 1
        total_req += c["hits"]
        p = prov[iso]
        p["users"] += 1
        p["requests"] += c["hits"]
        p["threats"] += c["threat_hits"]
        if c["is_attacker"]:
            p["attackers"] += 1
            p["score"] = max(p["score"], c["score"])
        city = g.get("city") or p["name"]
        p["cities"][city] = p["cities"].get(city, 0) + 1
        key = (round(g["lat"], 2), round(g["lon"], 2))
        pt = points.get(key)
        if pt is None:
            pt = points[key] = {"lat": g["lat"], "lon": g["lon"], "city": city, "province": iso,
                                "users": 0, "requests": 0, "threats": 0, "attackers": 0, "score": 0}
        pt["users"] += 1
        pt["requests"] += c["hits"]
        pt["threats"] += c["threat_hits"]
        if c["is_attacker"]:
            pt["attackers"] += 1
            pt["score"] = max(pt["score"], c["score"])
    for p in prov.values():
        p["top_cities"] = [k for k, _ in sorted(p["cities"].items(), key=lambda kv: -kv[1])[:4]]
        del p["cities"]
    return {
        "users": total_users,
        "requests": total_req,
        "active_provinces": sum(1 for p in prov.values() if p["users"]),
        "provinces": sorted(prov.values(), key=lambda p: (-p["users"], -p["requests"], p["name"])),
        "points": sorted(points.values(), key=lambda p: -p["users"])[:300],
    }
