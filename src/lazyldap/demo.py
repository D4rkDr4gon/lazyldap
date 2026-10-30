"""
demo.py — `lazyldap --demo`: un Active Directory falso para probar la TUI sin
servidor (y para las capturas del README).

Usa el servidor simulado de ldap3 (MOCK_SYNC) con el esquema de Windows
Server 2012 R2 que trae ldap3 (OFFLINE_AD_2012_R2), así los GUID, SID y
fechas se ven como en un AD real. Perfiles y estado van a una carpeta
temporal: no toca ~/.config/lazyldap. La contraseña sale de un "keyring"
falso. El mock no evalúa reglas de coincidencia extendidas (los filtros con
OID de AD); un AD real sí.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from pathlib import Path

DOMAIN = "DC=acme,DC=local"
HOST = "dc01.acme.local"
ADMIN = f"CN=Administrator,CN=Users,{DOMAIN}"
PASSWORD = "demo"

PEOPLE = [
    # nombre, apellido, cuenta, puesto, área, OU, deshabilitado
    ("Ana", "García", "agarcia", "IT Manager", "IT", "IT", False),
    ("Bruno", "Fernández", "bfernandez", "Sysadmin", "IT", "IT", False),
    ("Carla", "Méndez", "cmendez", "Security Analyst", "IT", "IT", False),
    ("Diego", "Torres", "dtorres", "Network Engineer", "IT", "IT", True),
    ("Elena", "Ruiz", "eruiz", "CFO", "Finance", "Finance", False),
    ("Facundo", "López", "flopez", "Accountant", "Finance", "Finance", False),
    ("Gabriela", "Sosa", "gsosa", "Payroll Analyst", "Finance", "Finance", True),
    ("Hernán", "Castro", "hcastro", "Sales Lead", "Sales", "Sales", False),
    ("Inés", "Romero", "iromero", "Account Executive", "Sales", "Sales", False),
    ("Julián", "Díaz", "jdiaz", "Account Executive", "Sales", "Sales", False),
    ("Karina", "Vega", "kvega", "HR Partner", "HR", "HR", False),
    ("Lucas", "Molina", "lmolina", "Recruiter", "HR", "HR", False),
]
GROUPS = {
    "Domain Admins": ["agarcia", "bfernandez"],
    "IT Operations": ["agarcia", "bfernandez", "cmendez", "dtorres"],
    "VPN Users": ["agarcia", "bfernandez", "cmendez", "eruiz", "hcastro", "iromero"],
    "Finance": ["eruiz", "flopez", "gsosa"],
    "Sales": ["hcastro", "iromero", "jdiaz"],
    "HR": ["kvega", "lmolina"],
}
COMPUTERS = ["WS-0101", "WS-0102", "WS-0103", "WS-0204", "NB-0301", "NB-0302"]
SERVERS = ["SRV-DC01", "SRV-FILE01", "SRV-SQL01"]


def _guid(seed: str) -> bytes:
    return uuid.UUID(bytes=hashlib.md5(seed.encode()).digest()).bytes_le


def _sid(rid: int) -> bytes:
    sub = [21, 3569595041, 3098015461, 4074885321, rid]
    return bytes([1, len(sub), 0, 0, 0, 0, 0, 5]) + b"".join(x.to_bytes(4, "little") for x in sub)


def _when(i: int) -> str:
    return f"2025{1 + i % 12:02d}{1 + (i * 7) % 27:02d}0930{i % 60:02d}.0Z"


def entries() -> list[tuple[str, dict]]:
    out = [
        (DOMAIN, {"objectClass": ["top", "domain", "domainDNS"], "dc": "acme", "name": "acme",
                  "objectGUID": _guid("domain"), "objectSid": _sid(0)[:-4], "whenCreated": _when(0)}),
        (f"CN=Users,{DOMAIN}", {"objectClass": ["top", "container"], "cn": "Users",
                                 "description": "Default container for upgraded user accounts"}),
        (ADMIN, {"objectClass": ["top", "person", "organizationalPerson", "user"], "cn": "Administrator",
                 "sAMAccountName": "Administrator", "userPassword": PASSWORD, "userAccountControl": "66048",
                 "description": "Built-in account for administering the computer/domain",
                 "objectGUID": _guid("admin"), "objectSid": _sid(500), "whenCreated": _when(1)}),
        (f"CN=Builtin,{DOMAIN}", {"objectClass": ["top", "builtinDomain"], "cn": "Builtin"}),
        (f"OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": "Acme",
                                "description": "Acme Corp"}),
        (f"OU=Users,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": "Users"}),
        (f"OU=Groups,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": "Groups"}),
        (f"OU=Computers,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": "Computers"}),
        (f"OU=Servers,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": "Servers"}),
        (f"OU=Service Accounts,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"],
                                                    "ou": "Service Accounts"}),
    ]
    dn_of = {}
    for ou in sorted({p[5] for p in PEOPLE}):
        out.append((f"OU={ou},OU=Users,OU=Acme,{DOMAIN}", {"objectClass": ["top", "organizationalUnit"], "ou": ou}))
    member_of: dict[str, list[str]] = {}
    for g, members in GROUPS.items():
        for m in members:
            member_of.setdefault(m, []).append(f"CN={g},OU=Groups,OU=Acme,{DOMAIN}")
    for i, (gn, sn, sam, title, dept, ou, disabled) in enumerate(PEOPLE):
        dn = f"CN={gn} {sn},OU={ou},OU=Users,OU=Acme,{DOMAIN}"
        dn_of[sam] = dn
        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": f"{gn} {sn}", "givenName": gn, "sn": sn, "displayName": f"{gn} {sn}",
            "sAMAccountName": sam, "userPrincipalName": f"{sam}@acme.local", "mail": f"{sam}@acme.com",
            "title": title, "department": dept, "company": "Acme Corp",
            "telephoneNumber": f"+54 11 4{i:03d} {1000 + i * 37}",
            "userAccountControl": "514" if disabled else "512",
            "objectGUID": _guid(sam), "objectSid": _sid(1100 + i), "whenCreated": _when(i + 2),
        }
        if sam in member_of:
            attrs["memberOf"] = member_of[sam]
        out.append((dn, attrs))
    for j, (g, members) in enumerate(GROUPS.items()):
        out.append((f"CN={g},OU=Groups,OU=Acme,{DOMAIN}", {
            "objectClass": ["top", "group"], "cn": g, "sAMAccountName": g.replace(" ", ""),
            "groupType": "-2147483646", "member": [dn_of[m] for m in members],
            "objectGUID": _guid(g), "objectSid": _sid(1200 + j), "whenCreated": _when(j + 20)}))
    for k, name in enumerate(COMPUTERS):
        out.append((f"CN={name},OU=Computers,OU=Acme,{DOMAIN}", {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"], "cn": name,
            "sAMAccountName": f"{name}$", "dNSHostName": f"{name.lower()}.acme.local",
            "operatingSystem": "Windows 11 Enterprise", "operatingSystemVersion": "10.0 (22631)",
            "objectGUID": _guid(name), "whenCreated": _when(k + 30)}))
    for k, name in enumerate(SERVERS):
        out.append((f"CN={name},OU=Servers,OU=Acme,{DOMAIN}", {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"], "cn": name,
            "sAMAccountName": f"{name}$", "dNSHostName": f"{name.lower()}.acme.local",
            "operatingSystem": "Windows Server 2022 Standard", "operatingSystemVersion": "10.0 (20348)",
            "objectGUID": _guid(name), "whenCreated": _when(k + 40)}))
    for k, name in enumerate(["svc-backup", "svc-sql", "svc-ldap-reader"]):
        out.append((f"CN={name},OU=Service Accounts,OU=Acme,{DOMAIN}", {
            "objectClass": ["top", "person", "organizationalPerson", "user"], "cn": name,
            "sAMAccountName": name, "userPrincipalName": f"{name}@acme.local",
            "description": "Service account", "userAccountControl": "66048",
            "objectGUID": _guid(name), "objectSid": _sid(1300 + k), "whenCreated": _when(k + 50)}))
    return out


def setup() -> str:
    """Prepara el modo demo antes de crear la app. Devuelve el perfil a conectar."""
    tmp = Path(tempfile.mkdtemp(prefix="lazyldap-demo-"))
    os.environ["LAZYLDAP_CONF"] = str(tmp / "profiles.json")
    os.environ["LAZYLDAP_STATE"] = str(tmp / "state.json")

    from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

    from . import core

    core.CONF, core.STATE = tmp / "profiles.json", tmp / "state.json"
    core.secret_get = lambda name: PASSWORD if name == "acme-ad" else None
    core.secret_set = lambda name, password: True
    core.secret_clear = lambda name: None

    real = core.Session.make_connection

    def make_connection(self):
        if self.profile.host != HOST:
            return real(self)
        server = Server(HOST, port=self.profile.real_port, get_info=OFFLINE_AD_2012_R2)
        conn = Connection(server, user=self.profile.bind_dn, password=self.password, client_strategy=MOCK_SYNC,
                          raise_exceptions=True, read_only=self.profile.readonly)
        for dn, attrs in entries():
            conn.strategy.add_entry(dn, attrs)
        return conn

    core.Session.make_connection = make_connection
    core.save_profiles([
        core.Profile("acme-ad", HOST, security="ssl", bind_dn=ADMIN, password="keyring", base_dn=DOMAIN,
                     mode="readwrite"),
        core.Profile("openldap-lab", "ldap.lab.example.org", bind_dn="cn=admin,dc=lab,dc=example,dc=org"),
        core.Profile("edir-prod", "idv.example.com", port=636, security="ssl",
                     bind_dn="cn=reader,ou=svc,o=example"),
    ])
    return "acme-ad"
