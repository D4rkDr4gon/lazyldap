"""
core.py — backend de lazyldap (sin Textual): perfiles, contraseñas en el
keyring, la sesión LDAP (ldap3), LDIF y lectura completa para exportar.

- Perfiles: ~/.config/lazyldap/profiles.json (LAZYLDAP_CONF apunta a una
  copia). Nunca guarda contraseñas.
- Contraseñas: libsecret con `secret-tool` (atributos app=lazyldap
  profile=<nombre>) si el perfil lo pide; si no, se piden al conectar.
- Session: una conexión ldap3 síncrona protegida con un lock, así los
  workers de la TUI (hilos) no la usan a la vez.
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from ldap3 import (ALL, ANONYMOUS, BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SIMPLE, SUBTREE,
                   Connection, Server, Tls)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.dn import to_dn

_XDG_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
_XDG_STATE = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
CONF = Path(os.environ.get("LAZYLDAP_CONF", _XDG_CONFIG / "lazyldap" / "profiles.json"))
# Estado entre aperturas: último perfil, última entrada y última búsqueda por perfil
STATE = Path(os.environ.get("LAZYLDAP_STATE", _XDG_STATE / "lazyldap" / "state.json"))
MAX_CHILDREN = 5000        # hijos por nodo del árbol (con paginado)
MAX_RESULTS = 1000         # resultados de una búsqueda (la lista en pantalla)
MAX_EXPORT = 200_000       # entradas de un export (Excel / LDIF)
PASSWORD_ATTRS = {"userpassword", "unicodepwd", "sambantpassword"}
SCOPES = {"sub": SUBTREE, "one": LEVEL, "base": BASE}


# ── Perfiles ──────────────────────────────────────────────

@dataclass
class Profile:
    name: str
    host: str
    port: int = 0                  # 0 = el de la seguridad elegida (389 / 636)
    security: str = "none"         # none | ssl | starttls
    verify: str = "yes"            # yes | no (certificados autofirmados)
    auth: str = "simple"           # simple | anonymous
    bind_dn: str = ""
    password: str = "ask"          # ask | keyring
    base_dn: str = ""              # vacío = namingContexts del RootDSE (separar con ;)
    mode: str = "readonly"         # readonly | readwrite
    timeout: int = 10
    page_size: int = 500

    @property
    def real_port(self) -> int:
        return self.port or (636 if self.security == "ssl" else 389)

    @property
    def url(self) -> str:
        return f"{'ldaps' if self.security == 'ssl' else 'ldap'}://{self.host}:{self.real_port}"

    @property
    def readonly(self) -> bool:
        return self.mode != "readwrite"


def load_profiles() -> list[Profile]:
    try:
        data = json.loads(CONF.read_text())
    except (OSError, ValueError):
        return []
    known = Profile.__dataclass_fields__
    out = []
    for p in data.get("profiles", []) if isinstance(data, dict) else []:
        try:
            out.append(Profile(**{k: v for k, v in p.items() if k in known}))
        except TypeError:
            continue
    return out


def save_profiles(profiles: list[Profile]) -> None:
    CONF.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONF.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"profiles": [asdict(p) for p in profiles]}, indent=2, ensure_ascii=False) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)


# ── Estado ────────────────────────────────────────────────

def load_state() -> dict:
    try:
        data = json.loads(STATE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, STATE)
    except OSError:
        pass


# ── Keyring (libsecret) ───────────────────────────────────

def _secret(args: list[str], data: str | None = None) -> Optional[str]:
    try:
        r = subprocess.run(["secret-tool", *args], input=data, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def secret_get(name: str) -> Optional[str]:
    out = _secret(["lookup", "app", "lazyldap", "profile", name])
    return out or None


def secret_set(name: str, password: str) -> bool:
    return _secret(["store", f"--label=lazyldap {name}", "app", "lazyldap", "profile", name], password) is not None


def secret_clear(name: str) -> None:
    _secret(["clear", "app", "lazyldap", "profile", name])


# ── DN ────────────────────────────────────────────────────

def split_dn(dn: str) -> list[str]:
    try:
        return to_dn(dn)
    except LDAPException:
        return [dn]


def rdn_of(dn: str) -> str:
    return split_dn(dn)[0] if dn else ""


def parent_of(dn: str) -> str:
    return ",".join(split_dn(dn)[1:])


def dn_key(dn: str) -> str:
    """Clave para comparar DNs (el servidor puede devolverlos con otra caja/espacios)."""
    return ",".join(p.strip().lower() for p in split_dn(dn))


def is_under(dn: str, base: str) -> bool:
    d, b = dn_key(dn), dn_key(base)
    return d == b or d.endswith("," + b)


# ── Filtros ───────────────────────────────────────────────

def build_filter(text: str) -> str:
    """Filtro LDAP estándar (RFC 4515), como en Softerra: va tal cual; si falta
    el paréntesis exterior (objectClass=user) se agrega."""
    text = text.strip()
    return text if text.startswith("(") else f"({text})"


def split_attrs(text: str) -> list[str]:
    """ "cn, mail sAMAccountName" → ["cn", "mail", "sAMAccountName"] """
    return [a for a in text.replace(";", ",").replace(" ", ",").split(",") if a]


# ── Valores ───────────────────────────────────────────────

def show_value(raw: bytes, formatted) -> tuple[str, bool]:
    """(texto para mostrar, es_binario). Usa el texto si el valor es UTF-8
    imprimible; si no, el formato de ldap3 (GUID, SID…) o <binary N B>."""
    try:
        s = raw.decode("utf-8")
        if s.isprintable() or all(c.isprintable() or c in "\r\n\t" for c in s):
            return s, False
    except UnicodeDecodeError:
        pass
    if formatted is not None and not isinstance(formatted, (bytes, bytearray)):
        return str(formatted), True
    return f"<binary {len(raw)} B>", True


def encode_password(attr: str, value: str) -> bytes | str:
    """unicodePwd de AD va entre comillas en UTF-16LE (y solo por LDAPS)."""
    if attr.lower() == "unicodepwd":
        return f'"{value}"'.encode("utf-16-le")
    return value


@dataclass
class Attr:
    name: str
    values: list[str]
    raw: list[bytes]
    binary: list[bool]
    operational: bool = False


@dataclass
class Child:
    dn: str
    classes: list[str] = field(default_factory=list)
    has_children: Optional[bool] = None   # None = no se sabe hasta expandir
    values: dict[str, str] = field(default_factory=dict)   # atributos pedidos en una búsqueda


# ── Sesión ────────────────────────────────────────────────

class LdapError(Exception):
    pass


def _err(e: Exception) -> LdapError:
    msg = getattr(e, "message", "") or str(e) or type(e).__name__
    return LdapError(msg.strip())


class Session:
    """Conexión a un perfil. Todos los métodos bloquean: llamarlos desde un worker."""

    def __init__(self, profile: Profile, password: str = "") -> None:
        self.profile, self.password = profile, password
        self.conn: Optional[Connection] = None
        self.lock = threading.Lock()
        self.log: list[tuple[float, str, str, str]] = []   # (hora, operación, dn, resultado)
        self.roots: list[str] = []

    # Separado para que las pruebas lo cambien por una conexión MOCK_SYNC
    def make_connection(self) -> Connection:
        p = self.profile
        tls = None
        if p.security in ("ssl", "starttls"):
            tls = Tls(validate=ssl.CERT_REQUIRED if p.verify == "yes" else ssl.CERT_NONE)
        server = Server(p.host, port=p.real_port, use_ssl=p.security == "ssl", tls=tls,
                        get_info=ALL, connect_timeout=p.timeout)
        anon = p.auth == "anonymous"
        return Connection(server, user=None if anon else p.bind_dn, password=None if anon else self.password,
                          authentication=ANONYMOUS if anon else SIMPLE, receive_timeout=p.timeout,
                          raise_exceptions=True, auto_referrals=False, read_only=p.readonly)

    def _log(self, op: str, dn: str, result: str) -> None:
        self.log.append((time.time(), op, dn, result))
        del self.log[:-500]

    def _result(self) -> str:
        r = self.conn.result if self.conn else None
        return (r or {}).get("description", "success") if isinstance(r, dict) else "success"

    def connect(self) -> None:
        with self.lock:
            try:
                self.conn = self.make_connection()
                self.conn.open()
                if self.profile.security == "starttls":
                    self.conn.start_tls()
                self.conn.bind()
            except Exception as e:  # noqa: BLE001 - LDAPException, socket, ssl
                self._log("bind", self.profile.bind_dn or "anonymous", "error")
                self.conn = None
                raise _err(e) from None
            self._log("bind", self.profile.bind_dn or "anonymous", "success")
            self.roots = [b.strip() for b in self.profile.base_dn.split(";") if b.strip()]
            info = self.conn.server.info
            if not self.roots and info is not None:
                self.roots = [str(n) for n in info.naming_contexts or [] if str(n)]

    def close(self) -> None:
        with self.lock:
            if self.conn is not None:
                try:
                    self.conn.unbind()
                except Exception:  # noqa: BLE001
                    pass
            self.conn = None

    @property
    def connected(self) -> bool:
        return self.conn is not None and self.conn.bound

    # ── esquema ──

    def schema(self):
        info = self.conn.server.schema if self.conn else None
        return info if info is not None and getattr(info, "attribute_types", None) else None

    def known_attrs(self, names: list[str]) -> list[str]:
        """Los que el esquema conoce (ldap3 rechaza atributos desconocidos)."""
        s = self.schema()
        if s is None:
            return names
        have = {k.lower() for k in s.attribute_types}
        return [n for n in names if n.lower() in have]

    def must_attrs(self, classes: list[str]) -> list[str]:
        """Atributos obligatorios de esas clases (y sus superclases)."""
        s = self.schema()
        if s is None:
            return []
        out, seen, todo = [], set(), list(classes)
        while todo:
            c = s.object_classes.get(todo.pop())
            if c is None or c.oid in seen:
                continue
            seen.add(c.oid)
            todo += list(c.superior or [])
            for a in c.must_contain or []:
                if a.lower() not in {x.lower() for x in out} and a.lower() != "objectclass":
                    out.append(a)
        return out

    # ── lectura ──

    def children(self, dn: str) -> tuple[list[Child], bool]:
        """(hijos ordenados por RDN, truncado)."""
        attrs = self.known_attrs(["objectClass", "hasSubordinates", "numSubordinates"])
        out, truncated, me = [], False, dn_key(dn)
        with self.lock:
            try:
                gen = self.conn.extend.standard.paged_search(dn, "(objectClass=*)", LEVEL, attributes=attrs,
                                                            paged_size=self.profile.page_size, generator=True)
                for e in gen:
                    # Algunos servidores (y el mock de ldap3) devuelven la base en un LEVEL
                    if e.get("type") != "searchResEntry" or dn_key(e["dn"]) == me:
                        continue
                    a = e.get("attributes", {})
                    has = a.get("hasSubordinates")
                    num = a.get("numSubordinates")
                    if isinstance(has, list):
                        has = has[0] if has else None
                    if isinstance(has, str):
                        has = has.upper() == "TRUE"
                    if has is None and num not in (None, []):
                        try:
                            has = int(num[0] if isinstance(num, list) else num) > 0
                        except (TypeError, ValueError):
                            has = None
                    oc = a.get("objectClass", [])
                    out.append(Child(e["dn"], [str(c) for c in (oc if isinstance(oc, list) else [oc])],
                                     bool(has) if has is not None else None))
                    if len(out) >= MAX_CHILDREN:
                        truncated = True
                        break
            except LDAPException as e:
                self._log("list", dn, "error")
                raise _err(e) from None
        self._log("list", dn, f"{len(out)} entries")
        out.sort(key=lambda c: rdn_of(c.dn).lower())
        return out, truncated

    def entry(self, dn: str, operational: bool = False) -> list[Attr]:
        with self.lock:
            try:
                self.conn.search(dn, "(objectClass=*)", BASE, attributes=["*", "+"] if operational else ["*"])
            except LDAPException as e:
                self._log("read", dn, "error")
                raise _err(e) from None
            resp = [e for e in self.conn.response if e.get("type") == "searchResEntry"]
        if not resp:
            raise LdapError("entry not found")
        r = resp[0]
        user = {k.lower() for k in r.get("attributes", {})}
        if operational:
            # Lo que no vuelve con "*" es operacional: se pide una vez más sin "+"
            with self.lock:
                self.conn.search(dn, "(objectClass=*)", BASE, attributes=["*"])
                user = {k.lower() for e in self.conn.response if e.get("type") == "searchResEntry"
                        for k in e.get("attributes", {})}
        out = []
        for name, raws in r.get("raw_attributes", {}).items():
            fmt = r.get("attributes", {}).get(name)
            fmts = fmt if isinstance(fmt, list) else [fmt] * len(raws)
            vals, bins = [], []
            for i, raw in enumerate(raws):
                v, b = show_value(raw, fmts[i] if i < len(fmts) else None)
                vals.append(v)
                bins.append(b)
            out.append(Attr(name, vals, list(raws), bins, operational=name.lower() not in user))
        out.sort(key=lambda a: (a.operational, a.name.lower() != "objectclass", a.name.lower()))
        self._log("read", dn, "success")
        return out

    def search(self, base: str, flt: str, scope: str, wanted: list[str] = ()) -> tuple[list[Child], bool]:
        attrs = self.known_attrs(list(dict.fromkeys(["objectClass", *wanted])))
        with self.lock:
            try:
                gen = self.conn.extend.standard.paged_search(base, flt, SCOPES.get(scope, SUBTREE), attributes=attrs,
                                                            paged_size=self.profile.page_size, generator=True)
                out, truncated = [], False
                for e in gen:
                    if e.get("type") != "searchResEntry":
                        continue
                    a = e.get("attributes", {})
                    oc = a.get("objectClass", [])
                    vals = {}
                    for w in wanted:
                        v = next((v for k, v in a.items() if k.lower() == w.lower()), None)
                        v = v if isinstance(v, list) else [] if v is None else [v]
                        vals[w] = "; ".join(str(x) for x in v)
                    out.append(Child(e["dn"], [str(c) for c in (oc if isinstance(oc, list) else [oc])], values=vals))
                    if len(out) >= MAX_RESULTS:
                        truncated = True
                        break
            except LDAPException as e:
                self._log("search", f"{base} {flt}", "error")
                raise _err(e) from None
        self._log("search", f"{base} {flt}", f"{len(out)} results")
        return out, truncated

    def fetch(self, base: str, flt: str, scope: str, wanted: list[str] = ()) -> list[tuple[str, dict]]:
        """Entradas completas para exportar: [(dn, {atributo: [valores como texto]})].
        Sin `wanted`, todos los atributos de usuario."""
        attrs = self.known_attrs(list(dict.fromkeys(wanted))) if wanted else ["*"]
        out = []
        with self.lock:
            try:
                gen = self.conn.extend.standard.paged_search(base, flt, SCOPES.get(scope, SUBTREE), attributes=attrs,
                                                            paged_size=self.profile.page_size, generator=True)
                for e in gen:
                    if e.get("type") != "searchResEntry":
                        continue
                    fmt = e.get("attributes", {})
                    vals = {}
                    for name, raws in e.get("raw_attributes", {}).items():
                        f = fmt.get(name)
                        fs = f if isinstance(f, list) else [f] * len(raws)
                        vals[name] = [show_value(r, fs[i] if i < len(fs) else None)[0] for i, r in enumerate(raws)]
                    out.append((e["dn"], vals))
                    if len(out) >= MAX_EXPORT:
                        break
            except LDAPException as e:
                self._log("export", f"{base} {flt}", "error")
                raise _err(e) from None
        self._log("export", f"{base} {flt}", f"{len(out)} entries")
        return out

    def ldif(self, dn: str, subtree: bool) -> tuple[str, int]:
        with self.lock:
            try:
                res = self.conn.extend.standard.paged_search(dn, "(objectClass=*)", SUBTREE if subtree else BASE,
                                                            attributes=["*"], paged_size=self.profile.page_size,
                                                            generator=False)
                entries = [e for e in res if e.get("type") == "searchResEntry"]
                text = self.conn.response_to_ldif(entries)
            except LDAPException as e:
                self._log("export", dn, "error")
                raise _err(e) from None
        self._log("export", dn, f"{len(entries)} entries")
        return text, len(entries)

    # ── escritura ──

    def _write(self, op: str, dn: str, fn) -> None:
        if self.profile.readonly:
            raise LdapError("profile is read-only")
        with self.lock:
            try:
                ok = fn()
            except LDAPException as e:
                self._log(op, dn, "error")
                raise _err(e) from None
            res = self._result()
        self._log(op, dn, res)
        if ok is False:
            raise LdapError(res)

    def replace_value(self, dn: str, attr: str, old: bytes | None, new: bytes | str) -> None:
        """Cambia un valor: con old, borra ese valor y agrega el nuevo (multivaluados);
        sin old (o atributos de contraseña), reemplaza el atributo entero."""
        if old is None or attr.lower() in PASSWORD_ATTRS:
            changes = {attr: [(MODIFY_REPLACE, [new])]}
        else:
            changes = {attr: [(MODIFY_DELETE, [old]), (MODIFY_ADD, [new])]}
        self._write("modify", dn, lambda: self.conn.modify(dn, changes))

    def add_value(self, dn: str, attr: str, value: bytes | str) -> None:
        self._write("modify", dn, lambda: self.conn.modify(dn, {attr: [(MODIFY_ADD, [value])]}))

    def delete_value(self, dn: str, attr: str, raw: bytes | None) -> None:
        vals = [raw] if raw is not None else []
        self._write("modify", dn, lambda: self.conn.modify(dn, {attr: [(MODIFY_DELETE, vals)]}))

    def add_entry(self, dn: str, classes: list[str], attrs: dict[str, list[str]]) -> None:
        self._write("add", dn, lambda: self.conn.add(dn, classes, attrs))

    def delete_entry(self, dn: str) -> None:
        self._write("delete", dn, lambda: self.conn.delete(dn))

    def rename(self, dn: str, new_rdn: str, new_parent: str | None) -> str:
        self._write("rename", dn, lambda: self.conn.modify_dn(dn, new_rdn, delete_old_dn=True,
                                                              new_superior=new_parent or None))
        return f"{new_rdn},{new_parent or parent_of(dn)}"
