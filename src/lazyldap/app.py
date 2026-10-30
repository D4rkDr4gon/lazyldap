"""
app.py — la TUI de lazyldap: navegador LDAP en la terminal (estilo Softerra
LDAP Browser, con la forma de lazygit).

- [1] Profiles: perfiles de conexión (servidor, seguridad, bind DN, base DN,
  modo solo lectura / lectura-escritura). enter conecta; la contraseña se
  pide al conectar o sale del keyring (secret-tool).
- [2] Directory: árbol del directorio, se carga por niveles al expandir.
- [3] Entry: atributos de la entrada seleccionada (con los operacionales
  si se piden). Con un perfil read-write: editar, agregar y borrar valores,
  crear entradas (pide los atributos obligatorios del esquema), renombrar,
  mover y borrar.
- Búsqueda con filtro LDAP estándar, resultados a Excel, export a Excel o
  LDIF y registro de las operaciones de la sesión.

Backend sin Textual: core.py. Piezas de interfaz: ui.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Static

from . import core as L
from .ui import (THEME, ConfirmModal, DView, Field, FormModal, Panel, PickModal, Table, TextModal, ViewApp,
                 bindings_of, css, key_display)
from .xlsx import entries_table, write_xlsx

M, OK, WARN, ERR, P = THEME["muted"], THEME["status_ok"], THEME["status_warn"], THEME["status_error"], THEME["primary"]

SECURITY = [("None (ldap://)", "none"), ("LDAPS (ldaps://)", "ssl"), ("StartTLS", "starttls")]
VERIFY = [("Verify certificate", "yes"), ("Don't verify (self-signed)", "no")]
AUTH = [("Simple bind", "simple"), ("Anonymous", "anonymous")]
PASSWORD = [("Ask when connecting", "ask"), ("Store in keyring", "keyring")]
MODE = [("Read-only", "readonly"), ("Read-write", "readwrite")]
SCOPE = [("Subtree", "sub"), ("One level", "one"), ("Base", "base")]

# Ícono por objectClass (Nerd Font), del más específico al más genérico
ICONS = [
    ({"computer"}, "󰍹"),
    ({"group", "groupofnames", "groupofuniquenames", "posixgroup", "groupofentries"}, "󰡉"),
    ({"person", "user", "inetorgperson", "organizationalperson", "posixaccount"}, "󰀄"),
    ({"organizationalunit", "organization", "container", "domain", "dcobject", "builtindomain",
      "country", "locality", "ndscontainerloginproperties"}, "󰉋"),
]


def icon_for(classes: list[str]) -> str:
    oc = {c.lower() for c in classes}
    return next((i for keys, i in ICONS if oc & keys), "󰈙")


def rdn_text(rdn: str) -> Text:
    """ou=People → "ou=" atenuado y el valor normal."""
    t = Text()
    attr, sep, val = rdn.partition("=")
    if sep:
        t.append(attr + "=", style=M)
        t.append(val)
    else:
        t.append(rdn)
    return t


def copy_text(text: str) -> bool:
    cmd = ["wl-copy"] if os.environ.get("WAYLAND_DISPLAY") else ["xclip", "-selection", "clipboard"]
    if not shutil.which(cmd[0]):
        return False
    try:
        subprocess.run(cmd, input=text, text=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


class ResultsModal(PickModal):
    """Resultados de una búsqueda: enter va a la entrada, e los exporta a Excel."""

    BINDINGS = [Binding("e", "excel", "export to Excel")]

    def __init__(self, title: str, columns: list[str], rows: list, on_excel: Callable[[], None]) -> None:
        super().__init__(title, columns, rows, hint="enter go to entry · e export to Excel · esc close")
        self.on_excel = on_excel

    def action_excel(self) -> None:
        self.on_excel()


class Node:
    def __init__(self, dn: str, classes: list[str] | None = None, has_children: Optional[bool] = None,
                 depth: int = 0) -> None:
        self.dn, self.classes, self.has_children, self.depth = dn, classes or [], has_children, depth
        self.children: Optional[list[str]] = None     # claves; None = sin cargar
        self.truncated = False
        self.expanded = False
        self.loading = False


class LazyLdapView(DView):
    FOCUS = "#profiles"

    DEFAULT_CSS = css("""
    LazyLdapView > Horizontal { height: 1fr; }
    #left { width: 2fr; }
    #right { width: 3fr; }
    #profiles-panel { height: auto; max-height: 12; }
    #profiles { height: auto; max-height: 10; }
    #tree-panel, #entry-panel { height: 1fr; }
    #tree, #entry { height: 1fr; }
    #session-panel { height: auto; }
    #session { height: auto; }
    """)

    BINDINGS = [
        Binding("1", "focus_profiles", "profiles", show=False),
        Binding("2", "focus_tree", "directory", show=False),
        Binding("3", "focus_entry", "entry", show=False),
        Binding("l,right", "expand", "expand", show=False, priority=True),
        Binding("h,left", "collapse", "collapse / parent", show=False, priority=True),
        Binding("n", "new", "new"),
        Binding("e", "edit", "edit"),
        Binding("a", "add", "add value"),
        Binding("d", "delete", "delete"),
        Binding("r", "refresh", "refresh"),
        Binding("slash", "search", "search"),
        Binding("s", "results", "last search results", show=False),
        Binding("o", "operational", "operational attributes", show=False),
        Binding("y", "copy", "copy"),
        Binding("Y", "copy_dn", "copy DN", show=False),
        Binding("R", "rename", "rename / move", show=False),
        Binding("X", "export", "export LDIF", show=False),
        Binding("L", "log", "session log", show=False),
        Binding("question_mark", "help", "help", show=False),
        Binding("x", "disconnect", "disconnect"),
    ]

    def __init__(self, autoconnect: str = "", **kw) -> None:
        super().__init__(**kw)
        self.autoconnect = autoconnect
        self.profiles: list[L.Profile] = []
        self.session: Optional[L.Session] = None
        self.connecting = ""
        self.nodes: dict[str, Node] = {}
        self.roots: list[str] = []
        self.attrs: list[L.Attr] = []
        self.entry_dn = ""
        self.operational = False
        self._entry_timer = None
        self._want_dn = ""
        self.state = L.load_state()        # último perfil / entrada / búsqueda (entre aperturas)
        self.last_results: tuple = ()      # (resultados, truncado, atributos) de la última búsqueda
        self.last_search: tuple = ()       # (base, filtro, alcance, atributos) para exportarla

    def compose(self) -> ComposeResult:
        yield Horizontal(
            Vertical(Panel(Table(id="profiles"), title="[1] Profiles", id="profiles-panel"),
                     Panel(Table(id="tree", show_header=False), title="[2] Directory", id="tree-panel"),
                     id="left"),
            Vertical(Panel(Static(id="session"), title="Session", id="session-panel"),
                     Panel(Table(id="entry"), title="[3] Entry", id="entry-panel"),
                     id="right"))

    def on_mount(self) -> None:
        p = self.query_one("#profiles", Table)
        p.add_column(" ", key="st", width=1)
        p.add_column("Name", key="name", width=16)
        p.add_column("Server", key="url", width=34)
        self.query_one("#tree", Table).add_column("entry", key="e")
        e = self.query_one("#entry", Table)
        e.add_column("Attribute", key="attr", width=24)
        e.add_column("Value", key="value")
        self.reload_profiles()
        self.render_session()
        if self.autoconnect:
            prof = next((p for p in self.profiles if p.name == self.autoconnect), None)
            if prof:
                self.call_after_refresh(self.connect_profile, prof)
            else:
                self.app.notify_err(f"No profile called {self.autoconnect}")
        elif last := self.state.get("last_profile"):
            names = [p.name for p in self.profiles]
            if last in names:
                self.query_one("#profiles", Table).move_cursor(row=names.index(last))

    def on_unmount(self) -> None:
        self.remember()
        if self.session:
            self.session.close()

    def remember(self) -> None:
        """Guarda la entrada abierta del perfil conectado para la próxima vez."""
        if self.session and self.entry_dn:
            self.state.setdefault("dn", {})[self.session.profile.name] = self.entry_dn
        L.save_state(self.state)

    def profile_state(self, key: str) -> dict:
        name = self.session.profile.name if self.session else ""
        return self.state.setdefault(key, {}).setdefault(name, {}) if name else {}

    # ── foco y atajos ──

    def focused_id(self) -> str:
        f = self.app.focused
        return f.id if f is not None and f.id else ""

    def hints(self) -> list[tuple[str, str]]:
        fid = self.focused_id()
        if fid == "tree":
            return [("enter", "expand"), ("h", "collapse"), ("/", "search"), ("n", "new entry"),
                    ("s", "results"), ("R", "rename"), ("d", "delete"), ("X", "export"), ("y", "copy DN"),
                    ("r", "refresh"), ("tab", "panel")]
        if fid == "entry":
            return [("enter", "view"), ("e", "edit"), ("a", "add"), ("d", "delete"),
                    ("o", "operational"), ("y", "copy"), ("Y", "copy DN"), ("L", "log"), ("tab", "panel")]
        return [("enter", "connect"), ("n", "new"), ("e", "edit"), ("d", "delete"), ("x", "disconnect"),
                ("1-3", "panels"), ("?", "help"), ("q", "quit")]

    def action_focus_profiles(self) -> None:
        self.query_one("#profiles", Table).focus()

    def action_focus_tree(self) -> None:
        self.query_one("#tree", Table).focus()

    def action_focus_entry(self) -> None:
        self.query_one("#entry", Table).focus()

    # ── perfiles ──

    def reload_profiles(self, select: str | None = None) -> None:
        self.profiles = L.load_profiles()
        live = self.session.profile.name if self.session and self.session.connected else ""
        rows = []
        for p in self.profiles:
            st = (Text("●", style=OK) if p.name == live else Text("…", style=WARN) if p.name == self.connecting
                  else Text("○", style=M))
            rows.append((p.name, [st, Text(p.name, style="bold" if p.name == live else ""),
                                  Text(p.url, style=M)]))
        t = self.query_one("#profiles", Table)
        t.set_rows(rows)
        if select and select in [r[0] for r in rows]:
            t.move_cursor(row=[r[0] for r in rows].index(select))
        self.query_one("#profiles-panel").border_subtitle = f" {len(rows)} " if rows else " press n "

    def current_profile(self) -> Optional[L.Profile]:
        key = self.query_one("#profiles", Table).selected_key()
        return next((p for p in self.profiles if p.name == key), None)

    def profile_form(self, p: Optional[L.Profile]) -> None:
        editing = p is not None
        p = p or L.Profile(name="", host="")
        taken = {x.name for x in self.profiles} - ({p.name} if editing else set())

        def check(v: dict) -> Optional[str]:
            if not v["name"]:
                return "The name is missing"
            if v["name"] in taken:
                return f"There is already a profile called {v['name']}"
            if not v["host"]:
                return "The host is missing"
            if v["port"] and not v["port"].isdigit():
                return "The port must be a number"
            if v["auth"] == "simple" and not v["bind_dn"]:
                return "Simple bind needs a bind DN (or choose Anonymous)"
            return None

        def done(v: Optional[dict]) -> None:
            if not v:
                return
            new = L.Profile(name=v["name"], host=v["host"], port=int(v["port"] or 0), security=v["security"],
                            verify=v["verify"], auth=v["auth"], bind_dn=v["bind_dn"], password=v["password"],
                            base_dn=v["base_dn"], mode=v["mode"], timeout=p.timeout, page_size=p.page_size)
            if editing and p.password == "keyring":
                if new.password != "keyring":
                    L.secret_clear(p.name)
                elif new.name != p.name and (pw := L.secret_get(p.name)):
                    L.secret_set(new.name, pw)
                    L.secret_clear(p.name)
            profiles = [new if x.name == p.name else x for x in self.profiles] if editing else self.profiles + [new]
            L.save_profiles(profiles)
            self.reload_profiles(select=new.name)
            if editing and self.session and self.session.profile.name == p.name:
                self.app.notify_ok("Saved: disconnect (x) and connect again to apply it")
            else:
                self.app.notify_ok(f"Profile {new.name} saved")

        fields = [
            Field("name", "Name", p.name, "work-ad"),
            Field("host", "Host", p.host, "ldap.example.com"),
            Field("port", "Port", str(p.port or ""), "empty = 389 / 636 for LDAPS"),
            Field("security", "Security", p.security, choices=SECURITY),
            Field("verify", "Certificate", p.verify, choices=VERIFY),
            Field("auth", "Authentication", p.auth, choices=AUTH),
            Field("bind_dn", "Bind DN", p.bind_dn, "cn=admin,dc=example,dc=com  ·  user@domain for AD"),
            Field("password", "Password", p.password, choices=PASSWORD),
            Field("base_dn", "Base DN", p.base_dn, "empty = naming contexts of the server  ·  several with ;"),
            Field("mode", "Mode", p.mode, choices=MODE),
        ]
        self.app.push_screen(FormModal("Edit profile" if editing else "New profile", fields, validate=check,
                                       hint="Passwords are never written to profiles.json."), done)

    def connect_profile(self, p: L.Profile) -> None:
        if self.connecting:
            return
        if self.session and self.session.connected and self.session.profile.name == p.name:
            self.action_focus_tree()
            return
        if p.auth == "anonymous":
            self.do_connect(p, "")
        elif p.password == "keyring":
            self.keyring_connect(p)
        else:
            self.ask_password(p)

    def ask_password(self, p: L.Profile, store: bool = False, error: str = "") -> None:
        def done(v: Optional[dict]) -> None:
            if v:
                self.do_connect(p, v["password"], store=store)

        hint = f"✗ {error}" if error else ("It will be stored in the keyring." if store else "")
        self.app.push_screen(FormModal(f"Log in · {p.name}",
                                       [Field("password", f"Password for {p.bind_dn}", password=True)],
                                       hint=hint), done)

    @work(thread=True, group="secret")
    def keyring_connect(self, p: L.Profile) -> None:
        pw = L.secret_get(p.name)
        if pw is None:
            self.app.call_from_thread(self.ask_password, p, True)
        else:
            self.app.call_from_thread(self.do_connect, p, pw, False, True)

    def do_connect(self, p: L.Profile, pw: str, store: bool = False, from_keyring: bool = False) -> None:
        self.connecting = p.name
        self.reload_profiles()
        self.render_session(f"connecting to {p.url}…")
        self.connect_worker(p, pw, store, from_keyring)

    @work(thread=True, group="ldap")
    def connect_worker(self, p: L.Profile, pw: str, store: bool, from_keyring: bool) -> None:
        old, s = self.session, L.Session(p, pw)
        if old:
            old.close()
        try:
            s.connect()
            root_nodes = [(r, s.children(r)) for r in s.roots[:1]]
        except L.LdapError as e:
            self.app.call_from_thread(self.connect_failed, p, str(e), from_keyring)
            return
        if store:
            L.secret_set(p.name, pw)
        self.app.call_from_thread(self.connected, s, root_nodes)

    def connect_failed(self, p: L.Profile, msg: str, from_keyring: bool) -> None:
        self.connecting = ""
        self.session = None
        self.reload_profiles()
        self.clear_tree()
        if from_keyring and "invalidcredentials" in msg.replace(" ", "").lower():
            self.ask_password(p, store=True, error="The stored password was rejected")
            return
        self.render_session()
        self.app.notify_err(f"{p.name}: {msg}")

    def connected(self, s: L.Session, root_nodes: list) -> None:
        self.connecting = ""
        self.session = s
        self.reload_profiles()
        self.clear_tree()
        self.roots = []
        for r in s.roots:
            k = L.dn_key(r)
            self.nodes[k] = Node(r, depth=0)
            self.roots.append(k)
        for r, (children, trunc) in root_nodes:
            self.set_children(L.dn_key(r), children, trunc)
            self.nodes[L.dn_key(r)].expanded = True
        self.render_tree()
        self.render_session()
        if not self.roots:
            self.app.notify_err("The server doesn't publish naming contexts: set a Base DN in the profile")
            return
        tree = self.query_one("#tree", Table)
        tree.focus()
        tree.first_selectable()
        self.app.notify_ok(f"Connected to {s.profile.name}")
        self.state["last_profile"] = s.profile.name
        L.save_state(self.state)
        # Vuelve a la entrada que estaba abierta la última vez
        last = self.state.get("dn", {}).get(s.profile.name)
        if last and any(L.is_under(last, self.nodes[r].dn) for r in self.roots):
            self.reveal(last)

    def action_disconnect(self) -> None:
        if not self.session:
            return
        self.remember()
        s, self.session = self.session, None
        self.close_worker(s)
        self.clear_tree()
        self.reload_profiles()
        self.render_session()
        self.action_focus_profiles()

    @work(thread=True, group="close")
    def close_worker(self, s: L.Session) -> None:
        s.close()

    # ── sesión ──

    def render_session(self, busy: str = "") -> None:
        t = Text()

        def row(label: str, value: str | Text, style: str = "") -> None:
            if t:
                t.append("\n")
            t.append(f"{label:<10}", style=f"bold {M}")
            t.append(value, style=style) if isinstance(value, str) else t.append_text(value)

        s = self.session
        if busy:
            row("Status", busy, WARN)
        elif not s or not s.connected:
            row("Status", "○ not connected", M)
            row("", "pick a profile and press enter" if self.profiles else "press n to create a profile", M)
        else:
            p = s.profile
            row("Server", Text.assemble((p.url, ""), ("  ● connected", OK),
                                        ("" if p.security != "none" else "  (plain text)", WARN)))
            row("Bound as", p.bind_dn if p.auth == "simple" else "anonymous")
            row("Mode", "read-only" if p.readonly else "read-write", OK if p.readonly else WARN)
            if self.entry_dn:
                row("DN", self.entry_dn)
        self.query_one("#session", Static).update(t)

    # ── árbol ──

    def clear_tree(self) -> None:
        self.nodes, self.roots, self.attrs, self.entry_dn = {}, [], [], ""
        self.render_tree()
        self.render_entry()

    def set_children(self, key: str, children: list, truncated: bool) -> None:
        node = self.nodes[key]
        node.children, node.truncated, node.loading = [], truncated, False
        node.has_children = bool(children)
        for c in children:
            ck = L.dn_key(c.dn)
            old = self.nodes.get(ck)
            if old is not None:   # refresco: conserva lo expandido
                old.classes, old.has_children = c.classes, old.has_children if old.children is not None \
                    else c.has_children
            else:
                self.nodes[ck] = Node(c.dn, c.classes, c.has_children, node.depth + 1)
            node.children.append(ck)

    def render_tree(self) -> None:
        rows: list[tuple[str, list]] = []

        def walk(key: str) -> None:
            n = self.nodes[key]
            if n.loading:
                marker = Text("… ", style=WARN)
            elif n.expanded:
                marker = Text("▾ ", style=M)
            elif n.has_children is False:
                marker = Text("  ")
            else:
                marker = Text("▸ ", style=M)
            label = Text("  " * n.depth)
            label.append_text(marker)
            label.append("󰒋 " if n.depth == 0 else icon_for(n.classes) + " ", style=M)
            label.append_text(rdn_text(n.dn if n.depth == 0 else L.rdn_of(n.dn)))
            rows.append((key, [label]))
            if n.expanded and n.children is not None:
                for c in n.children:
                    walk(c)
                if n.truncated:
                    rows.append((f"gap:more:{key}", [Text("  " * (n.depth + 1) + f"  … first {L.MAX_CHILDREN} "
                                                          "shown: use / to search", style=M)]))

        for r in self.roots:
            walk(r)
        self.query_one("#tree", Table).set_rows(rows)
        total = sum(1 for k in self.nodes if self.nodes[k].children is not None)
        self.query_one("#tree-panel").border_subtitle = f" {len(rows)} shown · {total} loaded " if rows else ""

    def tree_key(self) -> Optional[str]:
        k = self.query_one("#tree", Table).selected_key()
        return k if k in self.nodes else None

    def tree_dn(self) -> str:
        k = self.tree_key()
        return self.nodes[k].dn if k else ""

    def toggle(self, key: str, expand: Optional[bool] = None) -> None:
        n = self.nodes[key]
        want = not n.expanded if expand is None else expand
        if want and n.children is None:
            if not n.loading:
                n.loading = True
                self.render_tree()
                self.load_children(key)
            return
        if want and n.has_children is False:
            return
        n.expanded = want
        self.render_tree()

    @work(thread=True, group="tree")
    def load_children(self, key: str, expand: bool = True) -> None:
        s, n = self.session, self.nodes.get(key)
        if not s or not n:
            return
        try:
            children, trunc = s.children(n.dn)
        except L.LdapError as e:
            self.app.call_from_thread(self.children_failed, key, str(e))
            return
        self.app.call_from_thread(self.children_loaded, s, key, children, trunc, expand)

    def children_failed(self, key: str, msg: str) -> None:
        if key in self.nodes:
            self.nodes[key].loading = False
        self.render_tree()
        self.app.notify_err(msg)

    def children_loaded(self, s: L.Session, key: str, children: list, trunc: bool, expand: bool) -> None:
        if s is not self.session or key not in self.nodes:
            return
        self.set_children(key, children, trunc)
        if expand:
            self.nodes[key].expanded = True
        self.render_tree()

    def action_expand(self) -> None:
        if self.focused_id() == "tree" and (k := self.tree_key()):
            n = self.nodes[k]
            if n.expanded and n.children:   # ya abierto: baja al primer hijo
                t = self.query_one("#tree", Table)
                t.move_cursor(row=(t.cursor_row or 0) + 1)
            else:
                self.toggle(k, True)

    def action_collapse(self) -> None:
        if self.focused_id() != "tree" or not (k := self.tree_key()):
            return
        n = self.nodes[k]
        if n.expanded:
            self.toggle(k, False)
            return
        parent = L.dn_key(L.parent_of(n.dn))   # cerrado: sube al padre
        if n.depth > 0 and parent in self.nodes:
            self.select_tree(parent)

    def select_tree(self, key: str) -> None:
        t = self.query_one("#tree", Table)
        keys = [r.key.value for r in t.ordered_rows]
        if key in keys:
            t.move_cursor(row=keys.index(key))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tid = event.data_table.id
        if tid == "profiles" and (p := self.current_profile()):
            self.connect_profile(p)
        elif tid == "tree" and (k := self.tree_key()):
            self.toggle(k)
        elif tid == "entry":
            self.view_value()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "tree" or not self.session:
            return
        dn = self.tree_dn()
        if not dn or dn == self._want_dn:
            return
        # Espera un instante: recorrer el árbol con j/k no dispara una lectura por fila
        if self._entry_timer is not None:
            self._entry_timer.stop()
        self._entry_timer = self.set_timer(0.12, lambda: self.load_entry(dn))

    # ── entrada ──

    def load_entry(self, dn: str) -> None:
        self._want_dn = dn
        self.entry_worker(dn)

    @work(thread=True, group="entry", exclusive=True)
    def entry_worker(self, dn: str) -> None:
        s = self.session
        if not s or not dn:
            return
        try:
            attrs = s.entry(dn, self.operational)
        except L.LdapError as e:
            self.app.call_from_thread(self.entry_loaded, s, dn, None, str(e))
            return
        self.app.call_from_thread(self.entry_loaded, s, dn, attrs, "")

    def entry_loaded(self, s: L.Session, dn: str, attrs: Optional[list], err: str) -> None:
        if s is not self.session or dn != self._want_dn:
            return   # el cursor ya se movió a otra entrada
        self.entry_dn, self.attrs = dn, attrs or []
        self.render_entry(err)
        self.render_session()

    def render_entry(self, err: str = "") -> None:
        rows = []
        for i, a in enumerate(self.attrs):
            for j, v in enumerate(a.values):
                style = M if a.operational else ""
                name = Text(a.name if j == 0 else "", style=f"bold {M}" if a.operational else "bold")
                val = Text(v[:400].replace("\n", "↵"), style=f"italic {M}" if a.binary[j] else style)
                rows.append((f"{i}:{j}", [name, val]))
        if err:
            rows = [("gap:err", [Text("✗ error", style=ERR), Text(err, style=ERR)])]
        t = self.query_one("#entry", Table)
        t.set_rows(rows)
        panel = self.query_one("#entry-panel")
        panel.border_title = f" [3] {L.rdn_of(self.entry_dn)} " if self.entry_dn else " [3] Entry "
        if self.attrs:
            extra = " · +operational" if self.operational else ""
            panel.border_subtitle = f" {len(self.attrs)} attributes · {len(rows)} values{extra} "
        else:
            panel.border_subtitle = ""

    def current_value(self) -> Optional[tuple[L.Attr, int]]:
        k = self.query_one("#entry", Table).selected_key()
        if not k or ":" not in k or k.startswith("gap:"):
            return None
        i, j = (int(x) for x in k.split(":"))
        return (self.attrs[i], j) if i < len(self.attrs) and j < len(self.attrs[i].values) else None

    def view_value(self) -> None:
        cur = self.current_value()
        if not cur:
            return
        a, j = cur
        text = a.values[j]
        if a.binary[j] and not text.startswith("<binary"):
            text += f"\n\n({len(a.raw[j])} bytes)"
        elif a.binary[j]:
            text += "\n\n" + a.raw[j][:512].hex(" ", 2)
        self.app.push_screen(TextModal(f"{a.name} · {L.rdn_of(self.entry_dn)}", text, end=False))

    def action_operational(self) -> None:
        if not self.session:
            return
        self.operational = not self.operational
        if self.entry_dn:
            self.load_entry(self.entry_dn)

    # ── acciones según el panel ──

    def can_write(self) -> bool:
        if not self.session or not self.session.connected:
            self.app.notify_err("Not connected")
            return False
        if self.session.profile.readonly:
            self.app.notify_err("Read-only profile: edit it (e in Profiles) and set Mode to read-write")
            return False
        return True

    def action_new(self) -> None:
        fid = self.focused_id()
        if fid == "profiles":
            self.profile_form(None)
        elif fid == "tree" and self.tree_dn() and self.can_write():
            self.new_entry_form(self.tree_dn())

    def action_edit(self) -> None:
        fid = self.focused_id()
        if fid == "profiles" and (p := self.current_profile()):
            self.profile_form(p)
        elif fid == "entry":
            self.edit_value()
        elif fid == "tree":
            self.action_rename()

    def action_add(self) -> None:
        if self.focused_id() not in ("entry", "tree") or not self.entry_dn or not self.can_write():
            return
        dn = self.entry_dn
        cur = self.current_value() if self.focused_id() == "entry" else None

        def done(v: Optional[dict]) -> None:
            if v:
                val = L.encode_password(v["attr"], v["value"]) if v["attr"].lower() in L.PASSWORD_ATTRS \
                    else v["value"]
                self.write(f"Added {v['attr']}", lambda: self.session.add_value(dn, v["attr"], val),
                           lambda _: self.load_entry(dn))

        self.app.push_screen(FormModal(f"Add value · {L.rdn_of(dn)}", [
            Field("attr", "Attribute", cur[0].name if cur else "", "description"),
            Field("value", "Value")],
            hint="Adds one more value (multi-valued attributes) or a new attribute.",
            validate=lambda v: None if v["attr"] and v["value"] else "Attribute and value are needed"), done)

    def edit_value(self) -> None:
        cur = self.current_value()
        if not cur or not self.can_write():
            return
        a, j = cur
        dn = self.entry_dn
        is_pw = a.name.lower() in L.PASSWORD_ATTRS
        if a.binary[j] and not is_pw:
            self.app.notify_err("Binary value: it can't be edited here")
            return

        def done(v: Optional[dict]) -> None:
            if v is None:
                return
            new = L.encode_password(a.name, v["value"]) if is_pw else v["value"]
            if not is_pw and new == a.values[j]:
                return
            self.write(f"{a.name} updated", lambda: self.session.replace_value(dn, a.name, a.raw[j], new),
                       lambda _: self.load_entry(dn))

        self.app.push_screen(FormModal(f"Edit {a.name} · {L.rdn_of(dn)}",
                                       [Field("value", "New password" if is_pw else "Value",
                                              "" if is_pw else a.values[j], password=is_pw)],
                                       hint="The whole attribute is replaced." if is_pw else ""), done)

    def action_delete(self) -> None:
        fid = self.focused_id()
        if fid == "profiles" and (p := self.current_profile()):
            def gone(yes: bool) -> None:
                if not yes:
                    return
                if self.session and self.session.profile.name == p.name:
                    self.action_disconnect()
                if p.password == "keyring":
                    L.secret_clear(p.name)
                L.save_profiles([x for x in self.profiles if x.name != p.name])
                self.reload_profiles()
                self.render_session()
            self.app.push_screen(ConfirmModal("Delete profile", f"Delete the profile {p.name}?"), gone)
        elif fid == "entry" and (cur := self.current_value()) and self.can_write():
            a, j = cur
            dn = self.entry_dn
            self.app.push_screen(ConfirmModal("Delete value", f"Delete this value of {a.name}?\n\n{a.values[j][:200]}"),
                                 lambda yes: yes and self.write(f"Deleted a value of {a.name}",
                                                                lambda: self.session.delete_value(dn, a.name, a.raw[j]),
                                                                lambda _: self.load_entry(dn)))
        elif fid == "tree" and (k := self.tree_key()) and self.nodes[k].depth > 0 and self.can_write():
            n = self.nodes[k]
            warn = "\n\nIt has children: the server will refuse it." if n.children else ""
            self.app.push_screen(ConfirmModal("Delete entry", f"Delete {n.dn}?{warn}"),
                                 lambda yes: yes and self.write(f"Deleted {L.rdn_of(n.dn)}",
                                                                lambda: self.session.delete_entry(n.dn),
                                                                lambda _: self.refresh_parent_of(n.dn)))

    def action_rename(self) -> None:
        if self.focused_id() != "tree" or not (k := self.tree_key()) or self.nodes[k].depth == 0 \
                or not self.can_write():
            return
        dn = self.nodes[k].dn
        parent = L.parent_of(dn)

        def done(v: Optional[dict]) -> None:
            if not v or (v["rdn"] == L.rdn_of(dn) and L.dn_key(v["parent"]) == L.dn_key(parent)):
                return
            moved = v["parent"] if L.dn_key(v["parent"]) != L.dn_key(parent) else None

            def after(new_dn: str) -> None:
                self.refresh_parent_of(dn)
                if moved:
                    self.refresh_parent_of(new_dn)
                self.reveal(new_dn)

            self.write(f"Renamed to {v['rdn']}", lambda: self.session.rename(dn, v["rdn"], moved), after)

        self.app.push_screen(FormModal(f"Rename / move · {L.rdn_of(dn)}", [
            Field("rdn", "New RDN", L.rdn_of(dn)), Field("parent", "Parent (change it to move)", parent)],
            validate=lambda v: None if "=" in v["rdn"] and v["parent"] else "RDN looks like attr=value"), done)

    def new_entry_form(self, parent: str) -> None:
        def step2(v: Optional[dict]) -> None:
            if not v:
                return
            classes = [c.strip() for c in v["classes"].replace(";", ",").split(",") if c.strip()]
            rdn_attr, _, rdn_val = v["rdn"].partition("=")
            must = [a for a in self.session.must_attrs(classes) if a.lower() != rdn_attr.strip().lower()]
            fields = [Field(f"m{i}", f"{a} (required)") for i, a in enumerate(must)]
            fields.append(Field("extra", "Other attributes", placeholder="attr=value; attr=value"))

            def check(x: dict) -> Optional[str]:
                missing = [a for i, a in enumerate(must) if not x[f"m{i}"]]
                return f"Missing: {', '.join(missing)}" if missing else None

            def done(x: Optional[dict]) -> None:
                if not x:
                    return
                attrs: dict[str, list[str]] = {rdn_attr.strip(): [rdn_val.strip()]}
                for i, a in enumerate(must):
                    attrs.setdefault(a, []).append(x[f"m{i}"])
                for part in x["extra"].split(";"):
                    k, sep, val = part.partition("=")
                    if sep and k.strip():
                        attrs.setdefault(k.strip(), []).append(val.strip())
                dn = f"{v['rdn'].strip()},{parent}"
                self.write(f"Created {v['rdn']}", lambda: self.session.add_entry(dn, classes, attrs),
                           lambda _: (self.refresh_node(L.dn_key(parent), then=dn)))

            self.app.push_screen(FormModal(f"New entry · {v['rdn']}", fields, validate=check,
                                           hint=f"objectClass: {', '.join(classes)}"), done)

        self.app.push_screen(FormModal(f"New entry under {L.rdn_of(parent)}", [
            Field("rdn", "RDN", placeholder="cn=name  ·  ou=Unit  ·  uid=user"),
            Field("classes", "objectClass", placeholder="inetOrgPerson, organizationalPerson, person, top")],
            enter_advances=True,
            validate=lambda v: None if "=" in v["rdn"] and v["classes"] else "RDN (attr=value) and objectClass"),
            step2)

    def action_refresh(self) -> None:
        fid = self.focused_id()
        if fid == "profiles":
            self.reload_profiles()
        elif fid == "tree" and (k := self.tree_key()):
            self.refresh_node(k)
            self.load_entry(self.nodes[k].dn)
        elif fid == "entry" and self.entry_dn:
            self.load_entry(self.entry_dn)

    def refresh_node(self, key: str, then: str = "") -> None:
        if key not in self.nodes:
            return
        self.nodes[key].loading = True
        self.render_tree()
        self.refresh_worker(key, then)

    @work(thread=True, group="tree")
    def refresh_worker(self, key: str, then: str) -> None:
        s, n = self.session, self.nodes.get(key)
        if not s or not n:
            return
        try:
            children, trunc = s.children(n.dn)
        except L.LdapError as e:
            self.app.call_from_thread(self.children_failed, key, str(e))
            return
        self.app.call_from_thread(self.children_loaded, s, key, children, trunc, True)
        if then:
            self.app.call_from_thread(self.reveal, then)

    def refresh_parent_of(self, dn: str) -> None:
        self.refresh_node(L.dn_key(L.parent_of(dn)))

    # ── escrituras ──

    def write(self, label: str, fn, after) -> None:
        self.write_worker(label, fn, after)

    @work(thread=True, group="write")
    def write_worker(self, label: str, fn, after) -> None:
        try:
            res = fn()
        except L.LdapError as e:
            self.app.call_from_thread(self.app.notify_err, str(e))
            return
        self.app.call_from_thread(self.app.notify_ok, label)
        self.app.call_from_thread(after, res)

    # ── búsqueda ──

    def action_search(self) -> None:
        if not self.session or not self.session.connected:
            self.app.notify_err("Not connected")
            return
        # Base por defecto: la raíz de la rama seleccionada (se puede cambiar en el form)
        dn = self.tree_dn()
        root = next((r for r in self.roots if dn and L.is_under(dn, self.nodes[r].dn)),
                    self.roots[0] if self.roots else None)
        base = self.nodes[root].dn if root else ""
        last = self.profile_state("search")

        def done(v: Optional[dict]) -> None:
            if not v:
                return
            last.update(filter=v["filter"], scope=v["scope"], attrs=v["attrs"])
            L.save_state(self.state)
            self.last_search = (v["base"], L.build_filter(v["filter"]), v["scope"], L.split_attrs(v["attrs"]))
            self.search_worker(*self.last_search)

        self.app.push_screen(FormModal("Search", [
            Field("filter", "Filter", last.get("filter", ""),
                  placeholder="(&(objectCategory=person)(objectClass=user)(sAMAccountName=jdoe*))"),
            Field("base", "Base DN", base),
            Field("scope", "Scope", last.get("scope", "sub"), choices=SCOPE),
            Field("attrs", "Attributes", last.get("attrs", ""), placeholder="cn, mail, sAMAccountName  (columns)")],
            hint="Standard LDAP filter (RFC 4515). Outer parentheses are optional.",
            validate=lambda v: None if v["filter"] and v["base"] else "Filter and base DN are needed"), done)

    def action_results(self) -> None:
        if self.last_results:
            self.search_done(*self.last_results)

    @work(thread=True, group="search", exclusive=True)
    def search_worker(self, base: str, flt: str, scope: str, attrs: list[str]) -> None:
        s = self.session
        try:
            res, trunc = s.search(base, flt, scope, attrs)
        except L.LdapError as e:
            self.app.call_from_thread(self.app.notify_err, f"Search: {e}")
            return
        if not res:
            self.app.call_from_thread(self.app.notify_err, f"No results for {flt} under {base}")
            return
        self.app.call_from_thread(self.search_done, res, trunc, attrs)

    def search_done(self, res: list, trunc: bool, attrs: list[str]) -> None:
        self.last_results = (res, trunc, attrs)
        # Con atributos pedidos, sus valores son las columnas (como la lista de resultados de Softerra)
        rows = [(c.dn, [Text(icon_for(c.classes), style=M), rdn_text(L.rdn_of(c.dn)),
                        *([Text(c.values.get(a, "")) for a in attrs] if attrs else [Text(L.parent_of(c.dn), style=M)])])
                for c in res]
        more = f" (first {L.MAX_RESULTS})" if trunc else ""

        def pick(dn: Optional[str]) -> None:
            if dn:
                self.reveal(dn)

        title = f"Search · {len(res)} result{'' if len(res) == 1 else 's'}{more}"
        self.app.push_screen(ResultsModal(title, [" ", "Entry", *(attrs or ["Parent"])], rows, self.export_results),
                             pick)

    def export_results(self) -> None:
        """Los resultados de la última búsqueda a una planilla (todos, no solo los de la lista)."""
        if not self.last_search or not self.session:
            return
        base, flt, scope, attrs = self.last_search
        fields = [Field("path", "File", str(Path.home() / f"lazyldap-{datetime.now():%Y%m%d-%H%M}.xlsx"), files=True)]
        if attrs:
            fields.append(Field("cols", "Columns", "req", choices=[(f"Requested: {', '.join(attrs)}", "req"),
                                                                    ("All attributes", "all")]))

        def done(v: Optional[dict]) -> None:
            if v:
                path = Path(v["path"]).expanduser()
                path = path if path.suffix.lower() == ".xlsx" else path.with_name(path.name + ".xlsx")
                self.excel_worker(base, flt, scope, attrs if v.get("cols", "all") == "req" else [], path)

        self.app.push_screen(FormModal("Export results to Excel", fields,
                                       hint=f"{flt}  ·  {scope} under {base}",
                                       validate=lambda v: None if v["path"] else "The file is missing"), done)

    @work(thread=True, group="export")
    def excel_worker(self, base: str, flt: str, scope: str, attrs: list[str], path: Path,
                     title: str = "Search") -> None:
        s = self.session
        try:
            entries = s.fetch(base, flt, scope, attrs)
            headers, rows = entries_table(entries, attrs or None)
            p = s.profile
            info = [["Server", p.url], ["Bound as", p.bind_dn if p.auth == "simple" else "anonymous"],
                    ["Base DN", base], ["Filter", flt], ["Scope", {"sub": "subtree", "one": "one level"}.get(scope, scope)],
                    ["Entries", str(len(entries))], ["Exported", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]]
            path.parent.mkdir(parents=True, exist_ok=True)
            write_xlsx(path, [("Results", headers, rows), (title, ["Field", "Value"], info)])
        except (L.LdapError, OSError) as e:
            self.app.call_from_thread(self.app.notify_err, f"Export: {e}")
            return
        self.app.call_from_thread(self.app.notify_ok, f"{len(entries)} entries → {path}")

    @work(thread=True, group="tree")
    def reveal(self, dn: str) -> None:
        """Expande el árbol hasta dn (cargando lo que falte) y lo selecciona."""
        s = self.session
        root = next((r for r in self.roots if L.is_under(dn, self.nodes[r].dn)), None)
        if not s or root is None:
            self.app.call_from_thread(self.reveal_done, s, dn, [], [])
            return
        parts = L.split_dn(dn)
        root_len = len(L.split_dn(self.nodes[root].dn))
        chain = [",".join(parts[i:]) for i in range(len(parts) - root_len, 0, -1)]   # root → padre de dn
        loaded = []
        known = {k: (n.children is not None) for k, n in self.nodes.items()}
        for anc in chain:
            k = L.dn_key(anc)
            if not known.get(k):
                try:
                    loaded.append((k, anc, *s.children(anc)))
                except L.LdapError:
                    break
                known[k] = True
        self.app.call_from_thread(self.reveal_done, s, dn, chain, loaded)

    def reveal_done(self, s, dn: str, chain: list[str], loaded: list) -> None:
        if s is not self.session:
            return
        for k, anc, children, trunc in loaded:
            if k not in self.nodes:   # lo crea set_children del padre; por las dudas
                parent = self.nodes.get(L.dn_key(L.parent_of(anc)))
                self.nodes[k] = Node(anc, depth=parent.depth + 1 if parent else 0)
            self.set_children(k, children, trunc)
        for anc in chain:
            if (k := L.dn_key(anc)) in self.nodes and self.nodes[k].children is not None:
                self.nodes[k].expanded = True
        self.render_tree()
        tree = self.query_one("#tree", Table)
        tree.focus()
        self.select_tree(L.dn_key(dn))
        self.load_entry(dn)   # aunque no esté en el árbol (fuera de los primeros N)

    # ── varios ──

    def action_copy(self) -> None:
        fid = self.focused_id()
        if fid == "entry" and (cur := self.current_value()):
            text = cur[0].values[cur[1]]
        elif fid == "tree" and self.tree_dn():
            text = self.tree_dn()
        else:
            return
        self.app.notify_ok("Copied") if copy_text(text) else self.app.notify_err("Could not copy (wl-copy?)")

    def action_copy_dn(self) -> None:
        dn = self.entry_dn or self.tree_dn()
        if dn:
            self.app.notify_ok("DN copied") if copy_text(dn) else self.app.notify_err("Could not copy (wl-copy?)")

    def action_export(self) -> None:
        dn = self.tree_dn() if self.focused_id() == "tree" else self.entry_dn
        if not dn or not self.session:
            return
        name = L.rdn_of(dn).partition("=")[2].replace("/", "_").replace(" ", "_") or "export"

        def done(v: Optional[dict]) -> None:
            if not v:
                return
            ext = "." + v["format"]
            path = Path(v["path"]).expanduser()
            path = path if path.suffix.lower() == ext else path.with_name(path.name + ext)
            if v["format"] == "xlsx":
                self.excel_worker(dn, "(objectClass=*)", v["scope"], [], path, title="Export")
            else:
                self.export_worker(dn, v["scope"] == "sub", path)

        self.app.push_screen(FormModal(f"Export · {L.rdn_of(dn)}", [
            Field("path", "File", str(Path.home() / name), files=True),
            Field("format", "Format", "ldif", choices=[("LDIF (.ldif)", "ldif"), ("Excel (.xlsx)", "xlsx")]),
            Field("scope", "What", "sub", choices=[("Entry and everything below", "sub"), ("Only this entry", "base")])],
            hint="The extension is added if it's missing.",
            validate=lambda v: None if v["path"] else "The file is missing"), done)

    @work(thread=True, group="export")
    def export_worker(self, dn: str, subtree: bool, path: Path) -> None:
        try:
            text, n = self.session.ldif(dn, subtree)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        except (L.LdapError, OSError) as e:
            self.app.call_from_thread(self.app.notify_err, f"Export: {e}")
            return
        self.app.call_from_thread(self.app.notify_ok, f"{n} entries → {path}")

    def action_help(self) -> None:
        t = Text()
        t.append("Keys (remappable in ~/.config/lazyldap/keymap.json)\n\n", style=f"bold {M}")
        for b in [*bindings_of(type(self))]:
            t.append(f"{key_display(b.key):<8}", style=f"bold {P}")
            t.append(f"{b.description or b.action:<26}", style="")
            t.append(f"{b.id}\n", style=M)
        t.append("\nenter   connect / expand / view value\ntab     next panel\nq       quit\n", style="")
        self.app.push_screen(TextModal("Help", t, end=False))

    def action_log(self) -> None:
        if not self.session:
            return
        t = Text()
        for when, op, dn, res in self.session.log:
            t.append(time.strftime("%H:%M:%S ", time.localtime(when)), style=M)
            t.append(f"{op:<7} ", style="bold")
            t.append(f"{res:<14} ", style=ERR if res == "error" else OK)
            t.append(dn + "\n")
        self.app.push_screen(TextModal(f"Session log · {self.session.profile.name}", t or "Nothing yet"))


def LazyLdapApp(autoconnect: str = "") -> ViewApp:
    return ViewApp(LazyLdapView, title="lazyldap", autoconnect=autoconnect)
