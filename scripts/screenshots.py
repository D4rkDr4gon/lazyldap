#!/usr/bin/env python3
"""
screenshots.py — regenera las capturas del README con el modo demo.

    PYTHONPATH=src python3 scripts/screenshots.py

Corre la TUI headless (Textual run_test), guarda cada escena en SVG y la pasa
a PNG con rsvg-convert (si no está, quedan los SVG). Usa el tema por defecto.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
SIZE = (150, 46)

os.environ["LAZYLDAP_THEME"] = "/nonexistent"
sys.path.insert(0, str(ROOT / "src"))

from lazyldap import demo  # noqa: E402

PROFILE = demo.setup()

from lazyldap.app import LazyLdapApp  # noqa: E402

ANA = f"CN=Ana García,OU=IT,OU=Users,OU=Acme,{demo.DOMAIN}"


async def settle(app, pilot) -> None:
    for _ in range(5):
        await app.workers.wait_for_complete()
        await pilot.pause(0.15)


def save(app, name: str) -> None:
    svg = OUT / f"{name}.svg"
    app.save_screenshot(str(svg))
    if shutil.which("rsvg-convert"):
        # Sin xml:space="preserve" rsvg colapsa los espacios y la captura se ve corrida
        fixed = svg.read_text().replace("<svg ", '<svg xml:space="preserve" ', 1)
        svg.write_text(fixed)
        subprocess.run(["rsvg-convert", "--zoom", "1.25", str(svg), "-o", str(svg.with_suffix(".png"))], check=True)
        svg.unlink()
    print("→", name)


async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = LazyLdapApp(PROFILE)
    async with app.run_test(size=SIZE) as pilot:
        v = app.view
        await settle(app, pilot)

        # 1. Árbol + entrada
        v.reveal(ANA)
        await settle(app, pilot)
        save(app, "browse")

        # 2. Búsqueda (form)
        await pilot.press("slash")
        await pilot.pause()
        app.screen.query_one("#f-filter").value = "(&(objectCategory=person)(objectClass=user)(department=*))"
        app.screen.query_one("#f-attrs").value = "sAMAccountName, title, department, mail"
        await pilot.pause()
        save(app, "search")

        # 3. Resultados con columnas
        app.screen.query_one("#f-filter").value = "(&(objectClass=user)(department=*))"
        await pilot.press("ctrl+s")
        await settle(app, pilot)
        save(app, "results")

        # 4. Export a Excel
        await pilot.press("e")
        await pilot.pause()
        app.screen.query_one("#f-path").value = "~/findings/it-users.xlsx"
        await pilot.pause()
        save(app, "export-excel")
        await pilot.press("escape", "escape")
        await pilot.pause()

        # 5. Perfil
        await pilot.press("1", "e")
        await pilot.pause()
        save(app, "profile")


if __name__ == "__main__":
    asyncio.run(main())
