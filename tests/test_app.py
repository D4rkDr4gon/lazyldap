"""La TUI headless (Textual run_test) contra el AD falso del modo demo."""

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

os.environ["LAZYLDAP_THEME"] = "/nonexistent"     # tema por defecto

from lazyldap import demo  # noqa: E402

PROFILE = demo.setup()

from lazyldap.app import LazyLdapApp  # noqa: E402


async def settle(app, pilot):
    for _ in range(4):
        await app.workers.wait_for_complete()
        await pilot.pause(0.1)


class AppTest(unittest.IsolatedAsyncioTestCase):
    async def test_browse_search_and_export(self):
        app = LazyLdapApp(PROFILE)
        async with app.run_test(size=(160, 44)) as pilot:
            await settle(app, pilot)
            v = app.view
            self.assertTrue(v.session.connected)
            self.assertEqual(v.tree_dn(), demo.DOMAIN)

            await pilot.press("slash")
            await pilot.pause()
            app.screen.query_one("#f-filter").value = "(&(objectClass=user)(department=IT))"
            app.screen.query_one("#f-attrs").value = "sAMAccountName, title"
            await pilot.press("ctrl+s")
            await settle(app, pilot)
            self.assertEqual(len(app.screen.rows), 4)

            out = Path(tempfile.mkdtemp()) / "it"
            await pilot.press("e")
            await pilot.pause()
            app.screen.query_one("#f-path").value = str(out)
            await pilot.press("ctrl+s")
            await settle(app, pilot)
            with zipfile.ZipFile(out.with_suffix(".xlsx")) as z:
                sheet = z.read("xl/worksheets/sheet1.xml").decode()
            self.assertIn("bfernandez", sheet)
            self.assertIn("Network Engineer", sheet)

            await pilot.press("enter")                    # ir a la entrada elegida
            await settle(app, pilot)
            self.assertTrue(v.entry_dn.startswith("CN="))
            self.assertIn("OU=IT", v.tree_dn())


if __name__ == "__main__":
    unittest.main()
