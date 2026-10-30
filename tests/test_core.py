"""Backend contra el AD falso del modo demo (servidor simulado de ldap3)."""

import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree

os.environ["LAZYLDAP_CONF"] = os.path.join(tempfile.mkdtemp(), "profiles.json")

from lazyldap import core, demo  # noqa: E402
from lazyldap.xlsx import entries_table, write_xlsx  # noqa: E402

demo.setup()


def session(mode: str = "readwrite") -> core.Session:
    p = core.Profile("t", demo.HOST, bind_dn=demo.ADMIN, base_dn=demo.DOMAIN, mode=mode)
    s = core.Session(p, demo.PASSWORD)
    s.connect()
    return s


class FilterTest(unittest.TestCase):
    def test_filter_goes_as_is(self):
        f = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        self.assertEqual(core.build_filter(f), f)

    def test_outer_parentheses_are_added(self):
        self.assertEqual(core.build_filter(" sAMAccountName=a* "), "(sAMAccountName=a*)")

    def test_split_attrs(self):
        self.assertEqual(core.split_attrs("cn, mail;sn  title"), ["cn", "mail", "sn", "title"])


class DnTest(unittest.TestCase):
    def test_parts(self):
        dn = r"CN=Smith\, John,OU=Users,DC=acme,DC=local"
        self.assertEqual(core.rdn_of(dn), r"CN=Smith\, John")
        self.assertEqual(core.parent_of(dn), "OU=Users,DC=acme,DC=local")
        self.assertTrue(core.is_under(dn, "dc=ACME, dc=local"))
        self.assertFalse(core.is_under("DC=acme2,DC=local", "DC=acme,DC=local"))


class SessionTest(unittest.TestCase):
    def test_tree_and_entry(self):
        s = session()
        self.assertEqual(s.roots, [demo.DOMAIN])
        names = [core.rdn_of(c.dn) for c in s.children(demo.DOMAIN)[0]]
        self.assertIn("OU=Acme", names)
        attrs = {a.name: a for a in s.entry(f"CN=Ana García,OU=IT,OU=Users,OU=Acme,{demo.DOMAIN}")}
        self.assertEqual(attrs["sAMAccountName"].values, ["agarcia"])
        self.assertTrue(attrs["objectSid"].values[0].startswith("S-1-5-21-"))
        self.assertEqual(list(attrs)[0], "objectClass")

    def test_search_with_columns(self):
        res, trunc = session().search(demo.DOMAIN, "(&(objectClass=user)(department=Finance))", "sub",
                                      ["sAMAccountName", "title"])
        self.assertFalse(trunc)
        self.assertEqual(sorted(c.values["sAMAccountName"] for c in res), ["eruiz", "flopez", "gsosa"])

    def test_readonly_blocks_writes(self):
        s = session("readonly")
        with self.assertRaises(core.LdapError):
            s.add_value(demo.ADMIN, "description", "x")

    def test_write_cycle(self):
        s = session()
        parent = f"OU=HR,OU=Users,OU=Acme,{demo.DOMAIN}"
        dn = f"CN=Test User,{parent}"
        s.add_entry(dn, ["user"], {"cn": ["Test User"], "sAMAccountName": ["tuser"]})
        s.add_value(dn, "mail", "t@acme.com")
        s.replace_value(dn, "mail", b"t@acme.com", "t2@acme.com")
        self.assertIn("t2@acme.com", {a.name: a for a in s.entry(dn)}["mail"].values)
        new = s.rename(dn, "CN=Test User2", None)
        s.delete_entry(new)
        self.assertNotIn(new.lower(), [c.dn.lower() for c in s.children(parent)[0]])
        self.assertEqual([op for _, op, _, _ in s.log][-1], "list")


class XlsxTest(unittest.TestCase):
    def test_export_is_valid_xlsx(self):
        s = session()
        entries = s.fetch(demo.DOMAIN, "(objectClass=group)", "sub", ["cn", "member"])
        headers, rows = entries_table(entries, ["cn", "member"])
        self.assertEqual(headers, ["dn", "cn", "member"])
        path = Path(tempfile.mkdtemp()) / "out.xlsx"
        write_xlsx(path, [("Results", headers, rows), ("Search", ["Field", "Value"], [["Filter", "(x<y&z)"]])])
        with zipfile.ZipFile(path) as z:
            self.assertIsNone(z.testzip())
            for name in z.namelist():
                if name.endswith(".xml") or name.endswith(".rels"):
                    ElementTree.fromstring(z.read(name))      # XML bien formado
            sheet = z.read("xl/worksheets/sheet1.xml").decode()
        self.assertIn("Domain Admins", sheet)
        self.assertIn('<autoFilter ref="A1:C7"/>', sheet)

    def test_all_attributes_objectclass_first(self):
        headers, _ = entries_table([("a", {"sn": ["x"], "objectClass": ["top"], "cn": ["y"]})])
        self.assertEqual(headers, ["dn", "objectClass", "cn", "sn"])


if __name__ == "__main__":
    unittest.main()
