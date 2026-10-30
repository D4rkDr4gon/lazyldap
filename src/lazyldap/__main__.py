"""Punto de entrada: `lazyldap [perfil]`, `lazyldap --demo`, `python -m lazyldap`."""

from __future__ import annotations

import argparse
import sys

from . import __version__


def main() -> None:
    ap = argparse.ArgumentParser(prog="lazyldap", description="A terminal LDAP browser.")
    ap.add_argument("profile", nargs="?", default="", help="connect to this profile on start")
    ap.add_argument("--demo", action="store_true", help="browse a fake Active Directory (no server needed)")
    ap.add_argument("--version", action="version", version=f"lazyldap {__version__}")
    args = ap.parse_args()
    try:
        import ldap3  # noqa: F401
        import textual  # noqa: F401
    except ImportError as e:
        sys.exit(f"lazyldap needs {e.name}: pip install {e.name}  (Arch: pacman -S python-{e.name})")
    profile = args.profile
    if args.demo:
        from .demo import setup
        profile = setup()
    from .app import LazyLdapApp
    LazyLdapApp(profile).run()


if __name__ == "__main__":
    main()
