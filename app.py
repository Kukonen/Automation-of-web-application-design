"""Run the local teaching CMS: python app.py --demo."""
import argparse
import os
from pathlib import Path
from wsgiref.simple_server import make_server

from core import CMS
from web import WebApp


def load_env(path):
    """Read only CMS settings, without evaluating shell syntax or logging secrets."""
    path = Path(path)
    if not path.is_file():
        return
    allowed = {"CMS_DEMO_PASSWORD", "CMS_BASE_URL"}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key not in allowed:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if value:
            os.environ.setdefault(key, value)


def main():
    parser = argparse.ArgumentParser(description="Учебный портал Кафедра")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--demo", action="store_true", help="Учебные пользователи и примеры, пароль из CMS_DEMO_PASSWORD")
    args = parser.parse_args()
    root = Path(__file__).parent
    load_env(root / ".env")
    cms = CMS(root)
    if args.demo:
        password = os.environ.get("CMS_DEMO_PASSWORD", "Demo-Only-2026!")
        cms.seed(password)
        print("DEMO: admin, editor, author; пароль из CMS_DEMO_PASSWORD (по умолчанию Demo-Only-2026!).")
    app = WebApp(cms, root, os.environ.get("CMS_BASE_URL", f"http://{'localhost' if args.host in {'0.0.0.0', '127.0.0.1'} else args.host}:{args.port}"))
    print(f"Портал: http://{args.host}:{args.port}  Панель: /admin")
    with make_server(args.host, args.port, app) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
