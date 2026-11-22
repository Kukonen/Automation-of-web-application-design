"""CMS services. JSON schemas extend content without changing this module."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from hashlib import pbkdf2_hmac, sha256
import hmac
from io import BytesIO
import json
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlsplit


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CMS:
    """Repository and policy boundary shared by HTTP, CLI and tests."""

    STATES = {"draft", "review", "published", "archived"}
    TRANSITIONS = {
        "draft": {"review"}, "review": {"draft", "published"},
        "published": {"archived", "draft"}, "archived": {"draft"},
    }

    def __init__(self, root, db_path=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "data").mkdir(exist_ok=True)
        self.db_path = str(db_path or self.root / "data" / "cms.sqlite3")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.schemas = {}
        self.migrate()

    def close(self):
        self.conn.close()

    def migrate(self):
        """Apply ordered SQL migrations and version configuration changes."""
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        source = Path(__file__).parent
        migrations = self.root / "migrations"
        if not migrations.is_dir():
            migrations = source / "migrations"
        for file in sorted(migrations.glob("*.sql")):
            if self.conn.execute("SELECT 1 FROM migrations WHERE name=?", (file.name,)).fetchone():
                continue
            try:
                escaped_name = file.name.replace("'", "''")
                self.conn.executescript(
                    "BEGIN;\n" + file.read_text(encoding="utf-8")
                    + f"\nINSERT INTO migrations VALUES ('{escaped_name}', '{now()}');\nCOMMIT;"
                )
            except sqlite3.Error:
                self.conn.rollback()
                raise
        schemas = self.root / "schemas"
        if not schemas.is_dir():
            schemas = source / "schemas"
        loaded = {}
        for file in sorted(schemas.glob("*.json")):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", file.stem):
                raise ValueError("Некорректное имя типа материала")
            schema = json.loads(file.read_text(encoding="utf-8"))
            if not isinstance(schema.get("label"), str) or not isinstance(schema.get("fields"), dict):
                raise ValueError("Схема должна содержать label и fields")
            for name, rule in schema["fields"].items():
                if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", name):
                    raise ValueError("Некорректное имя поля")
                if rule.get("type") not in {"text", "integer", "url", "date"}:
                    raise ValueError("Неизвестный тип поля")
            loaded[file.stem] = schema
        if not loaded:
            raise ValueError("Не найдено ни одной контентной схемы")
        with self.conn:
            for name, schema in loaded.items():
                encoded = json.dumps(schema, ensure_ascii=False, sort_keys=True)
                previous = self.conn.execute(
                    "SELECT * FROM content_types WHERE name=?", (name,)
                ).fetchone()
                if previous and previous["schema_json"] == encoded:
                    continue
                # Validate existing rows before accepting an incompatible schema change.
                for row in self.conn.execute("SELECT fields_json FROM materials WHERE type=?", (name,)):
                    self._validate_fields(schema, json.loads(row["fields_json"]))
                version = previous["version"] + 1 if previous else 1
                self.conn.execute(
                    "INSERT INTO content_types VALUES (?,?,?) ON CONFLICT(name) DO UPDATE "
                    "SET schema_json=excluded.schema_json,version=excluded.version",
                    (name, encoded, version),
                )
                self.conn.execute(
                    "INSERT INTO schema_history(type_name,version,digest,applied_at) VALUES(?,?,?,?)",
                    (name, version, sha256(encoded.encode()).hexdigest(), now()),
                )
        self.schemas = loaded

    @staticmethod
    def _password_hash(password, salt=None):
        salt = salt or secrets.token_hex(16)
        digest = pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 150000).hex()
        return f"pbkdf2_sha256$150000${salt}${digest}"

    def create_user(self, username, password, role, actor=None):
        if role not in {"admin", "editor", "author"}:
            raise ValueError("Неизвестная роль")
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,40}", username):
            raise ValueError("Логин: от 3 до 40 латинских букв, цифр или подчеркиваний")
        if len(password) < 10 or len(password) > 200:
            raise ValueError("Пароль: от 10 до 200 символов")
        has_users = self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if has_users and not self.can(actor, "users"):
            raise PermissionError("Управление пользователями доступно администратору")
        try:
            with self.conn:
                cursor = self.conn.execute(
                    "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                    (username, self._password_hash(password), role),
                )
                self._audit(actor, "user.create", None, username)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Логин уже занят") from exc
        return {"id": cursor.lastrowid, "username": username, "role": role}

    def authenticate(self, username, password):
        row = self.conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            # A dummy hash keeps unknown-user work comparable to a wrong password.
            self._password_hash(password, "00" * 16)
            return None
        salt = row["password_hash"].split("$")[2]
        if not hmac.compare_digest(row["password_hash"], self._password_hash(password, salt)):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}

    def start_session(self, user):
        if not self._actor(user):
            raise PermissionError("Неизвестный пользователь")
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(timespec="seconds")
        with self.conn:
            self.conn.execute(
                "INSERT INTO sessions VALUES(?,?,?,?)",
                (sha256(token.encode()).hexdigest(), user["id"], secrets.token_urlsafe(32), expires),
            )
            self._audit(user, "session.login", None, "")
        return token

    def _session(self, token):
        if not token or not isinstance(token, str):
            return None
        return self.conn.execute(
            "SELECT s.*,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>?", (sha256(token.encode()).hexdigest(), now())
        ).fetchone()

    def session_user(self, token):
        row = self._session(token)
        return {"id": row["user_id"], "username": row["username"], "role": row["role"]} if row else None

    def csrf_token(self, token):
        row = self._session(token)
        return row["csrf"] if row else None

    def end_session(self, token):
        with self.conn:
            self.conn.execute("DELETE FROM sessions WHERE token_hash=?", (sha256(token.encode()).hexdigest(),))

    def _actor(self, actor):
        if not isinstance(actor, dict) or not isinstance(actor.get("id"), int):
            return None
        row = self.conn.execute("SELECT id,username,role FROM users WHERE id=?", (actor["id"],)).fetchone()
        return dict(row) if row else None

    def can(self, actor, operation, material=None, type_name=None):
        """Reload authority from DB: a forged role in an actor dict grants nothing."""
        actor = self._actor(actor)
        if not actor or (type_name and type_name not in self.schemas):
            return False
        role = actor["role"]
        known = {"create", "read", "update", "delete", "review", "publish", "archive", "restore", "stats", "audit", "users", "schemas", "media", "draft"}
        if operation not in known:
            return False
        if role == "admin":
            return True
        if operation in {"users", "schemas", "stats", "audit"}:
            return False
        if role == "editor":
            return True
        if operation in {"create", "media"}:
            return True
        own = bool(material and material["author_id"] == actor["id"])
        if operation == "read":
            return own
        if operation in {"update", "delete", "restore", "review"}:
            return own and material["status"] == "draft"
        return False

    def _require(self, actor, operation, material=None, type_name=None):
        if not self.can(actor, operation, material, type_name):
            raise PermissionError("Недостаточно прав для операции")

    @staticmethod
    def _validate_fields(schema, fields):
        if not isinstance(fields, dict):
            raise ValueError("Дополнительные поля должны быть объектом")
        if set(fields) - set(schema["fields"]):
            raise ValueError("Неизвестное дополнительное поле")
        result = {}
        for name, rule in schema["fields"].items():
            value = fields.get(name)
            if value is None or value == "":
                if rule.get("required"):
                    raise ValueError(f"Обязательное поле: {rule.get('label', name)}")
                continue
            kind = rule["type"]
            if kind == "integer":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"Поле {name} должно быть целым числом")
                if value < rule.get("minimum", -2147483648) or value > rule.get("maximum", 2147483647):
                    raise ValueError(f"Поле {name} вне допустимого диапазона")
            else:
                if not isinstance(value, str) or len(value) > rule.get("max_length", 2000):
                    raise ValueError(f"Некорректная строка в поле {name}")
                if kind == "date":
                    try:
                        date.fromisoformat(value)
                    except ValueError as exc:
                        raise ValueError(f"Некорректная дата в поле {name}") from exc
                if kind == "url":
                    parts = urlsplit(value)
                    if parts.scheme not in {"https", "http"} or not parts.netloc:
                        raise ValueError("Ссылка должна начинаться с https:// или http://")
            result[name] = value
        return result

    def _validate(self, data, existing=None):
        allowed = {"type", "title", "slug", "body", "description", "category", "tags", "fields"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError("Неизвестное поле материала")
        merged = {k: existing[k] for k in allowed if existing and k in existing}
        merged.update(data)
        type_name = merged.get("type")
        if type_name not in self.schemas:
            raise ValueError("Неизвестный тип материала")
        if existing and type_name != existing["type"]:
            raise ValueError("Тип существующего материала менять нельзя")
        for key, limit in [("title", 200), ("body", 100000), ("description", 300), ("category", 100)]:
            value = merged.get(key, "")
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError(f"Некорректное поле {key}")
            merged[key] = value.strip()
        if not merged["title"]:
            raise ValueError("Заголовок обязателен")
        slug = merged.get("slug", "")
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) or len(slug) > 120:
            raise ValueError("Slug: латинские строчные буквы, цифры и дефисы")
        merged["fields"] = self._validate_fields(self.schemas[type_name], merged.get("fields", {}))
        tags = merged.get("tags", [])
        if not isinstance(tags, list) or len(tags) > 20:
            raise ValueError("Допускается до 20 тегов")
        if any(not isinstance(t, str) or not t.strip() or len(t) > 80 for t in tags):
            raise ValueError("Некорректный тег")
        merged["tags"] = list(dict.fromkeys(t.strip() for t in tags))
        return merged

    def _terms(self, material_id, category, tags):
        self.conn.execute("DELETE FROM material_terms WHERE material_id=?", (material_id,))
        for kind, name in ([("category", category)] if category else []) + [("tag", t) for t in tags]:
            self.conn.execute("INSERT OR IGNORE INTO terms(kind,name) VALUES(?,?)", (kind, name))
            term_id = self.conn.execute("SELECT id FROM terms WHERE kind=? AND name=?", (kind, name)).fetchone()[0]
            self.conn.execute("INSERT INTO material_terms VALUES(?,?)", (material_id, term_id))

    def _material(self, row):
        if not row:
            return None
        item = dict(row)
        item["fields"] = json.loads(item.pop("fields_json"))
        terms = self.conn.execute(
            "SELECT kind,name FROM terms JOIN material_terms mt ON mt.term_id=terms.id "
            "WHERE mt.material_id=? ORDER BY terms.id", (item["id"],)
        ).fetchall()
        item["category"] = next((t["name"] for t in terms if t["kind"] == "category"), "")
        item["tags"] = [t["name"] for t in terms if t["kind"] == "tag"]
        return item

    def _get(self, identifier):
        """Internal repository read. Public callers must use get with a policy."""
        column = "id" if isinstance(identifier, int) else "slug"
        row = self.conn.execute(
            f"SELECT m.*,u.username AS author_name FROM materials m JOIN users u ON u.id=m.author_id WHERE m.{column}=?",
            (identifier,),
        ).fetchone()
        return self._material(row)

    def get(self, identifier, public=False, actor=None):
        """Read published content publicly or enforce an authenticated role."""
        if not public and not self._actor(actor):
            raise PermissionError("Для чтения служебного материала требуется вход")
        item = self._get(identifier)
        if public:
            return item if item and item["status"] == "published" else None
        if item:
            self._require(actor, "read", item)
        return item

    def _existing(self, identifier):
        item = self._get(identifier)
        if not item:
            raise LookupError("Материал не найден")
        return item

    def list(self, public=True, actor=None, type_name=None, category=None, tag=None, q=None, status=None, page=1, page_size=10):
        if isinstance(page, bool) or isinstance(page_size, bool):
            raise ValueError("Некорректная пагинация")
        try:
            page, page_size = int(page), int(page_size)
        except (TypeError, ValueError) as exc:
            raise ValueError("Некорректная пагинация") from exc
        if page < 1 or page_size < 1 or page_size > 100:
            raise ValueError("Страница от 1, размер страницы от 1 до 100")
        clauses, args = [], []
        if public:
            clauses.append("m.status='published'")
        else:
            current = self._actor(actor)
            if not current:
                raise PermissionError("Требуется вход")
            if current["role"] == "author":
                clauses.append("m.author_id=?")
                args.append(current["id"])
        for key, value in [("type", type_name), ("status", status)]:
            if value:
                clauses.append(f"m.{key}=?")
                args.append(value)
        for kind, value in [("category", category), ("tag", tag)]:
            if value:
                clauses.append("EXISTS(SELECT 1 FROM material_terms mt JOIN terms t ON t.id=mt.term_id "
                               "WHERE mt.material_id=m.id AND t.kind=? AND t.name=?)")
                args.extend([kind, value])
        if q:
            clauses.append("(m.title LIKE ? ESCAPE '\\' OR m.body LIKE ? ESCAPE '\\')")
            escaped = str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            args.extend([f"%{escaped}%"] * 2)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        total = self.conn.execute("SELECT count(*) FROM materials m" + where, args).fetchone()[0]
        rows = self.conn.execute(
            "SELECT m.*,u.username AS author_name FROM materials m JOIN users u ON u.id=m.author_id" + where
            + " ORDER BY m.published_at DESC,m.id DESC LIMIT ? OFFSET ?", args + [page_size, (page - 1) * page_size]
        ).fetchall()
        return {"items": [self._material(r) for r in rows], "total": total, "page": page,
                "page_size": page_size, "pages": (total + page_size - 1) // page_size}

    def _audit(self, actor, operation, material_id, detail):
        self.conn.execute(
            "INSERT INTO audit(actor_id,operation,material_id,detail,created_at) VALUES(?,?,?,?,?)",
            (actor["id"] if actor else None, operation, material_id, detail, now()),
        )

    def _revision(self, material_id, actor):
        item = self._existing(material_id)
        self.conn.execute(
            "INSERT INTO revisions(material_id,number,snapshot,actor_id,created_at) VALUES(?,?,?,?,?)",
            (material_id, item["revision"], json.dumps(item, ensure_ascii=False), actor["id"], now()),
        )

    def create(self, data, actor):
        data = self._validate(data)
        self._require(actor, "create", type_name=data["type"])
        timestamp = now()
        try:
            with self.conn:
                cursor = self.conn.execute(
                    "INSERT INTO materials(type,title,slug,body,description,fields_json,status,author_id,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,'draft',?,?,?)",
                    (data["type"], data["title"], data["slug"], data["body"], data["description"],
                     json.dumps(data["fields"], ensure_ascii=False), actor["id"], timestamp, timestamp),
                )
                material_id = cursor.lastrowid
                self._terms(material_id, data["category"], data["tags"])
                self._revision(material_id, actor)
                self._audit(actor, "material.create", material_id, data["type"])
        except sqlite3.IntegrityError as exc:
            raise ValueError("Адрес материала уже занят") from exc
        return self._get(material_id)

    def update(self, material_id, data, actor):
        item = self._existing(material_id)
        self._require(actor, "update", item)
        data = self._validate(data, item)
        try:
            with self.conn:
                self._update_fields(material_id, data)
                self._revision(material_id, actor)
                self._audit(actor, "material.update", material_id, "")
        except sqlite3.IntegrityError as exc:
            raise ValueError("Адрес материала уже занят") from exc
        return self._get(material_id)

    def _update_fields(self, material_id, data):
        self.conn.execute(
            "UPDATE materials SET title=?,slug=?,body=?,description=?,fields_json=?,revision=revision+1,updated_at=? WHERE id=?",
            (data["title"], data["slug"], data["body"], data["description"], json.dumps(data["fields"], ensure_ascii=False), now(), material_id),
        )
        self._terms(material_id, data["category"], data["tags"])

    def transition(self, material_id, status, actor):
        item = self._existing(material_id)
        if status not in self.TRANSITIONS[item["status"]]:
            raise ValueError("Недопустимый переход состояния")
        operation = {"review": "review", "published": "publish", "archived": "archive", "draft": "draft"}[status]
        self._require(actor, operation, item)
        with self.conn:
            published_at = now() if status == "published" and not item["published_at"] else item["published_at"]
            self.conn.execute(
                "UPDATE materials SET status=?,published_at=?,revision=revision+1,updated_at=? WHERE id=?",
                (status, published_at, now(), material_id),
            )
            self._revision(material_id, actor)
            self._audit(actor, "material.transition", material_id, f"{item['status']} -> {status}")
        return self._get(material_id)

    def revisions(self, material_id, actor):
        item = self._existing(material_id)
        self._require(actor, "read", item)
        rows = self.conn.execute("SELECT * FROM revisions WHERE material_id=? ORDER BY number DESC", (material_id,))
        return [dict(r) | {"snapshot": json.loads(r["snapshot"])} for r in rows]

    def restore(self, material_id, revision_id, actor):
        item = self._existing(material_id)
        self._require(actor, "restore", item)
        row = self.conn.execute("SELECT snapshot FROM revisions WHERE id=? AND material_id=?", (revision_id, material_id)).fetchone()
        if not row:
            raise LookupError("Ревизия не найдена")
        previous = json.loads(row["snapshot"])
        data = self._validate({k: previous[k] for k in ["type", "title", "slug", "body", "description", "category", "tags", "fields"]}, item)
        try:
            with self.conn:
                self._update_fields(material_id, data)
                # Restoring historical text never resurrects publication or rewrites authorship.
                self.conn.execute("UPDATE materials SET status='draft' WHERE id=?", (material_id,))
                self._revision(material_id, actor)
                self._audit(actor, "material.restore", material_id, str(revision_id))
        except sqlite3.IntegrityError as exc:
            raise ValueError("Исторический адрес уже занят") from exc
        return self._get(material_id)

    def delete(self, material_id, actor):
        item = self._existing(material_id)
        self._require(actor, "delete", item)
        with self.conn:
            self.conn.execute("DELETE FROM materials WHERE id=?", (material_id,))
            self._audit(actor, "material.delete", material_id, item["slug"])

    def bulk(self, ids, operation, actor):
        if operation not in {"delete", "review", "published", "archived", "draft"}:
            raise ValueError("Неизвестная пакетная операция")
        if not ids or len(ids) > 100 or len(set(ids)) != len(ids):
            raise ValueError("Пакет должен содержать от 1 до 100 различных материалов")
        # Preflight every row before mutations; outer savepoint protects the complete batch.
        for material_id in ids:
            item = self._existing(material_id)
            permission = "delete" if operation == "delete" else {"review": "review", "published": "publish", "archived": "archive", "draft": "draft"}[operation]
            self._require(actor, permission, item)
            if operation != "delete" and operation not in self.TRANSITIONS[item["status"]]:
                raise ValueError("Пакет содержит недопустимый переход")
        self.conn.execute("SAVEPOINT batch")
        try:
            for material_id in ids:
                item = self._existing(material_id)
                if operation == "delete":
                    self.conn.execute("DELETE FROM materials WHERE id=?", (material_id,))
                    self._audit(actor, "material.delete", material_id, "bulk")
                else:
                    published_at = now() if operation == "published" and not item["published_at"] else item["published_at"]
                    self.conn.execute("UPDATE materials SET status=?,published_at=?,revision=revision+1,updated_at=? WHERE id=?",
                                      (operation, published_at, now(), material_id))
                    self._revision(material_id, actor)
                    self._audit(actor, "material.transition", material_id, "bulk:" + operation)
            self.conn.execute("RELEASE batch")
            self.conn.commit()
        except Exception:
            self.conn.execute("ROLLBACK TO batch")
            self.conn.execute("RELEASE batch")
            raise
        return len(ids)

    def save_media(self, filename, content, actor):
        self._require(actor, "media")
        if not isinstance(content, bytes) or not content or len(content) > 5 * 1024 * 1024:
            raise ValueError("Изображение должно быть размером до 5 МБ")
        from PIL import Image, ImageOps, UnidentifiedImageError
        try:
            with Image.open(BytesIO(content)) as source:
                if source.format not in {"PNG", "JPEG", "WEBP"}:
                    raise ValueError("Допустимы PNG, JPEG и WebP")
                if source.width * source.height > 20000000:
                    raise ValueError("Изображение слишком большое")
                source.load()
                image = ImageOps.exif_transpose(source).convert("RGB")
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
            raise ValueError("Файл не является поддерживаемым изображением") from exc
        media_dir = self.root / "data" / "media"
        media_dir.mkdir(parents=True, exist_ok=True)
        name = secrets.token_hex(16)
        names = {"filename": name + ".jpg", "thumb": name + "-thumb.jpg", "preview": name + "-preview.jpg"}
        written = []
        try:
            for key, size in [("filename", None), ("thumb", (320, 320)), ("preview", (960, 960))]:
                derivative = image.copy()
                if size:
                    derivative.thumbnail(size)
                path = media_dir / names[key]
                derivative.save(path, "JPEG", quality=88)
                written.append(path)
            with self.conn:
                cursor = self.conn.execute(
                    "INSERT INTO media(filename,original_name,mime,size,width,height,thumb,preview,uploader_id,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (names["filename"], Path(filename).name[:200], "image/jpeg", written[0].stat().st_size,
                     image.width, image.height, names["thumb"], names["preview"], actor["id"], now()),
                )
                self._audit(actor, "media.upload", None, names["filename"])
        except Exception:
            for path in written:
                path.unlink(missing_ok=True)
            raise
        return dict(self.conn.execute("SELECT * FROM media WHERE id=?", (cursor.lastrowid,)).fetchone())

    def list_media(self, actor):
        self._require(actor, "media")
        return [dict(r) for r in self.conn.execute("SELECT * FROM media ORDER BY id DESC")]

    def record_view(self, material_id):
        item = self._existing(material_id)
        if item["status"] != "published":
            raise ValueError("Просмотр доступен только опубликованному материалу")
        with self.conn:
            self.conn.execute("INSERT INTO views(material_id,viewed_at) VALUES(?,?)", (material_id, now()))

    def stats(self, actor):
        self._require(actor, "stats")
        return {
            "total_views": self.conn.execute("SELECT count(*) FROM views").fetchone()[0],
            "views": [dict(r) for r in self.conn.execute("SELECT m.id,m.title,count(v.id) AS count FROM materials m LEFT JOIN views v ON v.material_id=m.id GROUP BY m.id ORDER BY count DESC")],
            "publications": [dict(r) for r in self.conn.execute("SELECT substr(published_at,1,10) AS day,count(*) AS count FROM materials WHERE published_at IS NOT NULL GROUP BY day ORDER BY day")],
            "authors": [dict(r) for r in self.conn.execute("SELECT u.username,count(DISTINCT m.id) AS materials,count(DISTINCT a.id) AS actions FROM users u LEFT JOIN materials m ON m.author_id=u.id LEFT JOIN audit a ON a.actor_id=u.id GROUP BY u.id ORDER BY materials DESC")],
        }

    def audit(self, actor):
        self._require(actor, "audit")
        return [dict(r) for r in self.conn.execute("SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200")]

    def seed(self, password):
        """Initialize a demonstrator. Password is supplied by setup, never hard coded."""
        if self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return False
        admin = self.create_user("admin", password, "admin")
        self.create_user("editor", password, "editor", admin)
        author = self.create_user("author", password, "author", admin)
        examples = [
            ("news", "Открыта мастерская интернет приложений", "internet-workshop", "Практикум объединяет проектирование, разработку и проверку учебных веб-систем.", {"lead": "От идеи до работающего приложения"}, "Новости кафедры", ["разработка", "практика"]),
            ("news", "Неделя открытых проектов", "open-projects", "Студенты представят прототипы и обсудят результаты независимой проверки.", {"lead": "Приглашаем на демонстрации"}, "Новости кафедры", ["проекты"]),
            ("course", "Проектирование интернет приложений", "web-design", "Контентные модели, архитектура, интерфейсы и проверка качества.", {"teacher": "Кафедра информационных систем", "hours": 72}, "Обучение", ["веб", "архитектура"]),
            ("course", "Практикум по Python", "python-course", "Разработка прикладных сервисов и автоматизированных проверок.", {"teacher": "Учебная лаборатория", "hours": 36}, "Обучение", ["python"]),
            ("event", "Демонстрация учебных CMS", "cms-demo", "Каждая команда покажет публикацию материала и изменение контентной схемы.", {"date": "2026-12-10", "location": "Учебная лаборатория"}, "События", ["cms", "проекты"]),
            ("event", "Семинар по тестированию", "testing-seminar", "Разберём сценарии проверки прав доступа, публикации и восстановления ревизий.", {"date": "2026-12-03", "location": "Аудитория 41"}, "События", ["тестирование"]),
            ("resource", "Документация Python", "python-docs", "Официальный справочник стандартной библиотеки.", {"url": "https://docs.python.org/3/", "format": "Справочник"}, "Материалы", ["python", "документация"]),
            ("resource", "Руководство SQLite", "sqlite-docs", "Документация по запросам, транзакциям и ограничениям SQLite.", {"url": "https://www.sqlite.org/docs.html", "format": "Документация"}, "Материалы", ["базы данных"]),
        ]
        for type_name, title, slug, body, fields, category, tags in examples:
            item = self.create({"type": type_name, "title": title, "slug": slug, "body": body,
                                "description": body[:160], "fields": fields, "category": category, "tags": tags}, author)
            self.transition(item["id"], "review", author)
            self.transition(item["id"], "published", admin)
        return True
