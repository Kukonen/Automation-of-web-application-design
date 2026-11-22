"""Small WSGI presentation layer and an escaping template renderer."""
from __future__ import annotations

import html
import io
import json
import mimetypes
import re
import secrets
import time
from email import policy
from email.parser import BytesParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode


class SafeHTML(str):
    """HTML produced by the renderer, never by a content field."""


class Templates:
    def __init__(self, root):
        self.root = Path(root)

    def render(self, name, values=None):
        values = values or {}
        if not re.fullmatch(r"[a-z_]+\.html", name):
            raise ValueError("Недопустимое имя шаблона")
        source = (self.root / name).read_text(encoding="utf-8")
        parent = re.search(r'{% extends "([a-z_]+\.html)" %}', source)
        if parent:
            blocks = dict(re.findall(r"{% block (\w+) %}(.*?){% endblock %}", source, re.S))
            source = (self.root / parent.group(1)).read_text(encoding="utf-8")
            source = re.sub(r"{% block (\w+) %}(.*?){% endblock %}", lambda m: blocks.get(m[1], m[2]), source, flags=re.S)
        source = re.sub(r'{% include "([a-z_]+\.html)" %}', lambda m: str(self.render(m[1], values)), source)
        def replace(match):
            value = values.get(match[1], "")
            return str(value) if isinstance(value, SafeHTML) else html.escape(str(value), quote=True)
        return SafeHTML(re.sub(r"{{\s*(\w+)\s*}}", replace, source))


class Request:
    def __init__(self, environ):
        self.method = environ.get("REQUEST_METHOD", "GET")
        self.path = environ.get("PATH_INFO", "/")
        self.query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        self.cookies = SimpleCookie()
        try:
            self.cookies.load(environ.get("HTTP_COOKIE", ""))
        except Exception:
            self.cookies = SimpleCookie()
        self.form = {}
        self.files = {}
        if self.method == "POST":
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if length < 0 or length > 10 * 1024 * 1024:
                raise ValueError("Размер запроса превышает 10 МБ")
            body = environ.get("wsgi.input", io.BytesIO()).read(length)
            content_type = environ.get("CONTENT_TYPE", "")
            if content_type.startswith("multipart/form-data"):
                message = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
                if not message.is_multipart():
                    raise ValueError("Некорректная форма загрузки")
                for part in message.iter_parts():
                    name = part.get_param("name", header="content-disposition")
                    filename = part.get_filename()
                    if filename is not None:
                        self.files[name] = (filename, part.get_payload(decode=True))
                    elif name:
                        self.form.setdefault(name, []).append(part.get_payload(decode=True).decode("utf-8"))
            else:
                self.form = parse_qs(body.decode("utf-8"), keep_blank_values=True)

    def get(self, name, default=""):
        return self.query.get(name, [default])[0]

    def post(self, name, default=""):
        return self.form.get(name, [default])[0]

    def cookie(self, name):
        value = self.cookies.get(name)
        return value.value if value else ""


class WebApp:
    def __init__(self, cms, root=None, base_url="http://localhost:8080"):
        self.cms = cms
        self.root = Path(root or Path(__file__).parent)
        self.templates = Templates(self.root / "templates")
        self.csrf_nonces = {}
        self.base_url = base_url.rstrip("/")

    def __call__(self, environ, start_response):
        self_extra = []
        try:
            req = Request(environ)
            req.session = req.cookie("cms_session")
            req.user = self.cms.session_user(req.session) if req.session else None
            req.theme = req.get("theme", req.cookie("cms_theme") or "light")
            if req.theme not in {"light", "contrast"}:
                req.theme = "light"
            req.csrf = req.cookie("cms_csrf")
            if req.csrf not in self.csrf_nonces or self.csrf_nonces.get(req.csrf, 0) < time.time():
                req.csrf = secrets.token_urlsafe(32)
                self.csrf_nonces[req.csrf] = time.time() + 7200
                self_extra.append(("Set-Cookie", f"cms_csrf={req.csrf}; Path=/; HttpOnly; SameSite=Strict"))
            if len(self.csrf_nonces) > 2000:
                self.csrf_nonces = {key: expiry for key, expiry in self.csrf_nonces.items() if expiry > time.time()}
            if req.get("theme"):
                self_extra.append(("Set-Cookie", f"cms_theme={req.theme}; Path=/; SameSite=Lax"))
            if req.method not in {"GET", "HEAD", "POST"}:
                result = self.error(req, 405, "Метод не поддерживается")
            elif req.method == "POST" and not secrets.compare_digest(req.post("csrf"), req.csrf):
                result = self.error(req, 403, "Не удалось проверить форму. Обновите страницу.")
            else:
                result = self.route(req)
        except PermissionError as exc:
            result = self.error(locals().get("req"), 403, str(exc) or "Доступ запрещён")
        except LookupError as exc:
            result = self.error(locals().get("req"), 404, str(exc) or "Страница не найдена")
        except (ValueError, UnicodeError) as exc:
            result = self.error(locals().get("req"), 400, str(exc))
        except Exception:
            import traceback
            traceback.print_exc()
            result = self.error(locals().get("req"), 500, "Внутренняя ошибка сервера")
        status, headers, body = result
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers += self_extra + [("Content-Length", str(len(body))), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "same-origin"), ("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")]
        start_response(f"{status} { {200:'OK',302:'Found',400:'Bad Request',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',500:'Internal Server Error'}.get(status,'OK')}", headers)
        return [b"" if environ.get("REQUEST_METHOD") == "HEAD" else body]

    def redirect(self, url, cookies=None):
        return 302, [("Location", url)] + (cookies or []), ""

    def render(self, name, values=None):
        return self.templates.render(name, values)

    def page(self, req, title, content, description="Учебный портал кафедры — новости, курсы, события и материалы"):
        menu = SafeHTML("".join(self.render("menu_item.html", {"url": "/?" + urlencode({"type": key}), "label": schema.get("label", key)}) for key, schema in self.cms.schemas.items()))
        user = getattr(req, "user", None)
        account = self.render("account.html", {"username": user["username"], "csrf": req.csrf}) if user else self.render("login_link.html")
        body = self.render("page.html", {"title": title, "description": description, "theme": getattr(req,"theme","light"), "menu": menu, "account": account, "content": content})
        return 200, [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")], body

    def error(self, req, status, text):
        if req is None:
            return status, [("Content-Type", "text/plain; charset=utf-8")], text
        content = self.render("error.html", {"code": status, "message": text})
        _, headers, body = self.page(req, "Ошибка", content)
        return status, headers, body

    def require_user(self, req):
        if not req.user:
            raise PermissionError("Для этого действия необходимо войти")

    def card(self, item):
        return self.render("card.html", {"title": item["title"], "url": "/material/" + quote(item["slug"]), "type": self.cms.schemas[item["type"]].get("label", item["type"]), "description": item.get("description") or item.get("body", "")[:180], "category": item.get("category", ""), "date": (item.get("published_at") or item.get("created_at", ""))[:10]})

    def route(self, req):
        if req.path.startswith("/static/"):
            name = req.path.removeprefix("/static/")
            if name != "style.css":
                raise LookupError("Файл не найден")
            return 200, [("Content-Type", "text/css; charset=utf-8")], (self.root / "static" / name).read_bytes()
        if req.path.startswith("/media/"):
            relative = req.path.removeprefix("/media/")
            path = (self.cms.root / "data" / "media" / relative).resolve()
            base = (self.cms.root / "data" / "media").resolve()
            if not path.is_relative_to(base) or not path.is_file() or path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
                raise LookupError("Изображение не найдено")
            return 200, [("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")], path.read_bytes()
        if req.path == "/login":
            if req.method == "POST":
                user = self.cms.authenticate(req.post("username"), req.post("password"))
                if not user:
                    return self.page(req, "Вход", self.render("login.html", {"csrf": req.csrf, "error": "Неверное имя пользователя или пароль"}))
                token = self.cms.start_session(user)
                return self.redirect("/admin", [("Set-Cookie", f"cms_session={token}; Path=/; HttpOnly; SameSite=Strict")])
            return self.page(req, "Вход", self.render("login.html", {"csrf": req.csrf}))
        if req.path == "/logout":
            if req.method != "POST":
                return self.error(req, 405, "Выход выполняется через форму")
            self.cms.end_session(req.session)
            return self.redirect("/", [("Set-Cookie", "cms_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")])
        if req.path == "/api/materials":
            page = int(req.get("page", "1"))
            page_size = int(req.get("page_size", "10"))
            if page < 1 or not 1 <= page_size <= 100:
                raise ValueError("page >= 1, page_size от 1 до 100")
            result = self.cms.list(public=True, type_name=req.get("type") or None, category=req.get("category") or None, tag=req.get("tag") or None, q=req.get("q") or None, page=page, page_size=page_size)
            return 200, [("Content-Type", "application/json; charset=utf-8")], json.dumps(result, ensure_ascii=False)
        if req.path == "/robots.txt":
            return 200, [("Content-Type", "text/plain; charset=utf-8")], "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /login\nSitemap: " + self.base_url + "/sitemap.xml\n"
        if req.path == "/sitemap.xml":
            result = self.cms.list(public=True, page_size=100)
            items = list(result["items"])
            for page in range(2, result["pages"] + 1):
                items.extend(self.cms.list(public=True, page_size=100, page=page)["items"])
            links = ["/"] + ["/material/" + quote(x["slug"]) for x in items]
            return 200, [("Content-Type", "application/xml; charset=utf-8")], '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join("<url><loc>" + html.escape(self.base_url + link) + "</loc></url>" for link in links) + "</urlset>"
        if req.path == "/":
            result = self.cms.list(public=True, type_name=req.get("type") or None, category=req.get("category") or None, tag=req.get("tag") or None, q=req.get("q") or None, page=max(1,int(req.get("page", "1"))), page_size=6)
            cards = SafeHTML("".join(self.card(item) for item in result["items"])) if result["items"] else self.render("empty.html")
            pagination = self.pagination(req, result)
            title = self.cms.schemas.get(req.get("type"), {}).get("label", "Знания становятся практикой")
            return self.page(req, title, self.render("home.html", {"heading": title, "cards": cards, "query": req.get("q"), "count": result["total"], "pagination": pagination}))
        if req.path.startswith("/material/"):
            slug = req.path.removeprefix("/material/")
            material = self.cms.get(slug, public=True)
            if not material:
                raise LookupError("Материал не найден")
            if req.method == "GET":
                self.cms.record_view(material["id"])
            fields = SafeHTML("".join(self.render("field_value.html", {"label": self.cms.schemas[material["type"]]["fields"].get(key,{}).get("label",key), "value": value}) for key,value in material.get("fields",{}).items()))
            return self.page(req, material["title"], self.render("material.html", {"title": material["title"], "body": material.get("body", ""), "category": material.get("category", ""), "tags": ", ".join(material.get("tags", [])), "author": material.get("author_name", ""), "date": (material.get("published_at") or "")[:10], "fields": fields}), material.get("description", ""))
        if req.path.startswith("/admin"):
            self.require_user(req)
            return self.admin(req)
        raise LookupError("Страница не найдена")

    def pagination(self, req, result):
        links = []
        for page in range(1, result.get("pages", 1) + 1):
            params = {key: value[0] for key,value in req.query.items() if key != "page"}
            params["page"] = page
            links.append(self.render("page_link.html", {"url": "?" + urlencode(params), "label": page, "class": "current" if page == result["page"] else ""}))
        return SafeHTML("".join(links))

    def admin(self, req):
        if req.path == "/admin/stats":
            stats = self.cms.stats(req.user)
            parts = [self.render("stat.html", {"value": stats.get("total_views",0), "label": "Просмотры материалов"})]
            for key,label in [("publications","Публикации по периодам"),("authors","Активность авторов"),("views","Просмотры материалов")]:
                records = stats.get(key, [])
                if key == "authors":
                    rows = SafeHTML("".join(self.render("metric_row.html", {"name": row["username"], "count": row["materials"], "extra": str(row["actions"]) + " действий"}) for row in records))
                    first_label, count_label = "Автор", "Материалов"
                else:
                    rows = SafeHTML("".join(self.render("metric_row.html", {"name": row.get("day", row.get("title", "")), "count": row["count"], "extra": ""}) for row in records))
                    first_label, count_label = ("Дата", "Публикаций") if key == "publications" else ("Материал", "Просмотров")
                parts.append(self.render("data_section.html", {"heading": label, "rows": rows, "first_label": first_label, "count_label": count_label}))
            return self.page(req, "Аналитика", self.render("admin_section.html", {"heading": "Аналитика портала", "content": SafeHTML("".join(parts))}))
        if req.path == "/admin/audit":
            records = self.cms.audit(req.user)
            labels = {"user.create":"Создание пользователя","session.login":"Вход в систему","material.create":"Создание материала","material.update":"Редактирование материала","material.transition":"Изменение статуса","material.restore":"Восстановление версии","material.delete":"Удаление материала","media.upload":"Загрузка изображения"}
            rows = SafeHTML("".join(self.render("audit_row.html", {"time": row.get("created_at", ""), "user": row.get("username", row.get("actor_id", "")), "action": labels.get(row.get("operation", ""), row.get("operation", "")), "target": row.get("material_id") or "—"}) for row in records))
            return self.page(req, "Журнал действий", self.render("audit.html", {"rows": rows}))
        if req.path == "/admin/media":
            message = ""
            if req.method == "POST":
                upload = req.files.get("image")
                if not upload:
                    raise ValueError("Выберите изображение")
                result = self.cms.save_media(upload[0], upload[1], req.user)
                message = "Изображение загружено. Созданы миниатюра 320 px и превью 960 px."
            images = SafeHTML("".join(self.render("media_item.html", {"url": "/media/" + item["filename"], "thumb": "/media/" + item["thumb"], "name": item["original_name"], "width": item["width"], "height": item["height"]}) for item in self.cms.list_media(req.user)))
            return self.page(req, "Медиа", self.render("media.html", {"csrf": req.csrf, "message": message, "images": images}))
        if req.path == "/admin/bulk":
            if req.method != "POST":
                return self.error(req, 405, "Ожидается форма")
            ids = [int(x) for x in req.form.get("ids", [])]
            self.cms.bulk(ids, req.post("operation"), req.user)
            return self.redirect("/admin")
        if req.path == "/admin/new":
            type_name = req.get("type", next(iter(self.cms.schemas)))
            if type_name not in self.cms.schemas:
                raise ValueError("Неизвестный тип материала")
            if not self.cms.can(req.user,"create", type_name=type_name):
                raise PermissionError("Создание этого типа запрещено")
            if req.method == "POST":
                item = self.cms.create(self.form_data(req, type_name), req.user)
                return self.redirect(f"/admin/edit/{item['id']}")
            return self.edit_form(req, {"type": type_name, "status": "draft"})
        match = re.fullmatch(r"/admin/(edit|transition|restore|delete)/(\d+)", req.path)
        if match:
            action, ident = match[1], int(match[2])
            material = self.cms.get(ident, actor=req.user)
            if not material:
                raise LookupError("Материал не найден")
            if action == "edit":
                if not self.cms.can(req.user,"update",material):
                    raise PermissionError("Редактирование этого материала запрещено")
                if req.method == "POST":
                    self.cms.update(ident, self.form_data(req, material["type"]), req.user)
                    return self.redirect(f"/admin/edit/{ident}")
                return self.edit_form(req, material)
            if req.method != "POST":
                return self.error(req, 405, "Ожидается форма")
            if action == "transition":
                self.cms.transition(ident, req.post("status"), req.user)
            elif action == "restore":
                self.cms.restore(ident, int(req.post("revision")), req.user)
            else:
                self.cms.delete(ident, req.user)
                return self.redirect("/admin")
            return self.redirect(f"/admin/edit/{ident}" if self.cms.can(req.user, "update", self.cms.get(ident, actor=req.user)) else "/admin")
        if req.path == "/admin":
            result = self.cms.list(public=False, actor=req.user, q=req.get("q") or None, type_name=req.get("type") or None, status=req.get("status") or None, page=max(1,int(req.get("page","1"))), page_size=15)
            rows = SafeHTML("".join(self.render("admin_row.html", {"id": row["id"], "title": row["title"], "type": self.cms.schemas[row["type"]].get("label",row["type"]), "status": self.status_label(row["status"]), "status_class": row["status"], "author": row.get("author_name", ""), "date": row.get("updated_at", "")[:10]}) for row in result["items"]))
            new_links = SafeHTML("".join(self.render("new_link.html", {"url": "/admin/new?" + urlencode({"type":key}), "label": schema.get("label",key)}) for key,schema in self.cms.schemas.items() if self.cms.can(req.user,"create",type_name=key)))
            type_options = SafeHTML("".join(self.render("option.html", {"value":key,"label":schema.get("label",key),"selected": SafeHTML("selected") if req.get("type")==key else ""}) for key,schema in self.cms.schemas.items()))
            return self.page(req, "Управление материалами", self.render("admin.html", {"csrf":req.csrf, "rows":rows, "new_links":new_links, "query":req.get("q"), "type_options":type_options, "count":result["total"], "pagination":self.pagination(req,result), "role":req.user["role"]}))
        raise LookupError("Раздел не найден")

    @staticmethod
    def status_label(status):
        return {"draft":"Черновик","review":"На модерации","published":"Опубликован","archived":"В архиве"}.get(status,status)

    def form_data(self, req, type_name):
        fields = {}
        for key,schema in self.cms.schemas[type_name]["fields"].items():
            value = req.post("field_" + key)
            if schema.get("type") in {"integer", "number"} and value:
                value = int(value) if schema.get("type") == "integer" else float(value)
            if value != "":
                fields[key] = value
        return {"type":type_name,"title":req.post("title"),"slug":req.post("slug"),"body":req.post("body"),"description":req.post("description"),"category":req.post("category"),"tags":[x.strip() for x in req.post("tags").split(",") if x.strip()],"fields":fields}

    def edit_form(self, req, item):
        type_name = item["type"]
        controls = []
        for key,schema in self.cms.schemas[type_name]["fields"].items():
            kind = {"integer":"number","number":"number","url":"url","date":"date"}.get(schema.get("type"),"text")
            controls.append(self.render("field_input.html", {"name":"field_"+key,"label":schema.get("label",key),"value":item.get("fields",{}).get(key,""),"input_type":kind,"required":SafeHTML("required") if schema.get("required") else ""}))
        actions, revisions = [], []
        if item.get("id"):
            for state in ["draft","review","published","archived"]:
                operation = {"draft":"draft","review":"review","published":"publish","archived":"archive"}[state]
                if state in self.cms.TRANSITIONS[item["status"]] and self.cms.can(req.user, operation, item):
                    actions.append(self.render("transition.html", {"id":item["id"],"csrf":req.csrf,"status":state,"label":self.status_label(state)}))
            for revision in self.cms.revisions(item["id"],req.user):
                revisions.append(self.render("revision.html", {"id":item["id"],"csrf":req.csrf,"revision":revision["id"],"number":revision["number"],"date":revision.get("created_at","")}))
        delete_form = self.render("delete.html", {"id": item["id"], "csrf": req.csrf}) if item.get("id") else SafeHTML("")
        return self.page(req, "Редактирование материала", self.render("edit.html", {"id":item.get("id",""),"csrf":req.csrf,"type_label":self.cms.schemas[type_name].get("label",type_name),"title":item.get("title",""),"slug":item.get("slug",""),"body":item.get("body",""),"description":item.get("description",""),"category":item.get("category",""),"tags":", ".join(item.get("tags",[])),"fields":SafeHTML("".join(controls)),"state":self.status_label(item["status"]),"transitions":SafeHTML("".join(actions)),"revisions":SafeHTML("".join(revisions)),"delete_form":delete_form}))
