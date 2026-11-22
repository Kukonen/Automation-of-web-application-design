"""Acceptance scenarios against a real HTTP server and temporary SQLite database."""
import io
import json
import os
from http.cookiejar import CookieJar
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener
from wsgiref.simple_server import WSGIRequestHandler, make_server

from core import CMS
from web import Templates, WebApp
from app import load_env


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *_):
        pass


class EnvironmentTests(unittest.TestCase):
    def test_env_preserves_existing_values_and_reads_only_literal_cms_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"CMS_BASE_URL":"http://existing.example"}, clear=True):
            source=Path(directory)/".env"
            source.write_text('# comment\nCMS_BASE_URL=http://replacement.example\nCMS_DEMO_PASSWORD="Literal$not-expanded!"\nUNRELATED=ignored\ninvalid\n',encoding="utf-8")
            load_env(source)
            self.assertEqual(os.environ["CMS_BASE_URL"],"http://existing.example")
            self.assertEqual(os.environ["CMS_DEMO_PASSWORD"],"Literal$not-expanded!")
            self.assertNotIn("UNRELATED",os.environ)
            load_env(Path(directory)/"missing.env")


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cms = CMS(cls.temp.name)
        cls.cms.seed("Test-Only-2026!")
        cls.root = Path(__file__).resolve().parents[1]
        cls.app = WebApp(cls.cms, cls.root)
        cls.server = make_server("127.0.0.1", 0, cls.app, handler_class=QuietHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.app.base_url = cls.base
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.cms.close()
        cls.temp.cleanup()

    def setUp(self):
        self.jar = CookieJar()
        self.client = build_opener(HTTPCookieProcessor(self.jar))

    def request(self, path, data=None, headers=None, method=None):
        if isinstance(data, dict):
            data = urlencode(data, doseq=True).encode()
        request = Request(self.base + path, data=data, headers=headers or {}, method=method)
        try:
            response = self.client.open(request)
        except HTTPError as error:
            response = error
        return response.status, response.read().decode("utf-8",errors="replace"), response.headers

    def csrf(self):
        self.request("/login")
        return next(cookie.value for cookie in self.jar if cookie.name == "cms_csrf")

    def login(self, username="admin"):
        token = self.csrf()
        status, body, _ = self.request("/login", {"csrf":token,"username":username,"password":"Test-Only-2026!"})
        self.assertEqual(status,200,body)
        return token

    def get_material(self, identifier):
        return self.cms.get(identifier, actor=self.cms.authenticate("admin","Test-Only-2026!"))

    def data(self, slug, title="Тестовый материал"):
        return {"title":title,"slug":slug,"body":"Текст для проверки публикации","description":"Описание материала","category":"Проверки","tags":"http, практика","field_lead":"Краткий анонс"}

    def test_01_public_browse_search_and_api(self):
        status, body, _ = self.request("/")
        self.assertEqual(status,200)
        self.assertIn("Знания становятся практикой",body)
        self.assertIn("Курсы",body)
        status, body, _ = self.request("/api/materials?page_size=2&type=course")
        result=json.loads(body)
        self.assertEqual(status,200)
        self.assertEqual(result["total"],2)
        self.assertTrue(all(item["type"]=="course" for item in result["items"]))
        self.assertEqual(self.request("/api/materials?page_size=101")[0],400)
        self.assertEqual(self.request("/api/materials?page=0")[0],400)
        self.assertIn("Python",self.request("/?"+urlencode({"q":"Python"}))[1])

    def test_02_http_crud_publish_restore_audit(self):
        csrf=self.login()
        data=self.data("http-crud") | {"csrf":csrf}
        status, body, _=self.request("/admin/new?type=news",data)
        self.assertEqual(status,200,body)
        item=self.get_material("http-crud")
        ident=item["id"]
        baseline=self.cms.revisions(ident,self.cms.authenticate("admin","Test-Only-2026!"))[-1]["id"]
        self.assertIn('maxlength="300"',body)
        status, body, _=self.request(f"/admin/edit/{ident}",data | {"title":"Новая редакция"})
        self.assertEqual(status,200,body)
        self.assertEqual(self.get_material(ident)["title"],"Новая редакция")
        self.assertEqual(self.request("/material/http-crud")[0],404)
        self.assertNotIn("http-crud",self.request("/api/materials?page_size=100")[1])
        for state in ["review","published"]:
            self.assertEqual(self.request(f"/admin/transition/{ident}",{"csrf":csrf,"status":state})[0],200)
        status, body, _=self.request("/material/http-crud")
        self.assertEqual(status,200)
        self.assertIn("Новая редакция",body)
        self.assertIn("Новая редакция",self.request("/api/materials?tag=http")[1])
        self.assertIn("Создание материала",self.request("/admin/audit")[1])
        self.assertIn("Редактирование материала",self.request("/admin/audit")[1])
        self.assertEqual(self.request(f"/admin/restore/{ident}",{"csrf":csrf,"revision":baseline})[0],200)
        self.assertEqual(self.get_material(ident)["title"],"Тестовый материал")
        self.assertEqual(self.get_material(ident)["status"],"draft")
        self.assertEqual(self.request("/material/http-crud")[0],404)

    def test_03_role_route_matrix(self):
        matrix=[("admin","/admin/stats",200),("admin","/admin/audit",200),("admin","/admin/media",200),("admin","/admin/new?type=news",200),("editor","/admin/stats",403),("editor","/admin/audit",403),("editor","/admin/media",200),("editor","/admin/new?type=news",200),("author","/admin/stats",403),("author","/admin/audit",403),("author","/admin/media",200),("author","/admin/new?type=news",200)]
        current=None
        for username,path,expected in matrix:
            with self.subTest(role=username,path=path):
                if username!=current:
                    self.jar=CookieJar()
                    self.client=build_opener(HTTPCookieProcessor(self.jar))
                    self.login(username)
                    current=username
                self.assertEqual(self.request(path)[0],expected)

    def test_04_csrf_and_logout(self):
        self.assertEqual(self.request("/admin")[0],403)
        csrf=self.login()
        self.assertEqual(self.request("/admin/new?type=news",self.data("no-csrf"))[0],403)
        self.assertIsNone(self.get_material("no-csrf"))
        self.assertEqual(self.request("/logout")[0],405)
        self.assertEqual(self.request("/logout",{"csrf":csrf})[0],200)
        self.assertEqual(self.request("/admin")[0],403)

    def test_05_xss_and_theme(self):
        csrf=self.login()
        payload='<script>alert("x")</script>'
        status,body,_=self.request("/admin/new?type=news",self.data("xss-http",payload) | {"csrf":csrf,"body":payload})
        self.assertEqual(status,200,body)
        self.assertNotIn(payload,body)
        self.assertIn("&lt;script&gt;",body)
        ident=self.get_material("xss-http")["id"]
        for state in ["review","published"]:
            self.request(f"/admin/transition/{ident}",{"csrf":csrf,"status":state})
        status,body,_=self.request("/material/xss-http?theme=contrast")
        self.assertEqual(status,200)
        self.assertNotIn(payload,body)
        self.assertIn("&lt;script&gt;",body)
        self.assertIn('data-theme="contrast"',body)
        self.assertIn('name="description"',body)

    def test_06_upload_and_binary_file(self):
        from PIL import Image
        csrf=self.login()
        buffer=io.BytesIO()
        Image.new("RGB",(640,400),(80,130,90)).save(buffer,"PNG")
        boundary="----CMSAcceptanceBoundary"
        body=(f'--{boundary}\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n{csrf}\r\n--{boundary}\r\nContent-Disposition: form-data; name="image"; filename="sample.png"\r\nContent-Type: image/png\r\n\r\n'.encode()+buffer.getvalue()+f"\r\n--{boundary}--\r\n".encode())
        status,page,_=self.request("/admin/media",body,{"Content-Type":f"multipart/form-data; boundary={boundary}"})
        self.assertEqual(status,200,page)
        self.assertIn("Изображение загружено",page)
        item=self.cms.list_media(self.cms.authenticate("admin","Test-Only-2026!"))[0]
        request=self.client.open(self.base+"/media/"+item["thumb"])
        self.assertEqual(request.status,200)
        self.assertEqual(request.headers["Content-Type"],"image/jpeg")
        self.assertGreater(len(request.read()),100)
        self.assertEqual(self.request("/media/../../core.py")[0],404)

    def test_07_seo_headers_and_cookie_flags(self):
        status,body,headers=self.request("/login")
        self.assertEqual(status,200)
        self.assertIn("HttpOnly",headers.get("Set-Cookie"))
        self.assertIn("SameSite=Strict",headers.get("Set-Cookie"))
        self.assertEqual(headers["X-Content-Type-Options"],"nosniff")
        status,body,_=self.request("/sitemap.xml")
        self.assertEqual(status,200)
        self.assertIn(self.base+"/material/python-docs",body)
        self.assertNotIn("http-crud",body)
        self.assertIn("Disallow: /admin",self.request("/robots.txt")[1])

    def test_08_http_author_cannot_publish_or_edit_others(self):
        csrf=self.login("author")
        self.assertEqual(self.request("/admin/new?type=news",self.data("author-http")|{"csrf":csrf})[0],200)
        ident=self.get_material("author-http")["id"]
        self.assertEqual(self.request(f"/admin/transition/{ident}",{"csrf":csrf,"status":"review"})[0],200)
        self.assertEqual(self.request(f"/admin/transition/{ident}",{"csrf":csrf,"status":"published"})[0],403)
        self.assertEqual(self.get_material(ident)["status"],"review")
        self.assertEqual(self.request(f"/admin/edit/{ident}")[0],403)

    def test_09_template_escapes_and_limits_names(self):
        templates=Templates(self.root/"templates")
        result=templates.render("field_value.html",{"label":"<b>","value":'"<svg onload=1>'})
        self.assertIn("&lt;svg",result)
        self.assertNotIn("<svg",result)
        with self.assertRaises(ValueError):
            templates.render("../core.py")

    def test_10_http_bulk_and_filter(self):
        csrf=self.login()
        ids=[]
        for slug in ["bulk-http-a","bulk-http-b"]:
            self.assertEqual(self.request("/admin/new?type=news",self.data(slug)|{"csrf":csrf})[0],200)
            ids.append(self.get_material(slug)["id"])
        self.assertEqual(self.request("/admin/bulk",{"csrf":csrf,"ids":ids,"operation":"review"})[0],200)
        self.assertTrue(all(self.get_material(ident)["status"]=="review" for ident in ids))
        self.assertIn("Тестовый материал",self.request("/admin?type=news&status=review")[1])


if __name__=="__main__":
    unittest.main()
