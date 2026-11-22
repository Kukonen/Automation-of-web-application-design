"""Core invariants exercised against real temporary SQLite databases."""

from io import BytesIO
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from PIL import Image

from core import CMS


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cms = CMS(self.root)
        self.admin = self.cms.create_user("admin", "Demonstrator-123", "admin")
        self.editor = self.cms.create_user("editor", "Demonstrator-123", "editor", self.admin)
        self.author = self.cms.create_user("author", "Demonstrator-123", "author", self.admin)

    def tearDown(self):
        self.cms.close()
        self.temp.cleanup()

    def data(self, slug="sample", **changes):
        data = {"type": "news", "title": "Учебная новость", "slug": slug, "body": "Текст",
                "description": "Описание", "category": "Учеба", "tags": ["веб", "python"],
                "fields": {"lead": "Анонс"}}
        data.update(changes)
        return data

    def item(self, **changes):
        return self.cms.create(self.data(**changes), self.author)

    def publish(self, item):
        self.cms.transition(item["id"], "review", self.author)
        return self.cms.transition(item["id"], "published", self.editor)

    def test_01_migrations_are_idempotent(self):
        self.cms.migrate()
        self.cms.migrate()
        names = [r[0] for r in self.cms.conn.execute("SELECT name FROM migrations ORDER BY name")]
        self.assertEqual(names, ["001_core.sql", "002_indexes.sql"])

    def test_02_four_types_loaded(self):
        self.assertEqual(set(self.cms.schemas), {"news", "course", "event", "resource"})

    def test_03_round_trip_preserves_unicode_and_taxonomy(self):
        item = self.item()
        read = self.cms.get(item["id"], actor=self.author)
        for name in self.data():
            self.assertEqual(read[name], self.data()[name])

    def test_04_round_trip_every_content_type(self):
        fields = {"news": {"lead": "Анонс"}, "course": {"teacher": "Иванов", "hours": 72},
                  "event": {"date": "2026-12-01", "location": "Онлайн"},
                  "resource": {"url": "https://example.org/lesson", "format": "PDF"}}
        for kind, values in fields.items():
            with self.subTest(kind=kind):
                item = self.item(slug=kind, type=kind, fields=values)
                self.assertEqual(self.cms.get(kind, actor=self.author)["fields"], values)
                self.assertEqual(item["status"], "draft")

    def test_05_required_field(self):
        with self.assertRaises(ValueError):
            self.item(fields={})

    def test_06_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            self.item(fields={"lead": "a", "unexpected": "b"})

    def test_07_unknown_top_level_field_rejected(self):
        with self.assertRaises(ValueError):
            self.item(author_id=self.admin["id"])

    def test_08_integer_validation(self):
        for value in [True, "72", 0, 1001, 1.5]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.item(type="course", fields={"teacher": "Teacher", "hours": value})

    def test_09_date_validation(self):
        with self.assertRaises(ValueError):
            self.item(type="event", fields={"date": "2026-02-30", "location": "Here"})

    def test_10_unsafe_url_rejected(self):
        for value in ["javascript:alert(1)", "//example.org", "file:///etc/passwd", "https://"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.item(type="resource", fields={"url": value, "format": "Link"})

    def test_11_duplicate_slug_does_not_create_partial_data(self):
        item = self.item()
        before = self.cms.conn.execute("SELECT count(*) FROM revisions").fetchone()[0]
        with self.assertRaises(ValueError):
            self.item(title="Другой", category="Новая")
        self.assertEqual(self.cms.conn.execute("SELECT count(*) FROM materials").fetchone()[0], 1)
        self.assertEqual(self.cms.conn.execute("SELECT count(*) FROM revisions").fetchone()[0], before)
        self.assertEqual(self.cms.get(item["id"], actor=self.author)["category"], "Учеба")

    def test_12_slug_validation(self):
        for slug in ["../etc", "MixedCase", "привет", "two--dashes", "a/b", ""]:
            with self.subTest(slug=slug), self.assertRaises(ValueError):
                self.item(slug=slug)

    def test_13_invalid_lifecycle_cannot_skip_moderation(self):
        item = self.item()
        with self.assertRaises(ValueError):
            self.cms.transition(item["id"], "published", self.admin)
        self.assertEqual(self.cms.get(item["id"], actor=self.author)["status"], "draft")

    def test_14_author_cannot_publish(self):
        item = self.item()
        self.cms.transition(item["id"], "review", self.author)
        with self.assertRaises(PermissionError):
            self.cms.transition(item["id"], "published", self.author)

    def test_15_lifecycle_through_archive(self):
        item = self.publish(self.item())
        self.assertIsNotNone(item["published_at"])
        self.cms.transition(item["id"], "archived", self.editor)
        self.assertIsNone(self.cms.get(item["slug"], public=True))
        self.cms.transition(item["id"], "draft", self.editor)
        self.assertEqual(self.cms.get(item["id"], actor=self.author)["revision"], 5)

    def test_16_update_creates_immutable_revision(self):
        item = self.item()
        self.cms.update(item["id"], {"title": "Новая версия"}, self.author)
        revisions = self.cms.revisions(item["id"], self.author)
        self.assertEqual([r["number"] for r in revisions], [2, 1])
        self.assertEqual(revisions[-1]["snapshot"]["title"], "Учебная новость")

    def test_17_restore_creates_new_revision_and_draft(self):
        item = self.item()
        revision = self.cms.revisions(item["id"], self.author)[0]
        self.cms.update(item["id"], {"title": "Вторая", "tags": ["тест"]}, self.author)
        self.publish(item)
        restored = self.cms.restore(item["id"], revision["id"], self.admin)
        self.assertEqual(restored["title"], item["title"])
        self.assertEqual(restored["tags"], item["tags"])
        self.assertEqual(restored["status"], "draft")
        self.assertEqual(restored["author_id"], self.author["id"])
        self.assertEqual(restored["revision"], 5)

    def test_18_cannot_restore_other_material_revision(self):
        first = self.item()
        second = self.item(slug="second")
        foreign = self.cms.revisions(second["id"], self.author)[0]
        with self.assertRaises(LookupError):
            self.cms.restore(first["id"], foreign["id"], self.author)

    def test_19_foreign_keys_reject_orphan_taxonomy(self):
        with self.assertRaises(sqlite3.IntegrityError), self.cms.conn:
            self.cms.conn.execute("INSERT INTO material_terms VALUES(999,999)")

    def test_20_taxonomy_filters_and_tag_deduplication(self):
        item = self.item(tags=["python", "python", "веб"])
        self.publish(item)
        self.assertEqual(self.cms.list(tag="python")["total"], 1)
        self.assertEqual(self.cms.list(category="Учеба")["total"], 1)
        self.assertEqual(self.cms.list(tag="other")["total"], 0)
        self.assertEqual(self.cms.get(item["id"], actor=self.author)["tags"], ["python", "веб"])

    def test_21_public_listing_never_leaks_draft(self):
        self.item()
        self.assertEqual(self.cms.list()["items"], [])
        self.assertEqual(self.cms.list(public=False, actor=self.author)["total"], 1)

    def test_22_search_uses_parameters_and_literal_wildcards(self):
        self.publish(self.item(title="100% практики"))
        self.assertEqual(self.cms.list(q="%")["total"], 1)
        self.assertEqual(self.cms.list(q="' OR 1=1 --")["total"], 0)
        self.assertEqual(self.cms.list(q="_")["total"], 0)

    def test_23_pagination_and_upper_bound(self):
        for index in range(3):
            self.publish(self.item(slug=f"item-{index}"))
        result = self.cms.list(page=2, page_size=2)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["pages"], 2)
        for page, size in [(0, 10), (1, 101), (-1, 3), (True, 10)]:
            with self.subTest(page=page, size=size), self.assertRaises(ValueError):
                self.cms.list(page=page, page_size=size)

    def test_24_authentication_and_hashed_password(self):
        self.assertEqual(self.cms.authenticate("author", "Demonstrator-123"), self.author)
        self.assertIsNone(self.cms.authenticate("author", "wrong"))
        self.assertIsNone(self.cms.authenticate("missing", "Demonstrator-123"))
        stored = self.cms.conn.execute("SELECT password_hash FROM users WHERE username='author'").fetchone()[0]
        self.assertNotIn("Demonstrator", stored)
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))

    def test_25_session_expiration_and_logout(self):
        token = self.cms.start_session(self.author)
        self.assertEqual(self.cms.session_user(token), self.author)
        self.assertGreater(len(self.cms.csrf_token(token)), 30)
        self.assertIsNone(self.cms.session_user("not-valid"))
        with self.cms.conn:
            self.cms.conn.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'")
        self.assertIsNone(self.cms.session_user(token))
        token = self.cms.start_session(self.author)
        self.cms.end_session(token)
        self.assertIsNone(self.cms.session_user(token))

    def test_26_roles_matrix_parameterized(self):
        own = self.item()
        cases = [
            (self.author, "update", own, True), (self.author, "review", own, True),
            (self.author, "publish", own, False), (self.author, "archive", own, False),
            (self.author, "stats", own, False), (self.author, "users", own, False),
            (self.editor, "update", own, True), (self.editor, "publish", own, True),
            (self.editor, "audit", own, False), (self.editor, "users", own, False),
            (self.admin, "audit", own, True), (self.admin, "users", own, True),
            (None, "create", own, False), (None, "read", own, False),
        ]
        for actor, operation, item, expected in cases:
            with self.subTest(role=actor and actor["role"], operation=operation):
                self.assertEqual(self.cms.can(actor, operation, item), expected)

    def test_27_forged_actor_role_does_not_escalate(self):
        forged = self.author | {"role": "admin"}
        self.assertFalse(self.cms.can(forged, "users"))
        with self.assertRaises(PermissionError):
            self.cms.create_user("hacker", "Long-password", "admin", forged)

    def test_28_author_cannot_modify_or_list_others(self):
        other = self.cms.create(self.data(), self.editor)
        self.assertEqual(self.cms.list(public=False, actor=self.author)["total"], 0)
        for action in [lambda: self.cms.update(other["id"], {"title": "x"}, self.author),
                       lambda: self.cms.delete(other["id"], self.author),
                       lambda: self.cms.revisions(other["id"], self.author)]:
            with self.assertRaises(PermissionError):
                action()

    def test_29_dynamic_type_registered_without_core_edit(self):
        shutil.copytree(Path(__file__).parents[1] / "schemas", self.root / "schemas")
        schema = {"label": "Проекты", "fields": {"repository": {"type": "url", "required": True}}}
        (self.root / "schemas" / "project.json").write_text(json.dumps(schema), encoding="utf-8")
        self.cms.migrate()
        item = self.item(type="project", fields={"repository": "https://example.org/project"})
        self.assertEqual(self.cms.get(item["id"], actor=self.author)["fields"]["repository"], "https://example.org/project")
        history = self.cms.conn.execute("SELECT version FROM schema_history WHERE type_name='project'").fetchall()
        self.assertEqual([r[0] for r in history], [1])

    def test_30_incompatible_schema_change_rejected_atomically(self):
        self.item()
        shutil.copytree(Path(__file__).parents[1] / "schemas", self.root / "schemas")
        path = self.root / "schemas" / "news.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema["fields"]["extra"] = {"type": "text", "required": True}
        path.write_text(json.dumps(schema), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.cms.migrate()
        self.assertEqual(self.cms.conn.execute("SELECT version FROM content_types WHERE name='news'").fetchone()[0], 1)

    def test_31_bulk_is_all_or_nothing_on_forbidden_row(self):
        first = self.item()
        second = self.cms.create(self.data(slug="second"), self.editor)
        with self.assertRaises(PermissionError):
            self.cms.bulk([first["id"], second["id"]], "delete", self.author)
        self.assertIsNotNone(self.cms.get(first["id"], actor=self.admin))
        self.assertIsNotNone(self.cms.get(second["id"], actor=self.admin))

    def test_32_bulk_transition_and_audit(self):
        items = [self.item(slug=f"bulk-{i}") for i in range(2)]
        self.assertEqual(self.cms.bulk([x["id"] for x in items], "review", self.author), 2)
        self.assertTrue(all(self.cms.get(x["id"], actor=self.author)["status"] == "review" for x in items))
        self.assertTrue(any(a["detail"] == "bulk:review" for a in self.cms.audit(self.admin)))

    def test_33_media_content_validation(self):
        for filename, data in [("image.png", b"<script>alert(1)</script>"), ("bad.svg", b"<svg></svg>"), ("empty.jpg", b"")]:
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.cms.save_media(filename, data, self.author)

    def test_34_media_derivatives_and_safe_filename(self):
        buffer = BytesIO()
        Image.new("RGB", (1200, 700), "blue").save(buffer, "PNG")
        media = self.cms.save_media("../../outside.png", buffer.getvalue(), self.author)
        self.assertNotIn("..", media["filename"])
        self.assertEqual(media["mime"], "image/jpeg")
        for key, limit in [("thumb", 320), ("preview", 960)]:
            with Image.open(self.root / "data" / "media" / media[key]) as image:
                self.assertLessEqual(max(image.size), limit)
        self.assertEqual(len(self.cms.list_media(self.author)), 1)

    def test_35_metrics_and_restricted_statistics(self):
        item = self.publish(self.item())
        self.cms.record_view(item["id"])
        self.cms.record_view(item["id"])
        stats = self.cms.stats(self.admin)
        self.assertEqual(stats["total_views"], 2)
        self.assertEqual(stats["publications"][0]["count"], 1)
        self.assertTrue(any(r["username"] == "author" and r["materials"] == 1 for r in stats["authors"]))
        with self.assertRaises(PermissionError):
            self.cms.stats(self.author)

    def test_36_delete_cascades_revisions_and_links(self):
        item = self.item()
        self.cms.delete(item["id"], self.author)
        self.assertIsNone(self.cms.get(item["id"], actor=self.author))
        self.assertEqual(self.cms.conn.execute("SELECT count(*) FROM revisions").fetchone()[0], 0)
        self.assertEqual(self.cms.conn.execute("SELECT count(*) FROM material_terms").fetchone()[0], 0)

    def test_37_seed_is_explicit_and_idempotent(self):
        empty_root = self.root / "empty"
        fresh = CMS(empty_root)
        try:
            self.assertTrue(fresh.seed("Demonstrator-123"))
            self.assertFalse(fresh.seed("Another-long-password"))
            self.assertEqual(fresh.list()["total"], 8)
            self.assertIsNotNone(fresh.authenticate("admin", "Demonstrator-123"))
        finally:
            fresh.close()

    def test_38_failed_update_preserves_taxonomy_and_revision(self):
        item = self.item()
        self.item(slug="occupied")
        with self.assertRaises(ValueError):
            self.cms.update(item["id"], {"slug": "occupied", "category": "Изменено"}, self.author)
        result = self.cms.get(item["id"], actor=self.author)
        self.assertEqual(result["slug"], "sample")
        self.assertEqual(result["category"], "Учеба")
        self.assertEqual(result["revision"], 1)

    def test_39_anonymous_service_get_and_list_are_denied(self):
        item = self.item()
        for read in [lambda: self.cms.get(item["id"]),
                     lambda: self.cms.get(item["slug"], public=False),
                     lambda: self.cms.list(public=False),
                     lambda: self.cms.list(public=False, actor={"id": 999, "role": "admin"})]:
            with self.assertRaises(PermissionError):
                read()
        self.assertIsNone(self.cms.get(item["id"], public=True))
        self.assertEqual(self.cms.list(public=True)["items"], [])

    def test_40_author_cannot_read_foreign_draft_via_service(self):
        other = self.cms.create(self.data(), self.editor)
        for identifier in [other["id"], other["slug"]]:
            with self.subTest(identifier=identifier), self.assertRaises(PermissionError):
                self.cms.get(identifier, actor=self.author)
        self.assertEqual(self.cms.list(public=False, actor=self.author)["total"], 0)
        self.assertEqual(self.cms.get(other["id"], actor=self.admin)["title"], other["title"])


if __name__ == "__main__":
    unittest.main()
