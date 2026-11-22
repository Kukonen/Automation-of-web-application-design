CREATE TABLE users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','editor','author'))
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE content_types (name TEXT PRIMARY KEY, schema_json TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE schema_history (
 id INTEGER PRIMARY KEY, type_name TEXT NOT NULL REFERENCES content_types(name),
 version INTEGER NOT NULL, digest TEXT NOT NULL, applied_at TEXT NOT NULL,
 UNIQUE(type_name,version)
);
CREATE TABLE materials (
 id INTEGER PRIMARY KEY, type TEXT NOT NULL REFERENCES content_types(name),
 title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, body TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '', fields_json TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('draft','review','published','archived')),
 author_id INTEGER NOT NULL REFERENCES users(id), revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, published_at TEXT
);
CREATE TABLE terms (
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('category','tag')),
 name TEXT NOT NULL, UNIQUE(kind,name)
);
CREATE TABLE material_terms (
 material_id INTEGER NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
 term_id INTEGER NOT NULL REFERENCES terms(id) ON DELETE CASCADE,
 PRIMARY KEY(material_id,term_id)
);
CREATE TABLE revisions (
 id INTEGER PRIMARY KEY, material_id INTEGER NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
 number INTEGER NOT NULL, snapshot TEXT NOT NULL, actor_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL, UNIQUE(material_id,number)
);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), operation TEXT NOT NULL,
 material_id INTEGER, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE media (
 id INTEGER PRIMARY KEY, filename TEXT NOT NULL, original_name TEXT NOT NULL,
 mime TEXT NOT NULL, size INTEGER NOT NULL, width INTEGER NOT NULL, height INTEGER NOT NULL,
 thumb TEXT NOT NULL, preview TEXT NOT NULL, uploader_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL
);
CREATE TABLE views (
 id INTEGER PRIMARY KEY, material_id INTEGER NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
 viewed_at TEXT NOT NULL
);
