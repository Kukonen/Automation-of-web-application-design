CREATE INDEX idx_materials_public ON materials(status,published_at DESC);
CREATE INDEX idx_materials_author ON materials(author_id);
CREATE INDEX idx_views_period ON views(viewed_at,material_id);
CREATE INDEX idx_terms_name ON terms(kind,name);
