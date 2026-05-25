CREATE TABLE IF NOT EXISTS organisations (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    ollama_endpoint_enc TEXT,
    trust_mode    TEXT NOT NULL DEFAULT 'hybrid',
    created_at    INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orgs_email ON organisations(email);
