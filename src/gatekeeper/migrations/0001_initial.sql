CREATE TABLE sessions (
  session_id     TEXT PRIMARY KEY,
  source         TEXT NOT NULL,            -- ActionSource
  cwd            TEXT NOT NULL,
  started_at     TEXT NOT NULL,
  action_counter INTEGER NOT NULL DEFAULT 0,
  metadata_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE prompts (       -- user prompts from /hooks/prompt
  prompt_id   TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  text        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE untrusted_reads (
  read_id            TEXT PRIMARY KEY,
  session_id         TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  action_id          TEXT NOT NULL,
  source             TEXT NOT NULL,
  content_sha256     TEXT NOT NULL,
  scanner_flags_json TEXT NOT NULL DEFAULT '[]',
  created_at         TEXT NOT NULL
);

CREATE TABLE decisions (
  decision_id   TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  action_id     TEXT NOT NULL UNIQUE,
  sequence      INTEGER NOT NULL,
  kind          TEXT NOT NULL,             -- ActionKind
  verdict       TEXT NOT NULL,             -- Verdict
  summary       TEXT,
  decision_json TEXT NOT NULL,             -- full Decision.model_dump_json()
  created_at    TEXT NOT NULL
);

CREATE TABLE checkpoints (   -- git checkpoints for rollback
  checkpoint_id  TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  decision_id    TEXT REFERENCES decisions(decision_id),
  repo_path      TEXT NOT NULL,
  git_ref        TEXT NOT NULL,            -- commit sha / stash ref
  created_at     TEXT NOT NULL,
  rolled_back_at TEXT
);

CREATE INDEX idx_prompts_session     ON prompts(session_id, created_at);
CREATE INDEX idx_untrusted_session   ON untrusted_reads(session_id, created_at);
CREATE INDEX idx_decisions_session   ON decisions(session_id, sequence);
CREATE INDEX idx_checkpoints_session ON checkpoints(session_id, created_at);
