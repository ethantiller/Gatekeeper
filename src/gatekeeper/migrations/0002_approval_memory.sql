CREATE TABLE remembered_approvals (   -- actions the user approved with "remember"
  action_id   TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL
);
