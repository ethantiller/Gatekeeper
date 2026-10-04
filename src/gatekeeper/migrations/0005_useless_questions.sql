CREATE TABLE useless_questions (
  question_id      TEXT PRIMARY KEY,
  session_id       TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  command_sha256   TEXT NOT NULL,             -- sha256 of the whitespace-collapsed command
  question         TEXT NOT NULL,
  asked_at         TEXT NOT NULL,
  answer_prompt_id TEXT REFERENCES prompts(prompt_id),  -- NULL until the user's next prompt
  used_at          TEXT                       -- set when a retry used the answer
);
CREATE INDEX idx_useless_questions_lookup ON useless_questions(session_id, command_sha256);
