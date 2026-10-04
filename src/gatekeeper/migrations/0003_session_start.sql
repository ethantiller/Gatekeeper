-- The folder the sandbox copies: the repo's top folder, not a subfolder the agent happened to start in.
-- Existing rows get an empty string because they were created before this column existed.
ALTER TABLE sessions ADD COLUMN repo_root TEXT NOT NULL DEFAULT '';

-- Random secret the fake secret values come from. Never derived from session_id, which the agent can read.
-- Existing rows get an empty string; a session without a seed must be treated as unusable by the sandbox.
ALTER TABLE sessions ADD COLUMN tripwire_seed TEXT NOT NULL DEFAULT '';

-- The question useless mode asked and is waiting on an answer for. NULL means no question is pending.
ALTER TABLE sessions ADD COLUMN pending_useless_question TEXT;

-- The useless-mode question this prompt answered. NULL means it was an ordinary prompt.
ALTER TABLE prompts ADD COLUMN answers_question TEXT;
