ALTER TABLE sessions ADD COLUMN repo_root TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN tripwire_seed TEXT NOT NULL DEFAULT '';  -- random; never derived from session_id
ALTER TABLE sessions ADD COLUMN pending_useless_question TEXT;           -- NULL when no question is waiting
ALTER TABLE prompts ADD COLUMN answers_question TEXT;                    -- the question this prompt answered, if any
