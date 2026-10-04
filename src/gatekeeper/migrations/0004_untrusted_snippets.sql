ALTER TABLE untrusted_reads ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0;  -- the action that did the read
ALTER TABLE untrusted_reads ADD COLUMN score REAL NOT NULL DEFAULT 0;        -- 0.8 or more means suspicious
ALTER TABLE untrusted_reads ADD COLUMN snippet TEXT NOT NULL DEFAULT '';     -- at most 2,000 characters
CREATE INDEX idx_untrusted_sequence ON untrusted_reads(session_id, sequence);
