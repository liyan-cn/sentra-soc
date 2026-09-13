ALTER TABLE action_outbox ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'live';

