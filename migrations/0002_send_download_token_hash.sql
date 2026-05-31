-- E2 (issue #18): store a hash of the Send download token, not the
-- plaintext token. Brings download tokens in line with the hash-at-rest
-- pattern used for PAT / SAT / refresh tokens, so a database read can no
-- longer expose live download tokens, and removes the variable-time SQL
-- `=` comparison against a plaintext secret.
--
-- Download tokens are ephemeral (5-minute TTL), so clearing existing rows
-- is safe — any in-flight token would expire within minutes regardless,
-- and re-issuing via `/access` is a single anonymous request.
--
-- Portable across SQLite (>= 3.25) and Postgres: both support
-- `ALTER TABLE ... RENAME COLUMN`.

DELETE FROM send_download_tokens;

ALTER TABLE send_download_tokens RENAME COLUMN token TO token_hash;
