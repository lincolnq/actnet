-- OAuth "Sign in with Avalanche" client registration moves onto the Project
-- entity (docs/25). A Project that offers login carries its stable, public
-- `oauth_client_id` and the exact-match `oauth_redirect_uris` allowlist here;
-- the token audience is the Project's existing `url`. `find_client` resolves an
-- incoming login request against this table — the PROJECTS env var no longer
-- configures OAuth clients (env-seeded OAuth clients are gone; docs/25).
--
-- `oauth_client_id` is UNIQUE so a manifest cannot claim another Project's
-- client id to hijack its login resolution; NULL for the common case of a
-- Project that does not offer login (Postgres allows many NULLs under UNIQUE).
ALTER TABLE projects
    ADD COLUMN oauth_client_id     TEXT UNIQUE,
    ADD COLUMN oauth_redirect_uris TEXT[] NOT NULL DEFAULT '{}';

-- The directory's `client_id` column was only ever a display-resolution copy, so
-- `GET /v1/projects` could map an incoming client_id to a name/official for the
-- consent screen. That copy is now redundant: the authoritative value lives on
-- `projects` and is surfaced by joining directory_entries -> projects. Drop the
-- duplicate so the two copies can no longer drift.
ALTER TABLE directory_entries DROP COLUMN client_id;
