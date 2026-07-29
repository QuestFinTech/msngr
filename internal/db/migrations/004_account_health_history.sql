-- 004_account_health_history: Separate "last changed" from "last polled" for account health.
--
-- Before this migration the poller rewrote accounts.updated_at on every poll, including
-- ok -> ok, so updated_at was a last-polled timestamp wearing the name of a last-changed
-- one. health_changed_at answers "since when?"; health_error retains the reason;
-- last_polled_at is the honest home for the per-poll write.
ALTER TABLE accounts ADD COLUMN health_changed_at TEXT;
ALTER TABLE accounts ADD COLUMN health_error TEXT;
ALTER TABLE accounts ADD COLUMN last_polled_at TEXT;
