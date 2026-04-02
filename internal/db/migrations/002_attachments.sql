-- 002_attachments: Add attachments_json column to outbound_queue for outbound attachment support.
ALTER TABLE outbound_queue ADD COLUMN attachments_json TEXT;
