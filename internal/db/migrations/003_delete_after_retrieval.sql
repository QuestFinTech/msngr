-- 003_delete_after_retrieval: Add option to delete messages from IMAP server after retrieval.
ALTER TABLE accounts ADD COLUMN delete_after_retrieval INTEGER DEFAULT 0;
