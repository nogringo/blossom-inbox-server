-- Draft BUD "blob pinning": each owner row is a pin, and this records when it
-- was created. Rows written before this column existed stay NULL and report the
-- blob's upload time instead.
ALTER TABLE owners ADD COLUMN pinned INTEGER;
