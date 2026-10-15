ALTER TABLE deliveries ADD COLUMN receipt_json TEXT;
ALTER TABLE deliveries ADD COLUMN mandate_id TEXT;
ALTER TABLE deliveries ADD COLUMN nonce_digest TEXT;
ALTER TABLE deliveries ADD COLUMN policy_digest TEXT;
ALTER TABLE deliveries ADD COLUMN callback_status TEXT
  CHECK (callback_status IN ('pending', 'approved', 'failed'));

UPDATE deliveries
SET callback_status = CASE WHEN status = 'completed' THEN 'approved' ELSE 'failed' END
WHERE callback_status IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS deliveries_completed_nonce_idx
  ON deliveries(nonce_digest)
  WHERE status = 'completed' AND nonce_digest IS NOT NULL;
