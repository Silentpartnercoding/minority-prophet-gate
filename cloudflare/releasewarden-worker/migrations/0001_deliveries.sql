CREATE TABLE IF NOT EXISTS deliveries (
  delivery_id TEXT PRIMARY KEY,
  body_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'completed', 'failed')),
  decision_json TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS deliveries_created_at_idx
  ON deliveries(created_at);
