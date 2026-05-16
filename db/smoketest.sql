-- Foundation smoke-test table. Throwaway. Superseded by PRD 0003 migration framework.
CREATE TABLE IF NOT EXISTS credentials_smoketest (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ciphertext bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
