CREATE TABLE IF NOT EXISTS user_service.users (
  id uuid PRIMARY KEY,
  full_name varchar(150) NOT NULL,
  email varchar(254) NOT NULL,
  roles text[] NOT NULL CHECK (cardinality(roles) > 0 AND roles <@ ARRAY['ADMIN','DOSEN','MAHASISWA','KOPRODI']::text[]),
  is_active boolean NOT NULL DEFAULT true,
  nim varchar(30) UNIQUE,
  admission_year smallint,
  nip varchar(30) UNIQUE,
  nidn varchar(30) UNIQUE,
  phone varchar(30) NOT NULL DEFAULT '',
  expertise text NOT NULL DEFAULT '',
  study_program varchar(150) NOT NULL DEFAULT 'Teknologi Informasi',
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (NOT ('MAHASISWA' = ANY(roles)) OR (nim IS NOT NULL AND admission_year IS NOT NULL)),
  CHECK (NOT ('KOPRODI' = ANY(roles)) OR 'DOSEN' = ANY(roles)),
  CHECK (NOT ('MAHASISWA' = ANY(roles) AND 'DOSEN' = ANY(roles)))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON user_service.users(lower(email));
CREATE TABLE IF NOT EXISTS user_service.audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_id uuid,
  target_id uuid NOT NULL,
  action text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
