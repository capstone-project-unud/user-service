UPDATE user_service.users
SET roles = array_remove(roles, 'KOPRODI')
WHERE 'KOPRODI' = ANY(roles);

ALTER TABLE user_service.users DROP CONSTRAINT IF EXISTS users_roles_check;
ALTER TABLE user_service.users ADD CONSTRAINT users_roles_check CHECK (
  cardinality(roles) > 0 AND roles <@ ARRAY['ADMIN','DOSEN','MAHASISWA','KOORDINATOR_TA','TU']::text[]
);
