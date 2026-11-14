ALTER TABLE user_service.users DROP CONSTRAINT users_roles_check;
ALTER TABLE user_service.users ADD CONSTRAINT users_roles_check CHECK (
  cardinality(roles) > 0 AND roles <@ ARRAY['ADMIN','DOSEN','MAHASISWA','KOPRODI','KOORDINATOR_TA','TU']::text[]
);
