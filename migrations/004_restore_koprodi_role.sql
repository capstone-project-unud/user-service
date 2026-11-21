ALTER TABLE user_service.users DROP CONSTRAINT users_roles_check;
ALTER TABLE user_service.users ADD CONSTRAINT users_roles_check CHECK (
 roles <@ ARRAY['ADMIN','DOSEN','MAHASISWA','KOORDINATOR_TA','TU','KOPRODI']::text[] AND cardinality(roles)>0
);
