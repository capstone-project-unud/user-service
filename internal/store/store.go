package store

import (
	"capstone/user-service/internal/domain"
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

const Columns = "id,full_name,email,roles,is_active,nim,admission_year,nip,nidn,phone,expertise,study_program,last_login_at,created_at,updated_at"

type Store struct{ DB *pgxpool.Pool }

func Scan(row pgx.Row) (domain.User, error) {
	var u domain.User
	e := row.Scan(&u.ID, &u.FullName, &u.Email, &u.Roles, &u.IsActive, &u.NIM, &u.AdmissionYear, &u.NIP, &u.NIDN, &u.Phone, &u.Expertise, &u.StudyProgram, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	return u, e
}
func (s Store) ByID(ctx context.Context, id string) (domain.User, error) {
	return Scan(s.DB.QueryRow(ctx, "SELECT "+Columns+" FROM user_service.users WHERE id=$1", id))
}
func (s Store) ByEmail(ctx context.Context, email string) (domain.User, error) {
	return Scan(s.DB.QueryRow(ctx, "SELECT "+Columns+" FROM user_service.users WHERE lower(email)=$1", email))
}
func (s Store) ByLoginIdentifier(ctx context.Context, raw string) (domain.User, error) {
	id := strings.TrimSpace(raw)
	if id == "" {
		return domain.User{}, pgx.ErrNoRows
	}
	if strings.Contains(id, "@") {
		return s.ByEmail(ctx, domain.NormalizeEmail(id))
	}
	compact := strings.ReplaceAll(id, " ", "")
	return Scan(s.DB.QueryRow(ctx, `
		SELECT `+Columns+`
		FROM user_service.users
		WHERE nim=$1 OR nip=$1 OR nidn=$1
		   OR replace(coalesce(nip,''),' ','')=$2
		   OR replace(coalesce(nidn,''),' ','')=$2
		   OR lower(email)=lower($1)
		ORDER BY CASE WHEN nim=$1 THEN 1 WHEN nip=$1 THEN 2 WHEN nidn=$1 THEN 3 ELSE 4 END
		LIMIT 1`, id, compact))
}
func Audit(ctx context.Context, tx pgx.Tx, actor, target, action string) error {
	var a any
	if actor != "" {
		a = actor
	}
	_, e := tx.Exec(ctx, "INSERT INTO user_service.audit_logs(actor_id,target_id,action) VALUES($1,$2,$3)", a, target, action)
	return e
}
