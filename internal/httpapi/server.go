package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"capstone/user-service/internal/accesslog"
	"capstone/user-service/internal/domain"
	"capstone/user-service/internal/store"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Server struct {
	Store                             store.Store
	Client                            *http.Client
	AuthURL, AuthToken, InternalToken string
}

func New(db store.Store) *fiber.App {
	s := &Server{Store: db, Client: &http.Client{Timeout: 8 * time.Second}, AuthURL: strings.TrimRight(os.Getenv("AUTH_SERVICE_URL"), "/"), AuthToken: os.Getenv("AUTH_INTERNAL_TOKEN"), InternalToken: os.Getenv("USER_INTERNAL_TOKEN")}
	app := fiber.New(fiber.Config{AppName: "capstone-users", BodyLimit: 32 * 1024, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, ErrorHandler: func(c fiber.Ctx, e error) error {
		code := 500
		message := "Layanan pengguna mengalami gangguan."
		var fe *fiber.Error
		var pe *pgconn.PgError
		if errors.As(e, &fe) {
			code = fe.Code
			message = fe.Message
		} else if errors.As(e, &pe) && pe.Code == "23505" {
			code = 409
			message = "Email, NIM, NIP, atau NIDN sudah digunakan."
		} else if errors.Is(e, pgx.ErrNoRows) {
			code = 404
			message = "Pengguna tidak ditemukan."
		}
		return c.Status(code).JSON(fiber.Map{"error": fiber.Map{"message": message}})
	}})
	app.Use(accesslog.New("user-service"))
	app.Use(recover.New())
	app.Use(func(c fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 15*time.Second)
		defer cancel()
		c.SetContext(ctx)
		return c.Next()
	})
	app.Get("/health", func(c fiber.Ctx) error {
		if db.DB.Ping(c.Context()) != nil {
			return fiber.ErrServiceUnavailable
		}
		return c.JSON(fiber.Map{"service": "user-service", "status": "ok"})
	})
	internal := app.Group("/internal", s.internal)
	internal.Get("/users/by-email", s.byEmail)
	internal.Get("/users/by-identifier", s.byIdentifier)
	internal.Get("/directory", s.directory)
	internal.Get("/users/:id", s.byID)
	internal.Post("/users/:id/login", s.lastLogin)
	internal.Post("/bootstrap", s.bootstrap)
	api := app.Group("/api/v1", s.authenticated)
	api.Get("/me", func(c fiber.Ctx) error { return c.JSON(fiber.Map{"user": c.Locals("user")}) })
	api.Put("/me", s.updateMe)
	users := api.Group("/users", s.admin)
	users.Get("/stats", s.stats)
	users.Get("/audit", s.audit)
	users.Get("/", s.list)
	users.Post("/", s.create)
	users.Patch("/batch-status", s.batchStatus)
	users.Get("/:id", func(c fiber.Ctx) error {
		u, e := s.Store.ByID(c.Context(), c.Params("id"))
		if e != nil {
			return e
		}
		return c.JSON(fiber.Map{"user": u})
	})
	users.Put("/:id", s.update)
	users.Patch("/:id/status", s.status)
	users.Put("/:id/password", s.resetPassword)
	return app
}
func (s *Server) internal(c fiber.Ctx) error {
	if subtle.ConstantTimeCompare([]byte(c.Get("X-Service-Token")), []byte(s.InternalToken)) != 1 {
		return fiber.ErrUnauthorized
	}
	return c.Next()
}
func (s *Server) authRequest(ctx context.Context, method, path string, data any) (int, []byte, error) {
	var body io.Reader
	if data != nil {
		b, e := json.Marshal(data)
		if e != nil {
			return 0, nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, s.AuthURL+path, body)
	if e != nil {
		return 0, nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Token", s.AuthToken)
	res, e := s.Client.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 32*1024))
	return res.StatusCode, b, e
}
func (s *Server) authenticated(c fiber.Ctx) error {
	t := c.Cookies("capstone_session")
	if len(t) != 43 {
		return fiber.ErrUnauthorized
	}
	status, b, e := s.authRequest(c.Context(), http.MethodPost, "/internal/sessions/verify", map[string]string{"token": t})
	if e != nil {
		return fiber.NewError(503, "Layanan autentikasi belum tersedia.")
	}
	if status == 401 {
		return fiber.ErrUnauthorized
	}
	if status != 200 {
		return fiber.ErrServiceUnavailable
	}
	var result struct {
		ID string `json:"user_id"`
	}
	if json.Unmarshal(b, &result) != nil {
		return fiber.ErrServiceUnavailable
	}
	u, e := s.Store.ByID(c.Context(), result.ID)
	if errors.Is(e, pgx.ErrNoRows) {
		return fiber.ErrUnauthorized
	}
	if e != nil {
		return e
	}
	if !u.IsActive {
		return fiber.ErrUnauthorized
	}
	c.Locals("user", u)
	c.Set("Cache-Control", "no-store")
	return c.Next()
}
func (s *Server) admin(c fiber.Ctx) error {
	if !domain.HasRole(c.Locals("user").(domain.User).Roles, "ADMIN") {
		return fiber.NewError(403, "Hanya admin yang dapat mengelola pengguna.")
	}
	return c.Next()
}
func (s *Server) byEmail(c fiber.Ctx) error {
	u, e := s.Store.ByEmail(c.Context(), domain.NormalizeEmail(c.Query("email")))
	if e != nil {
		return e
	}
	return c.JSON(u)
}
func (s *Server) byIdentifier(c fiber.Ctx) error {
	u, e := s.Store.ByLoginIdentifier(c.Context(), c.Query("q"))
	if e != nil {
		return e
	}
	return c.JSON(u)
}
func (s *Server) byID(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	u, e := s.Store.ByID(c.Context(), c.Params("id"))
	if e != nil {
		return e
	}
	return c.JSON(u)
}
func (s *Server) lastLogin(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	_, e := s.Store.DB.Exec(c.Context(), "UPDATE user_service.users SET last_login_at=now() WHERE id=$1", c.Params("id"))
	if e != nil {
		return e
	}
	return c.SendStatus(204)
}
func (s *Server) bootstrap(c fiber.Ctx) error { return s.insert(c, true) }
func (s *Server) create(c fiber.Ctx) error    { return s.insert(c, false) }
func (s *Server) insert(c fiber.Ctx, bootstrap bool) error {
	var in domain.Input
	if c.Bind().JSON(&in) != nil {
		return fiber.ErrUnprocessableEntity
	}
	if bootstrap {
		in.Roles = []string{"ADMIN"}
	}
	if e := in.Validate(true, bootstrap); e != nil {
		return fiber.NewError(422, e.Error())
	}
	ctx := c.Context()
	tx, e := s.Store.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if bootstrap {
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(140201)"); e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM user_service.users WHERE 'ADMIN'=ANY(roles))").Scan(&exists); e != nil {
			return e
		}
		if exists {
			return fiber.NewError(409, "Admin awal sudah tersedia.")
		}
	}
	id := uuid.NewString()
	active := true
	if in.IsActive != nil {
		active = *in.IsActive
	}
	u, e := store.Scan(tx.QueryRow(ctx, "INSERT INTO user_service.users(id,full_name,email,roles,is_active,nim,admission_year,nip,nidn,phone,expertise) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING "+store.Columns, id, in.FullName, in.Email, in.Roles, active, in.NIM, in.AdmissionYear, in.NIP, in.NIDN, in.Phone, in.Expertise))
	if e != nil {
		return e
	}
	actor := ""
	if !bootstrap {
		actor = c.Locals("user").(domain.User).ID
	}
	if e = store.Audit(ctx, tx, actor, id, "USER_CREATED"); e != nil {
		return e
	}
	status, _, e := s.authRequest(ctx, http.MethodPut, "/internal/credentials/"+id, map[string]string{"password": in.Password})
	if e != nil || status != 201 {
		s.compensate(id)
		return fiber.NewError(503, "Akun belum dibuat karena layanan autentikasi belum tersedia. Silakan coba kembali.")
	}
	if e = tx.Commit(ctx); e != nil {
		// An uncertain commit must not remove credentials for a committed profile.
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, checkErr := s.Store.ByID(checkCtx, id); errors.Is(checkErr, pgx.ErrNoRows) {
			s.compensate(id)
		}
		return fiber.NewError(503, "Hasil penyimpanan belum dapat dipastikan. Periksa daftar sebelum mencoba kembali.")
	}
	return c.Status(201).JSON(fiber.Map{"user": u})
}
func (s *Server) compensate(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, _, _ = s.authRequest(ctx, http.MethodDelete, "/internal/credentials/"+id, nil)
}
func (s *Server) list(c fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		page = 100000
	}
	limit := 12
	if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		parsedLimit, err := strconv.Atoi(rawLimit)
		if err != nil || parsedLimit < 1 || parsedLimit > 1000 {
			return fiber.ErrBadRequest
		}
		limit = parsedLimit
	}
	q := strings.TrimSpace(c.Query("q"))
	if len(q) > 150 {
		return fiber.ErrBadRequest
	}
	role := c.Query("role")
	if role != "" && !domain.HasRole([]string{"ADMIN", "DOSEN", "MAHASISWA", "KOORDINATOR_TA", "TU", "KOPRODI"}, role) {
		return fiber.ErrBadRequest
	}
	active := c.Query("status")
	if active != "" && active != "active" && active != "inactive" {
		return fiber.ErrBadRequest
	}
	year, _ := strconv.Atoi(c.Query("admission_year"))
	if year < 1900 || year > 2100 {
		year = 0
	}
	where := " FROM user_service.users WHERE ($1='' OR full_name ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' OR nim ILIKE '%'||$1||'%' OR nip ILIKE '%'||$1||'%' OR nidn ILIKE '%'||$1||'%') AND ($2='' OR ($2=ANY(roles) AND ($2<>'DOSEN' OR NOT ('KOORDINATOR_TA'=ANY(roles))))) AND ($3='' OR is_active=($3='active')) AND ($4=0 OR admission_year=$4)"
	var total int
	if e := s.Store.DB.QueryRow(c.Context(), "SELECT count(*)"+where, q, role, active, year).Scan(&total); e != nil {
		return e
	}
	rows, e := s.Store.DB.Query(c.Context(), "SELECT "+store.Columns+where+" ORDER BY created_at DESC,id DESC LIMIT $5 OFFSET $6", q, role, active, year, limit, (page-1)*limit)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []domain.User{}
	for rows.Next() {
		u, e := store.Scan(rows)
		if e != nil {
			return e
		}
		items = append(items, u)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}
func (s *Server) stats(c fiber.Ctx) error {
	var total, active, students, lecturers, lecturersOnly, coordinators, tu, admins int
	e := s.Store.DB.QueryRow(c.Context(), `
		SELECT count(*),
		       count(*) FILTER(WHERE is_active),
		       count(*) FILTER(WHERE 'MAHASISWA'=ANY(roles)),
		       count(*) FILTER(WHERE 'DOSEN'=ANY(roles)),
		       count(*) FILTER(WHERE 'DOSEN'=ANY(roles) AND NOT ('KOORDINATOR_TA'=ANY(roles))),
		       count(*) FILTER(WHERE 'KOORDINATOR_TA'=ANY(roles)),
		       count(*) FILTER(WHERE 'TU'=ANY(roles)),
		       count(*) FILTER(WHERE 'ADMIN'=ANY(roles))
		FROM user_service.users`).Scan(&total, &active, &students, &lecturers, &lecturersOnly, &coordinators, &tu, &admins)
	if e != nil {
		return e
	}
	type cohortStat struct {
		Year   int `json:"year"`
		Total  int `json:"total"`
		Active int `json:"active"`
	}
	cohorts := []cohortStat{}
	rows, e := s.Store.DB.Query(c.Context(), `
		SELECT admission_year, count(*), count(*) FILTER(WHERE is_active)
		FROM user_service.users
		WHERE 'MAHASISWA'=ANY(roles) AND admission_year IS NOT NULL
		GROUP BY admission_year
		ORDER BY admission_year ASC`)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var row cohortStat
		if e = rows.Scan(&row.Year, &row.Total, &row.Active); e != nil {
			return e
		}
		cohorts = append(cohorts, row)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return c.JSON(fiber.Map{
		"total":          total,
		"active":         active,
		"inactive":       total - active,
		"students":       students,
		"lecturers":      lecturers,
		"lecturers_only": lecturersOnly,
		"coordinators":   coordinators,
		"tu":             tu,
		"admins":         admins,
		"cohorts":        cohorts,
	})
}
func (s *Server) update(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	var in domain.Input
	if c.Bind().JSON(&in) != nil {
		return fiber.ErrUnprocessableEntity
	}
	if e := in.Validate(false, false); e != nil {
		return fiber.NewError(422, e.Error())
	}
	ctx := c.Context()
	tx, e := s.Store.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	old, e := store.Scan(tx.QueryRow(ctx, "SELECT "+store.Columns+" FROM user_service.users WHERE id=$1 FOR UPDATE", c.Params("id")))
	if e != nil {
		return e
	}
	if domain.HasRole(old.Roles, "ADMIN") && !domain.HasRole(in.Roles, "ADMIN") {
		return fiber.NewError(422, "Peran akun admin tidak dapat dihapus melalui formulir ini.")
	}
	u, e := store.Scan(tx.QueryRow(ctx, "UPDATE user_service.users SET full_name=$2,email=$3,roles=$4,nim=$5,admission_year=$6,nip=$7,nidn=$8,phone=$9,expertise=$10,updated_at=now() WHERE id=$1 RETURNING "+store.Columns, old.ID, in.FullName, in.Email, in.Roles, in.NIM, in.AdmissionYear, in.NIP, in.NIDN, in.Phone, in.Expertise))
	if e != nil {
		return e
	}
	if e = store.Audit(ctx, tx, c.Locals("user").(domain.User).ID, u.ID, "USER_UPDATED"); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return c.JSON(fiber.Map{"user": u})
}
func (s *Server) status(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	var in struct {
		Active *bool `json:"is_active"`
	}
	if c.Bind().JSON(&in) != nil || in.Active == nil {
		return fiber.ErrUnprocessableEntity
	}
	ctx := c.Context()
	tx, e := s.Store.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	u, e := store.Scan(tx.QueryRow(ctx, "SELECT "+store.Columns+" FROM user_service.users WHERE id=$1 FOR UPDATE", c.Params("id")))
	if e != nil {
		return e
	}
	if domain.HasRole(u.Roles, "ADMIN") {
		return fiber.NewError(422, "Status akun admin dilindungi pada modul ini.")
	}
	if _, e = tx.Exec(ctx, "UPDATE user_service.users SET is_active=$2,updated_at=now() WHERE id=$1", u.ID, *in.Active); e != nil {
		return e
	}
	action := "USER_DEACTIVATED"
	if !*in.Active {
		code, _, err := s.authRequest(ctx, http.MethodDelete, "/internal/sessions/user/"+u.ID, nil)
		if err != nil || code != 204 {
			return fiber.NewError(503, "Akun belum dinonaktifkan karena pencabutan sesi belum berhasil. Silakan coba kembali.")
		}
	}
	if *in.Active {
		action = "USER_ACTIVATED"
	}
	if e = store.Audit(ctx, tx, c.Locals("user").(domain.User).ID, u.ID, action); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return c.SendStatus(204)
}
func (s *Server) batchStatus(c fiber.Ctx) error {
	var in struct {
		UserIDs  []string `json:"user_ids"`
		IsActive *bool    `json:"is_active"`
	}
	if c.Bind().JSON(&in) != nil || in.IsActive == nil || len(in.UserIDs) == 0 {
		return fiber.ErrUnprocessableEntity
	}
	if len(in.UserIDs) > 500 {
		return fiber.NewError(400, "Maksimal 500 pengguna per operasi massal.")
	}
	for _, id := range in.UserIDs {
		if _, err := uuid.Parse(id); err != nil {
			return fiber.NewError(422, "Identitas pengguna tidak valid.")
		}
	}
	ctx := c.Context()
	tx, e := s.Store.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)

	actorID := c.Locals("user").(domain.User).ID
	if !*in.IsActive {
		var ungraduated bool
		var hasFinalExam bool
		if e = tx.QueryRow(ctx, `SELECT to_regclass('capstone_service.final_exams') IS NOT NULL`).Scan(&hasFinalExam); e != nil {
			return e
		}
		if hasFinalExam {
			if e = tx.QueryRow(ctx, `
				SELECT EXISTS(
					SELECT 1 FROM user_service.users u
					WHERE u.id = ANY($1::uuid[]) AND 'MAHASISWA'=ANY(u.roles)
					  AND NOT EXISTS(
						SELECT 1 FROM capstone_service.project_students ps
						JOIN capstone_service.final_exams fe ON fe.project_id=ps.project_id
						WHERE ps.student_id=u.id AND fe.status='PASSED'
						  AND NOT EXISTS(SELECT 1 FROM capstone_service.seminar_revision_items ri WHERE ri.project_id=fe.project_id AND ri.stage='FINAL_EXAM' AND ri.status <> 'APPROVED')
					  )
				)`, in.UserIDs).Scan(&ungraduated); e != nil {
				return e
			}
		} else {
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM user_service.users WHERE id=ANY($1::uuid[]) AND 'MAHASISWA'=ANY(roles))", in.UserIDs).Scan(&ungraduated); e != nil {
				return e
			}
		}
		if ungraduated {
			return fiber.NewError(422, "Deaktivasi massal mahasiswa memerlukan kelulusan Ujian Akhir dan penyelesaian revisi terverifikasi untuk seluruh mahasiswa terpilih.")
		}
	}
	updatedCount := 0

	for _, uid := range in.UserIDs {
		if _, e := uuid.Parse(uid); e != nil {
			continue
		}
		var isAdm bool
		if e := tx.QueryRow(ctx, "SELECT 'ADMIN'=ANY(roles) FROM user_service.users WHERE id=$1", uid).Scan(&isAdm); e != nil {
			continue
		}
		if isAdm {
			continue
		}
		if _, e := tx.Exec(ctx, "UPDATE user_service.users SET is_active=$2, updated_at=now() WHERE id=$1", uid, *in.IsActive); e == nil {
			updatedCount++
			if !*in.IsActive {
				_, _, _ = s.authRequest(ctx, http.MethodDelete, "/internal/sessions/user/"+uid, nil)
			}
			action := "USER_DEACTIVATED"
			if *in.IsActive {
				action = "USER_ACTIVATED"
			}
			_ = store.Audit(ctx, tx, actorID, uid, action)
		}
	}

	if e := tx.Commit(ctx); e != nil {
		return e
	}
	return c.JSON(fiber.Map{"updated_count": updatedCount})
}
func (s *Server) resetPassword(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	u, e := s.Store.ByID(c.Context(), c.Params("id"))
	if e != nil {
		return e
	}
	if domain.HasRole(u.Roles, "ADMIN") {
		return fiber.NewError(422, "Gunakan fitur ubah kata sandi pada profil admin.")
	}
	var in struct {
		Password string `json:"password"`
	}
	if c.Bind().JSON(&in) != nil || len(in.Password) < 12 || len(in.Password) > 72 {
		return fiber.NewError(422, "Kata sandi harus terdiri dari 12–72 byte.")
	}
	code, _, e := s.authRequest(c.Context(), http.MethodPut, "/internal/credentials/"+u.ID+"/password", map[string]string{"password": in.Password})
	if e != nil || code != 204 {
		return fiber.NewError(503, "Kata sandi belum dapat diatur ulang. Silakan coba kembali.")
	}
	_, e = s.Store.DB.Exec(c.Context(), "INSERT INTO user_service.audit_logs(actor_id,target_id,action) VALUES($1,$2,'PASSWORD_RESET')", c.Locals("user").(domain.User).ID, u.ID)
	if e != nil {
		return fiber.NewError(503, "Kata sandi telah berubah, tetapi pencatatan aktivitas gagal. Jangan mengirim ulang sebelum memeriksa akun.")
	}
	return c.SendStatus(204)
}
func (s *Server) updateMe(c fiber.Ctx) error {
	u := c.Locals("user").(domain.User)
	var in struct {
		FullName  string `json:"full_name"`
		Email     string `json:"email"`
		Phone     string `json:"phone"`
		Expertise string `json:"expertise"`
	}
	if c.Bind().JSON(&in) != nil {
		return fiber.ErrUnprocessableEntity
	}
	in.FullName = strings.TrimSpace(in.FullName)
	in.Email = domain.NormalizeEmail(in.Email)
	if e := domain.ValidateProfile(in.FullName, in.Email, in.Phone, in.Expertise); e != nil {
		return fiber.NewError(422, e.Error())
	}
	if !domain.HasRole(u.Roles, "DOSEN") {
		in.Expertise = u.Expertise
	}
	if domain.HasRole(u.Roles, "ADMIN") {
		in.Phone = u.Phone
	}
	ctx := c.Context()
	tx, e := s.Store.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	next, e := store.Scan(tx.QueryRow(ctx, "UPDATE user_service.users SET full_name=$2,email=$3,phone=$4,expertise=$5,updated_at=now() WHERE id=$1 RETURNING "+store.Columns, u.ID, in.FullName, in.Email, in.Phone, in.Expertise))
	if e != nil {
		return e
	}
	if e = store.Audit(ctx, tx, u.ID, u.ID, "PROFILE_UPDATED"); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return c.JSON(fiber.Map{"user": next})
}
func (s *Server) audit(c fiber.Ctx) error {
	rows, e := s.Store.DB.Query(c.Context(), "SELECT a.id,coalesce(u.full_name,'Bootstrap sistem'),coalesce(t.full_name,'Pengguna'),a.action,a.created_at FROM user_service.audit_logs a LEFT JOIN user_service.users u ON u.id=a.actor_id LEFT JOIN user_service.users t ON t.id=a.target_id ORDER BY a.id DESC LIMIT 20")
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []fiber.Map{}
	for rows.Next() {
		var id int64
		var actor, target, action string
		var at time.Time
		if e = rows.Scan(&id, &actor, &target, &action, &at); e != nil {
			return e
		}
		items = append(items, fiber.Map{"id": id, "actor": actor, "target": target, "action": action, "created_at": at})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return c.JSON(fiber.Map{"items": items})
}
