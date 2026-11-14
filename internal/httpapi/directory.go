package httpapi

import (
	"capstone/user-service/internal/domain"
	"github.com/gofiber/fiber/v3"
)

// Only the academic service consumes this limited identity projection.
func (s *Server) directory(c fiber.Ctx) error {
	role := c.Query("role")
	if role != "MAHASISWA" && role != "DOSEN" {
		return fiber.ErrBadRequest
	}
	q := c.Query("q")
	if len(q) > 150 {
		return fiber.ErrBadRequest
	}
	rows, err := s.Store.DB.Query(c.Context(), `SELECT id,full_name,coalesce(nim,''),roles,is_active FROM user_service.users
 WHERE is_active AND $1=ANY(roles) AND ($2='' OR full_name ILIKE '%'||$2||'%' OR nim ILIKE '%'||$2||'%') ORDER BY full_name,id LIMIT 100`, role, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []fiber.Map{}
	for rows.Next() {
		var id, name, nim string
		var roles []string
		var active bool
		if err = rows.Scan(&id, &name, &nim, &roles, &active); err != nil {
			return err
		}
		if domain.HasRole(roles, role) {
			items = append(items, fiber.Map{"id": id, "full_name": name, "nim": nim, "roles": roles, "is_active": active})
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": items})
}
