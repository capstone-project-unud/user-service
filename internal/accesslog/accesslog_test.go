package accesslog

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/recover"
)

func TestFinalStatusAndPrivateFields(t *testing.T) {
	for _, code := range []int{200, 400, 401, 403, 404, 500} {
		t.Run(strings.TrimSpace(httpStatusName(code)), func(t *testing.T) {
			var output bytes.Buffer
			app := fiber.New()
			app.Use(newLogger("test-service", &output))
			app.Use(recover.New())
			app.Post("/check", func(c fiber.Ctx) error {
				if code == 500 {
					panic("private-error")
				}
				if code >= 400 {
					return fiber.NewError(code, "private-error")
				}
				return c.SendStatus(code)
			})
			req := httptest.NewRequest("POST", "/check?token=private-query", strings.NewReader(`{"password":"private-body"}`))
			req.Header.Set("Cookie", "session=private-cookie")
			req.Header.Set("Authorization", "Bearer private-header")
			response, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			var entry struct {
				AccessLog                             bool `json:"access_log"`
				Status                                int  `json:"status"`
				Path, Method, Service, Time, Duration string
			}
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("invalid log: %v", err)
			}
			if response.StatusCode != code || entry.Status != code || !entry.AccessLog || entry.Path != "/check" || entry.Method != "POST" || entry.Service != "test-service" || entry.Time == "" || entry.Duration == "" {
				t.Fatalf("unexpected entry: %+v", entry)
			}
			if strings.Contains(output.String(), "private-") {
				t.Fatal("private request data leaked into access log")
			}
		})
	}
}

func httpStatusName(code int) string {
	return map[int]string{200: "success", 400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 500: "panic"}[code]
}
