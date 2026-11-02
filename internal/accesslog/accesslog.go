package accesslog

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
)

func New(service string) fiber.Handler {
	return newLogger(service, os.Stdout)
}

func newLogger(service string, output io.Writer) fiber.Handler {
	name, _ := json.Marshal(service)
	return logger.New(logger.Config{
		Stream:        output,
		DisableColors: true,
		TimeZone:      "UTC",
		TimeFormat:    time.RFC3339Nano,
		Format:        `{"access_log":true,"service":` + string(name) + `,"time":"${time}","status":${status},"method":${method_json},"path":${path_json},"duration":"${latency}"}` + "\n",
		CustomTags: map[string]logger.LogFunc{
			"path_json": func(output logger.Buffer, c fiber.Ctx, _ *logger.Data, _ string) (int, error) {
				value, _ := json.Marshal(c.Path())
				return output.Write(value)
			},
			"method_json": func(output logger.Buffer, c fiber.Ctx, _ *logger.Data, _ string) (int, error) {
				value, _ := json.Marshal(c.Method())
				return output.Write(value)
			},
		},
	})
}
