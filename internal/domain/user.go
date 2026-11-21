package domain

import (
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

type User struct {
	ID            string     `json:"id"`
	FullName      string     `json:"full_name"`
	Email         string     `json:"email"`
	Roles         []string   `json:"roles"`
	IsActive      bool       `json:"is_active"`
	NIM           *string    `json:"nim"`
	AdmissionYear *int       `json:"admission_year"`
	NIP           *string    `json:"nip"`
	NIDN          *string    `json:"nidn"`
	Phone         string     `json:"phone"`
	Expertise     string     `json:"expertise"`
	StudyProgram  string     `json:"study_program"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
type Input struct {
	FullName      string   `json:"full_name"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
	IsActive      *bool    `json:"is_active"`
	NIM           *string  `json:"nim"`
	AdmissionYear *int     `json:"admission_year"`
	NIP           *string  `json:"nip"`
	NIDN          *string  `json:"nidn"`
	Phone         string   `json:"phone"`
	Expertise     string   `json:"expertise"`
	Password      string   `json:"password"`
}

func HasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
func ValidateProfile(name, email, phone, expertise string) error {
	if utf8.RuneCountInString(strings.TrimSpace(name)) < 2 || utf8.RuneCountInString(name) > 150 {
		return fmt.Errorf("Nama harus terdiri dari 2–150 karakter.")
	}
	addr, e := mail.ParseAddress(email)
	if e != nil || addr.Address != email || len(email) > 254 {
		return fmt.Errorf("Format email tidak valid.")
	}
	if utf8.RuneCountInString(phone) > 30 || utf8.RuneCountInString(expertise) > 2000 {
		return fmt.Errorf("Telepon maksimal 30 karakter dan keahlian maksimal 2000 karakter.")
	}
	return nil
}
func (in *Input) Validate(create, bootstrap bool) error {
	in.FullName = strings.TrimSpace(in.FullName)
	in.Email = NormalizeEmail(in.Email)
	in.Phone = strings.TrimSpace(in.Phone)
	in.Expertise = strings.TrimSpace(in.Expertise)
	if err := ValidateProfile(in.FullName, in.Email, in.Phone, in.Expertise); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range in.Roles {
		if seen[r] {
			return fmt.Errorf("Peran tidak boleh berulang.")
		}
		seen[r] = true
		if !HasRole([]string{"MAHASISWA", "DOSEN", "KOORDINATOR_TA", "TU", "ADMIN", "KOPRODI"}, r) {
			return fmt.Errorf("Peran pengguna tidak valid.")
		}
	}
	if len(in.Roles) == 0 || len(in.Roles) > 3 || (seen["KOPRODI"] && !seen["DOSEN"]) || (seen["MAHASISWA"] && len(in.Roles) != 1) || (seen["ADMIN"] && len(in.Roles) != 1) || (seen["TU"] && len(in.Roles) != 1) {
		return fmt.Errorf("Pilih satu jenis akun. Dosen dapat memiliki peran Koprodi dan/atau Koordinator Capstone.")
	}
	for _, p := range []**string{&in.NIM, &in.NIP, &in.NIDN} {
		if *p != nil {
			v := strings.TrimSpace(**p)
			if len(v) > 30 {
				return fmt.Errorf("NIM, NIP, dan NIDN maksimal 30 karakter.")
			}
			if v == "" {
				*p = nil
			} else {
				*p = &v
			}
		}
	}
	if seen["MAHASISWA"] {
		if in.NIM == nil || in.AdmissionYear == nil || *in.AdmissionYear < 2000 || *in.AdmissionYear > time.Now().Year()+1 {
			return fmt.Errorf("NIM dan tahun angkatan yang valid wajib diisi.")
		}
		in.NIP = nil
		in.NIDN = nil
		in.Expertise = ""
	} else {
		in.NIM = nil
		in.AdmissionYear = nil
	}
	if create && (len(in.Password) < 12 || len(in.Password) > 72) {
		return fmt.Errorf("Kata sandi awal harus terdiri dari 12–72 byte.")
	}
	return nil
}
