package domain

import "testing"

func TestUserValidation(t *testing.T) {
	nim := "2305551001"
	year := 2023
	cases := []struct {
		name  string
		input Input
		valid bool
	}{
		{"student", Input{FullName: "Mahasiswa Pengujian", Email: "Student@Example.com", Roles: []string{"MAHASISWA"}, NIM: &nim, AdmissionYear: &year, Password: "TestPassword1234"}, true},
		{"missing student identity", Input{FullName: "Mahasiswa", Email: "m@example.com", Roles: []string{"MAHASISWA"}, Password: "TestPassword1234"}, false},
		{"koprodi also lecturer", Input{FullName: "Dosen Pengujian", Email: "d@example.com", Roles: []string{"DOSEN", "KOPRODI"}, Password: "TestPassword1234"}, true},
		{"koprodi without lecturer", Input{FullName: "Dosen", Email: "d@example.com", Roles: []string{"KOPRODI"}, Password: "TestPassword1234"}, false},
		{"admin not provisionable", Input{FullName: "Admin", Email: "a@example.com", Roles: []string{"ADMIN"}, Password: "TestPassword1234"}, false},
		{"duplicate roles", Input{FullName: "Dosen", Email: "d@example.com", Roles: []string{"DOSEN", "DOSEN"}, Password: "TestPassword1234"}, false},
		{"display name email", Input{FullName: "Dosen", Email: "Name <d@example.com>", Roles: []string{"DOSEN"}, Password: "TestPassword1234"}, false},
		{"short password", Input{FullName: "Dosen", Email: "d@example.com", Roles: []string{"DOSEN"}, Password: "short"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.input.Validate(true, false)
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, e)
			}
		})
	}
}
