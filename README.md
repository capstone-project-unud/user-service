# Layanan Pengguna

Repositori ini memuat layanan pengelolaan pengguna Sistem Layanan Capstone Project Program Studi Teknologi Informasi, Universitas Udayana. Layanan menggunakan Go Fiber v3 dan PostgreSQL untuk menyimpan profil, identitas akademik, peran, status akun, serta riwayat perubahan data.

## Ruang Lingkup

Administrator dapat membuat dan menyunting akun mahasiswa atau dosen, mencari pengguna, mengatur status aktif, serta meminta pengaturan ulang kata sandi. Pengguna yang telah login dapat melihat dan memperbarui profilnya sendiri sesuai kewenangan masing-masing.

| Peran | Ketentuan data dan akses |
| --- | --- |
| Mahasiswa | Memiliki NIM unik dan tahun angkatan; dapat memperbarui profil pribadi |
| Dosen | Dapat memiliki NIP, NIDN, nomor telepon, dan bidang keahlian |
| Koprodi | Merupakan peran tambahan pada akun dosen |
| Admin | Mengelola akun mahasiswa dan dosen serta melihat riwayat perubahan |

Akun mahasiswa dan dosen dibuat oleh administrator sesuai SOP registrasi. Penghapusan permanen pengguna tidak disediakan; penonaktifan akun mempertahankan data dan riwayatnya.

## Integrasi dan Penyimpanan

Database `user-service` menggunakan skema `user_service`. Tabel `users` menyimpan data pengguna dan `audit_logs` mencatat perubahan akun. Kredensial dan sesi dikelola oleh [layanan autentikasi](https://github.com/capstone-project-unud/auth-service).

Setiap permintaan terlindungi memerlukan verifikasi sesi melalui layanan autentikasi, kemudian pemeriksaan peran dan status akun pada database layanan ini. Penonaktifan akun disertai pencabutan sesi pengguna.

Pembuatan akun mengoordinasikan transaksi profil dengan pembuatan kredensial pada layanan autentikasi. Mekanisme ini menggunakan kompensasi saat terjadi kegagalan dan belum menyediakan transaksi atomik lintas database. Batas konsistensinya dijelaskan dalam [dokumen arsitektur](https://github.com/capstone-project-unud/infrastructure/blob/main/docs/architecture.md).

## Antarmuka dan Struktur

Endpoint `/api/v1/me` menyediakan akses profil pribadi. Endpoint `/api/v1/users` menyediakan pengelolaan akun, termasuk pencarian, ringkasan, riwayat perubahan, status, dan pengaturan ulang kata sandi, dengan kewenangan administrator. Endpoint internal dilindungi `USER_INTERNAL_TOKEN`.

Kode dikelompokkan ke dalam `cmd/api` untuk titik masuk aplikasi, `internal/domain` untuk aturan data, `internal/httpapi` untuk penanganan HTTP, `internal/store` untuk akses database, serta `migrations` untuk perubahan skema.

## Pengembangan

Layanan memerlukan Go 1.26 atau lebih baru dan konfigurasi berdasarkan `.env.example`. Penyiapan database dan akun administrator awal tersedia dalam repositori [infrastructure](https://github.com/capstone-project-unud/infrastructure).

```sh
go run ./cmd/api
go test ./...
```

Alamat lokal menggunakan port 8082. Berkas kredensial `.env` dan hasil kompilasi tidak disertakan dalam repositori.

Pengembangan Docker menggunakan `Dockerfile.dev` dan `.air.toml` untuk menjalankan Air v1.67.4. Perubahan source Go, `go.mod`, atau `go.sum` memicu kompilasi dan pemulaian ulang layanan. Gunakan gabungan `compose.yaml` dan `compose.dev.yaml` pada repositori infrastructure untuk mengaktifkan mode ini.
