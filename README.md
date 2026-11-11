# Sistem Informasi WIB × SES Group

**Versi 0.1.0 — aplikasi web internal yang dapat dijalankan secara lokal.**

Dibuat dengan FastAPI, SQLite, JavaScript tanpa CDN eksternal, dan antarmuka responsif berbahasa Indonesia. Nomor SK/KTA dibuat secara atomik dalam transaksi database. Dasbor menampilkan grafik pie/donut, distribusi wilayah, dan indikator penugasan SES Group yang berumur 90 hari sejak aktivitas terakhir diverifikasi.

## Mulai (Windows)

1. Ekstrak ZIP di folder khusus. Pastikan Python 3.11+ terpasang.
2. Jalankan `MULAI_DEMO.bat` untuk mencoba dengan 12 profil sintetis. Jalankan `MULAI_OPERASIONAL.bat` untuk database operasional terpisah yang langsung memuat **957 posisi bernama sebagai draft** dari Excel sumber, tanpa data contoh.
3. Pertama kali menjalankan, skrip membuat lingkungan Python dan menginstal dependensi melalui internet.
4. Browser dibuka ke `http://127.0.0.1:8765/`. Bila tidak, buka alamat itu sendiri.
5. Akun awal (termasuk `admin`, `jovi`, `febri`, `ihsan`, `ketum`, `sekjen`, `waketum`, `direksi`, `dpw_demo`, `audit`) mendapat kata sandi kuat acak. Buka `data_demo/AKUN_AWAL_RAHASIA.txt` atau `data_operasional/AKUN_AWAL_RAHASIA.txt` untuk melihatnya. **Ubah kata sandi setiap akun** lewat menu Pengaturan. Batasi akses ke berkas rahasia.
6. Pada pemakaian operasional pertama, 957 posisi bernama dan 21 posisi kosong dibaca otomatis dari file sumber. Nama yang terisi masuk sebagai **draft**, bukan pengurus terverifikasi; posisi yang kosong tidak dibuatkan orang fiktif. Jika ingin mengimpor berkas baru atau ulang, login sebagai Jovi/Febri/admin dan pilih **Data Pengurus → Impor Excel**. Periksa duplikasi dan keabsahan setiap pengangkatan.
7. Setelah input, buka profil pengurus untuk melengkapi identitas, mengunggah KTP atau dokumen; pengesahan WIB oleh akun Ketua Umum, kemudian SES Group oleh akun Direksi SES.

Jika instalasi gagal, buka terminal di folder ini lalu jalankan `python -m pip install -r requirements.txt`, kemudian `python launcher.py operasional`.

## Fitur yang tersedia

- Login dan pembatasan hak akses (DPP Jovi/Febri, Ketua Umum, Sekjen, Waketum, Direksi SES, Ihsan, DPW, auditor).
- Formulir pengurus & anggota: NIK 16 digit, penyimpanan NIK terenkripsi, cek duplikat, identitas, alamat, dan jabatan berjenjang. Data lama dapat diperbaiki melalui **Lengkapi biodata**, dan satu orang dapat memiliki beberapa jabatan.
- Penerbitan nomor anggota dan SK WIB otomatis **hanya saat pejabat berwenang menyetujui**, KTA dan SK PDF dapat diakses dari profil.
- Penugasan SES Group dari Ketua DPW (Koordinator Wilayah), Ketua DPD/DPC (Kepala Cabang), dan Ketua PAC (Kepala Unit); SK SES harus disahkan Direksi SES dan terlihat oleh Ihsan.
- Kantor sekretariat per wilayah dengan alamat dan checklist: berkas Kesbangpol, salinan akta SES dilegalisasi notaris, foto depan, foto interior, dan banner SES Group. Berkas dapat diunggah lalu diverifikasi sesuai kewenangan.
- Laporan kegiatan WIB/SES, status verifikasi dan pemantauan penugasan SES 90 hari tanpa aktivitas yang diverifikasi.
- Peta peluang bisnis (pupuk, Desa Mandiri/Bedah Desa, Dana Putus Sekolah, mesin air, komoditas, energi, properti, travel).
- Evaluasi WIB dan SES per triwulan, nilai 0–100 dan catatan, riwayat pemberhentian, pencarian, ekspor CSV, audit trail.
- Profil resmi WIB dan SES dalam halaman yang memerlukan login.

## Prinsip kewenangan dan keterbatasan

- Admin DPP **tidak** dapat mengesahkan SK WIB. Hanya peran Ketua Umum (dan superadmin teknis untuk uji) yang dapat melakukan persetujuan.
- Ihsan mengawasi administrasi SES, sedangkan pengesahan SK SES hanya oleh peran Direksi (dan superadmin untuk uji).
- Akun SES hanya dapat membuka profil WIB dari orang yang sudah memiliki penugasan SES **aktif**. Berkas KTP ditolak bagi akun SES.
- Pemberhentian WIB otomatis menonaktifkan penugasan SES terkait. Pemberhentian SES tidak menonaktifkan keanggotaan WIB.
- **Tidak ada pemecatan otomatis** pada hari ke-90. Aplikasi menandai kebutuhan evaluasi; pejabat harus mengambil keputusan sendiri.
- **Dukcapil belum tersambung.** Pemeriksaan NIK = format 16 digit dan indikasi duplikat internal, bukan keaslian identitas.
- **SK/KTA PDF merupakan keluaran administrasi, bukan tanda tangan elektronik tersertifikasi**, belum memakai kop/isi SK dari templat hukum final dan harus ditinjau serta ditandatangani sesuai kewenangan sebelum dipakai sebagai surat resmi eksternal.
- Model ini mendukung operasional **lokal internal**. Sebelum melayani banyak kantor melalui internet, perlu pengujian penetrasi, kebijakan retensi dan privasi, otorisasi granular, TLS/HTTPS, backup terenkripsi, monitoring, dan uji beban. SQLite belum ditujukan untuk beban pengguna serentak skala nasional.
- Nomor format final SK perlu disahkan WIB/SES dan disesuaikan dengan ketentuan arsip masing-masing organisasi.
- Berkas administratif Kesbangpol perlu diproses sesuai persyaratan yang benar untuk jenis badan hukum WIB; unggah tidak berarti instansi telah menerbitkan pengesahan baru.

## Struktur data

Semua data disimpan di `data_operasional/` (atau `data_demo/`), dengan file database SQLite, file KTP terenkripsi dan file lain di folder privat `uploads/`, serta kunci enkripsi `.local_secret`.

**Backup:** hentikan aplikasi terlebih dahulu, kemudian salin seluruh folder `data_operasional/`—termasuk berkas tersembunyi `.local_secret`—ke media yang aksesnya dibatasi dan dienkripsi. Jangan memisahkan file database dari kuncinya. Uji pemulihan secara berkala. Jangan simpan backup di folder publik.

## Linux/macOS

`chmod +x mulai_linux_macos.sh && ./mulai_linux_macos.sh operasional`

## Docker (localhost)

`docker compose up --build -d`

Jalankan hanya pada localhost. Akses dari perangkat lain membutuhkan rancangan deployment aman tersendiri.

## Catatan data

`import_sumber/Data_Kepengurusan_WIB_2026.xlsx` merupakan file yang diberikan pengguna dan mungkin memuat informasi pribadi. Jangan distribusikan ulang tanpa wewenang. Data tidak diaktifkan dan tidak dianggap benar sebelum diverifikasi.
