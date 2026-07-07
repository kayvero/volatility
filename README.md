# # Volatility Cheat Sheet & Studi Kasus Lengkap

Dokumen ini adalah panduan lengkap penggunaan **Volatility** (Volatility 2 & Volatility 3) untuk analisis memory forensics, dilengkapi dengan alur kerja praktis dan studi kasus dari skenario CTF/incident response.

---

## Daftar Isi

1. [Pengantar Memory Forensics](#1-pengantar-memory-forensics)
2. [Volatility 2 vs Volatility 3](#2-volatility-2-vs-volatility-3)
3. [Instalasi](#3-instalasi)
4. [Identifikasi Profile / OS Info](#4-identifikasi-profile--os-info)
5. [Cheat Sheet Plugin — Proses & Sistem](#5-cheat-sheet-plugin--proses--sistem)
6. [Cheat Sheet Plugin — Network](#6-cheat-sheet-plugin--network)
7. [Cheat Sheet Plugin — Registry](#7-cheat-sheet-plugin--registry)
8. [Cheat Sheet Plugin — Malware & Code Injection](#8-cheat-sheet-plugin--malware--code-injection)
9. [Cheat Sheet Plugin — File & Handle](#9-cheat-sheet-plugin--file--handle)
10. [Cheat Sheet Plugin — Command History & Credential](#10-cheat-sheet-plugin--command-history--credential)
11. [Ekstraksi File / Dumping](#11-ekstraksi-file--dumping)
12. [Volatility 3 — Perbedaan Perintah](#12-volatility-3--perbedaan-perintah)
13. [Alur Kerja Investigasi Standar](#13-alur-kerja-investigasi-standar)
14. [STUDI KASUS 1: Malware Proses Tersembunyi](#studi-kasus-1-malware-proses-tersembunyi)
15. [STUDI KASUS 2: Ransomware & Command Line Mencurigakan](#studi-kasus-2-ransomware--command-line-mencurigakan)
16. [STUDI KASUS 3: Credential Dumping / Mimikatz](#studi-kasus-3-credential-dumping--mimikatz)
17. [STUDI KASUS 4: CTF — Mencari Flag di Memory Dump](#studi-kasus-4-ctf--mencari-flag-di-memory-dump)
18. [Referensi Cepat (Quick Reference Table)](#18-referensi-cepat-quick-reference-table)

---

## 1. Pengantar Memory Forensics

Memory forensics adalah proses menganalisis **RAM dump** (image memori) dari sebuah sistem untuk menemukan jejak forensik yang tidak tersimpan di disk — seperti proses yang sedang berjalan, koneksi jaringan aktif, password di cleartext, malware yang hanya ada di memori (fileless malware), hingga kunci enkripsi.

**Volatility** adalah framework open-source berbasis Python yang menjadi standar industri untuk tugas ini. Volatility bekerja dengan cara mem-parsing struktur data kernel OS langsung dari raw memory image (format `.raw`, `.mem`, `.vmem`, `.dmp`, dll).

---

## 2. Volatility 2 vs Volatility 3

| Aspek | Volatility 2 | Volatility 3 |
|---|---|---|
| Bahasa | Python 2 | Python 3 |
| Profile | Wajib ditentukan manual (`--profile=Win7SP1x64`) | Otomatis dideteksi (tidak perlu profile manual untuk Windows umumnya) |
| Sintaks | `vol.py -f <img> --profile=<profile> <plugin>` | `vol3 -f <img> <plugin>` |
| Kecepatan | Lebih lambat untuk beberapa plugin | Umumnya lebih cepat & lebih stabil untuk OS modern |
| Status | Legacy, masih dipakai di banyak soal CTF lama | Aktif dikembangkan, direkomendasikan untuk kasus baru |

> **Tips CTF:** Kalau `imageinfo` di Vol2 gagal mendeteksi profile, atau soal menyebut Windows 10/11 versi baru, langsung coba Volatility 3 — biasanya jauh lebih mulus.

---

## 3. Instalasi

### Volatility 2
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
pip install -r requirements.txt   # python2 environment
python vol.py -h
```

### Volatility 3
```bash
pip install volatility3
# atau
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -r requirements.txt
python3 vol.py -h
```

### Symbol Table (Volatility 3, khusus Linux/Mac)
Volatility 3 butuh symbol table (`.json`/`.json.xz`) yang sesuai kernel target, diletakkan di folder `volatility3/symbols/`.

---

## 4. Identifikasi Profile / OS Info

### Volatility 2
```bash
# Menentukan profile OS yang cocok dengan memory image
vol.py -f memdump.raw imageinfo

# Alternatif yang lebih cepat (khusus Windows)
vol.py -f memdump.raw kdbgscan
```

### Volatility 3
```bash
# Vol3 otomatis mendeteksi OS, tapi bisa dicek eksplisit dengan:
vol3 -f memdump.raw windows.info
vol3 -f memdump.raw linux.info
```

---

## 5. Cheat Sheet Plugin — Proses & Sistem

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| List proses (tree, bisa disembunyikan dari task manager) | `pslist` | `windows.pslist` |
| List proses berbentuk tree (parent-child) | `pstree` | `windows.pstree` |
| Cari proses tersembunyi (cross-reference EPROCESS pool scan) | `psscan` | `windows.psscan` |
| Cari proses yang di-hide via DKOM/rootkit | `psxview` | *(gunakan psscan vs pslist manual)* |
| Command line tiap proses | `cmdline` | `windows.cmdline` |
| Environment variable proses | `envars` | `windows.envars` |
| DLL yang dimuat proses tertentu | `dlllist -p <PID>` | `windows.dlllist --pid <PID>` |
| Handle (file, registry, mutex) proses | `handles -p <PID>` | `windows.handles --pid <PID>` |
| Privilege token proses | `privs -p <PID>` | `windows.privileges` |
| Service yang berjalan | `svcscan` | `windows.svcscan` |

**Contoh:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 pslist
vol.py -f memdump.raw --profile=Win7SP1x64 pstree
vol.py -f memdump.raw --profile=Win7SP1x64 psscan

vol3 -f memdump.raw windows.pslist
vol3 -f memdump.raw windows.pstree
```

> **Tips:** Selalu bandingkan hasil `pslist` (yang berbasis linked-list, bisa dimanipulasi malware) dengan `psscan` (pool scanning, lebih sulit dihindari). Jika ada PID muncul di `psscan` tapi tidak di `pslist`, itu **indikasi kuat proses disembunyikan (rootkit/DKOM)**.

---

## 6. Cheat Sheet Plugin — Network

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| Koneksi jaringan aktif (XP/2003) | `connections` | — |
| Koneksi jaringan aktif (Vista+) | `netscan` | `windows.netscan` |
| Socket yang terbuka (XP/2003) | `sockets` | — |
| Interface jaringan | `netscan` mencakup ini juga | `windows.netscan` |

**Contoh:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 netscan
vol3 -f memdump.raw windows.netscan
```

Output berisi: local/remote IP & port, protokol (TCP/UDP), state koneksi (`ESTABLISHED`, `LISTENING`, dll), dan PID pemilik koneksi — sangat berguna untuk menemukan **C2 (command & control) callback** malware.

---

## 7. Cheat Sheet Plugin — Registry

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| List hive registry yang termuat | `hivelist` | `windows.registry.hivelist` |
| Dump/print key registry tertentu | `printkey -o <offset> -K "<path>"` | `windows.registry.printkey --key "<path>"` |
| Dump seluruh hive ke file | `hivedump -o <offset>` | — |
| Cari userassist (riwayat aplikasi dijalankan) | `userassist` | `windows.registry.userassist` |
| Cari shimcache (evidence of execution) | `shimcache` | `windows.registry.shimcache` |
| Autorun / Run keys (persistence) | `printkey -K "Microsoft\Windows\CurrentVersion\Run"` | sama, via `windows.registry.printkey` |

**Contoh mencari persistence malware:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 printkey -K "Microsoft\Windows\CurrentVersion\Run"
vol3 -f memdump.raw windows.registry.printkey --key "Microsoft\Windows\CurrentVersion\Run"
```

---

## 8. Cheat Sheet Plugin — Malware & Code Injection

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| Deteksi code injection / hollowing | `malfind` | `windows.malfind` |
| Deteksi hook API (SSDT, IAT, IDT, dll) | `apihooks` | — (terbatas) |
| Deteksi driver tersembunyi | `moddump`, `modscan` | `windows.modscan` |
| Deteksi hidden/orphan thread | `threads` | `windows.threads` |
| Ekstrak proses yang dicurigai untuk analisis lanjut (mis. VirusTotal) | `procdump -p <PID> -D <outdir>` | `windows.pslist --pid <PID> --dump` |
| Scan YARA rule terhadap seluruh memory | `yarascan -y rule.yar` | `windows.vadyarascan`, `windows.yarascan` |
| Cek VAD (Virtual Address Descriptor) — area memory proses | `vadinfo -p <PID>` | `windows.vadinfo --pid <PID>` |
| Dump area memory VAD tertentu | `vaddump -p <PID> -D <outdir>` | `windows.vadyarascan` |

**Contoh mencari code injection:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 malfind -D output/
vol3 -f memdump.raw windows.malfind --dump
```

`malfind` mencari region memory dengan permission `RWX` (read-write-execute) yang **tidak backed oleh file di disk** — pola klasik dari process injection (reflective DLL injection, process hollowing, shellcode injection).

**Contoh YARA scan (cari string/pattern spesifik):**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 yarascan -y malware_rules.yar
vol3 -f memdump.raw windows.yarascan --yara-file malware_rules.yar
```

---

## 9. Cheat Sheet Plugin — File & Handle

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| List file object di memory | `filescan` | `windows.filescan` |
| Dump file dari memory berdasar offset | `dumpfiles -Q <offset> -D <outdir>` | `windows.dumpfiles --virtaddr <addr>` |
| List handle yang dibuka proses | `handles -p <PID>` | `windows.handles --pid <PID>` |
| Cari mutex (indikator infeksi unik malware) | `handles -p <PID> -t Mutant` | `windows.handles --pid <PID>` (filter Mutant) |

**Contoh ekstrak file dari memory:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 filescan | grep -i "suspicious.exe"
vol.py -f memdump.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003e presume -D output/
```

---

## 10. Cheat Sheet Plugin — Command History & Credential

| Tujuan | Volatility 2 | Volatility 3 |
|---|---|---|
| Riwayat command shell (cmd.exe) | `cmdscan` | `windows.cmdscan` |
| Riwayat console (lebih lengkap) | `consoles` | `windows.consoles` |
| Dump hash password (SAM) | `hashdump` | `windows.hashdump` |
| Cari cached domain credential | `cachedump` | `windows.cachedump` |
| LSA secret (kadang berisi password service) | `lsadump` | `windows.lsadump` |
| Deteksi mimikatz artefak / cleartext password di LSASS | `malfind` pada proses `lsass.exe` + `procdump`, lalu analisis dengan `mimikatz`/`pypykatz` offline | sama |

**Contoh dump hash password:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 hashdump
vol3 -f memdump.raw windows.hashdump
```

**Contoh melihat command yang diketik attacker:**
```bash
vol.py -f memdump.raw --profile=Win7SP1x64 cmdscan
vol.py -f memdump.raw --profile=Win7SP1x64 consoles
```

---

## 11. Ekstraksi File / Dumping

| Aksi | Perintah |
|---|---|
| Dump executable proses tertentu | `vol.py -f mem.raw --profile=X procdump -p <PID> -D out/` |
| Dump seluruh memory space proses (untuk analisis lanjut) | `vol.py -f mem.raw --profile=X memdump -p <PID> -D out/` |
| Dump DLL tertentu | `vol.py -f mem.raw --profile=X dlldump -p <PID> -D out/` |
| Dump file dari VAD (biasanya untuk file yang dimapping, gambar/dokumen) | `vol.py -f mem.raw --profile=X vaddump -p <PID> -D out/` |

Setelah proses/file didump, biasanya dianalisis lebih lanjut dengan:
- `file <namafile>` — cek tipe file
- `strings <namafile> | grep -i <keyword>` — cari string mencurigakan
- Upload ke sandbox (VirusTotal, Any.run) — **hati-hati**, khusus lab/CTF, jangan upload data sensitif nyata

---

## 12. Volatility 3 — Perbedaan Perintah

Volatility 3 mengganti hampir semua penamaan plugin dengan awalan OS (`windows.`, `linux.`, `mac.`):

```bash
# List seluruh plugin yang tersedia
vol3 -f memdump.raw --help

# Contoh plugin Linux
vol3 -f memdump.raw linux.pslist
vol3 -f memdump.raw linux.bash        # riwayat bash history dari memori
vol3 -f memdump.raw linux.netstat

# Contoh plugin Mac
vol3 -f memdump.raw mac.pslist
vol3 -f memdump.raw mac.netstat
```

**Perbedaan penting:** Vol3 tidak butuh flag `--profile`. OS & versi kernel dideteksi otomatis dari struktur memory image (untuk Windows). Untuk Linux/Mac tetap perlu symbol table yang sesuai.

---

## 13. Alur Kerja Investigasi Standar

Berikut alur kerja umum saat menghadapi memory dump (baik untuk CTF maupun kasus nyata):

```
1. Identifikasi OS & profile
   → imageinfo (Vol2) / windows.info (Vol3)

2. Lihat gambaran umum proses
   → pslist, pstree, psscan
   → bandingkan pslist vs psscan untuk cari proses tersembunyi

3. Analisis proses mencurigakan
   → cmdline (lihat argumen command)
   → dlllist (lihat DLL yang dimuat, cari DLL asing)
   → malfind (cari code injection)

4. Cek jaringan
   → netscan (cari koneksi ke IP/domain asing)

5. Cek persistence
   → printkey pada registry Run keys
   → svcscan (service mencurigakan)
   → shimcache / userassist (evidence of execution)

6. Cek command history
   → cmdscan, consoles

7. Ekstrak & analisis file/proses mencurigakan
   → procdump / filescan + dumpfiles
   → strings, file, hash (untuk cek reputasi)

8. Jika butuh credential
   → hashdump, cachedump, lsadump
   → dump proses lsass.exe untuk analisis offline (mimikatz/pypykatz)

9. Jika CTF & mencari flag
   → strings pada seluruh dump
   → filescan untuk cari nama file mencurigakan (flag.txt, secret, dll)
   → cek clipboard (clipboard plugin di Vol2)
   → cek notepad buffer (notepad plugin di Vol2)
```

---

## STUDI KASUS 1: Malware Proses Tersembunyi

### Skenario
Sebuah workstation menunjukkan gejala lambat dan CPU tinggi. Analis mendapat memory dump `infected.raw` (Windows 7 x64) dan diminta mencari proses berbahaya yang mencoba menyembunyikan diri.

### Langkah Investigasi

**1. Tentukan profile:**
```bash
vol.py -f infected.raw imageinfo
# Output: Suggested Profile(s): Win7SP1x64
```

**2. Bandingkan pslist vs psscan:**
```bash
vol.py -f infected.raw --profile=Win7SP1x64 pslist > pslist.txt
vol.py -f infected.raw --profile=Win7SP1x64 psscan > psscan.txt
diff pslist.txt psscan.txt
```
➡️ Ditemukan PID `2884` bernama `svch0st.exe` (perhatikan angka "0" menggantikan huruf "o" — teknik typosquatting) muncul di `psscan` tapi **tidak muncul** di `pslist`. Ini indikasi proses disembunyikan dari daftar normal.

**3. Cek proses induk (parent) dan command line:**
```bash
vol.py -f infected.raw --profile=Win7SP1x64 pstree
vol.py -f infected.raw --profile=Win7SP1x64 cmdline -p 2884
```
➡️ Parent process adalah `explorer.exe`, command line menunjukkan proses dijalankan dari path mencurigakan: `C:\Users\Public\svch0st.exe`.

**4. Cek code injection:**
```bash
vol.py -f infected.raw --profile=Win7SP1x64 malfind -p 2884 -D output/
```
➡️ Ditemukan region memory `PAGE_EXECUTE_READWRITE` yang tidak terhubung ke file mapping — indikasi kuat shellcode/payload di-inject langsung ke memory.

**5. Cek koneksi jaringan proses tersebut:**
```bash
vol.py -f infected.raw --profile=Win7SP1x64 netscan | grep 2884
```
➡️ Ditemukan koneksi `ESTABLISHED` ke IP eksternal pada port `4444` (port default umum untuk reverse shell/C2 seperti Metasploit).

**6. Dump proses untuk analisis lanjut:**
```bash
vol.py -f infected.raw --profile=Win7SP1x64 procdump -p 2884 -D output/
```

### Kesimpulan Kasus
Proses `svch0st.exe` (PID 2884) adalah malware yang:
- Menyamar sebagai proses sistem (`svchost.exe`) dengan typosquatting
- Disembunyikan dari `pslist` (indikasi DKOM/rootkit atau proses baru saja unlink)
- Melakukan code injection (RWX memory tanpa file backing)
- Terhubung ke C2 server via port 4444

**IOC (Indicator of Compromise):**
- Nama file: `svch0st.exe`
- Path: `C:\Users\Public\svch0st.exe`
- Port C2: `4444`

---

## STUDI KASUS 2: Ransomware & Command Line Mencurigakan

### Skenario
Server file sharing mendadak semua filenya berekstensi `.locked`. Tim IR mengambil memory dump `ransomware.raw` sebelum mematikan mesin.

### Langkah Investigasi

**1. Cek command history untuk lihat aktivitas terakhir:**
```bash
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 cmdscan
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 consoles
```
➡️ Ditemukan command mencurigakan:
```
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
```
Ini adalah teknik klasik ransomware untuk **menghapus Volume Shadow Copy** agar korban tidak bisa restore file dari backup lokal.

**2. Cek proses yang menjalankan command tersebut:**
```bash
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 pstree
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 cmdline
```
➡️ Ditemukan proses `svc_update.exe` menjalankan `cmd.exe /c vssadmin delete shadows /all /quiet`.

**3. Cek persistence via registry:**
```bash
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 printkey -K "Microsoft\Windows\CurrentVersion\Run"
```
➡️ Ditemukan entri baru: `Updater = C:\ProgramData\svc_update.exe`.

**4. Cek file yang dibuka proses (mencari ransom note):**
```bash
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 filescan | grep -i "readme\|decrypt\|ransom"
```
➡️ Ditemukan file `!!!DECRYPT_FILES!!!.txt` yang baru dibuat proses tersebut, berisi instruksi pembayaran tebusan.

**5. Ekstrak binary ransomware untuk analisis statis:**
```bash
vol.py -f ransomware.raw --profile=Win2008R2SP1x64 procdump -p <PID> -D output/
strings output/executable.<PID>.exe | grep -i "bitcoin\|onion\|.locked"
```

### Kesimpulan Kasus
- Ransomware masuk sebagai `svc_update.exe`, persistence via Run key registry.
- Melakukan shadow copy deletion untuk mencegah recovery.
- Meninggalkan ransom note di sistem.

**IOC:**
- File: `svc_update.exe`, `!!!DECRYPT_FILES!!!.txt`
- Registry: `HKCU\...\Run\Updater`
- Command: `vssadmin delete shadows /all /quiet`

---

## STUDI KASUS 3: Credential Dumping / Mimikatz

### Skenario
Tim SOC mencurigai adanya credential dumping di sebuah Domain Controller setelah menemukan aktivitas login mencurigakan di akun admin lain. Memory dump `dc_memory.raw` diberikan untuk dianalisis.

### Langkah Investigasi

**1. Cari proses yang mengakses `lsass.exe` (target utama credential dumping):**
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 pslist | grep -i lsass
vol.py -f dc_memory.raw --profile=Win2012R2x64 handles -p <PID_lsass> -t Process
```
➡️ Ditemukan proses `procdump.exe` (bukan tool bawaan Sysinternals resmi, tapi mimikatz yang di-rename) membuka handle ke proses `lsass.exe`.

**2. Cek command line proses mencurigakan:**
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 cmdline -p <PID>
```
➡️ Command line: `procdump.exe -accepteula -ma lsass.exe lsass.dmp` — pola khas dumping LSASS untuk ekstraksi credential offline.

**3. Cek apakah ada mimikatz artefak langsung di memory (string scan):**
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 yarascan -Y "mimikatz" -p <PID>
```
atau menggunakan strings langsung:
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 memdump -p <PID> -D output/
strings output/<PID>.dmp | grep -i "sekurlsa\|mimikatz\|wdigest"
```

**4. Dump hash password lokal sebagai perbandingan:**
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 hashdump
vol.py -f dc_memory.raw --profile=Win2012R2x64 cachedump
vol.py -f dc_memory.raw --profile=Win2012R2x64 lsadump
```

**5. Cek koneksi jaringan proses tersebut (indikasi exfiltrasi):**
```bash
vol.py -f dc_memory.raw --profile=Win2012R2x64 netscan | grep <PID>
```

### Kesimpulan Kasus
- Attacker menggunakan tool credential-dumping yang disamarkan sebagai `procdump.exe` untuk mendump memory `lsass.exe`.
- Hasil dump kemungkinan dieksfiltrasi untuk diproses offline dengan mimikatz/pypykatz guna mengekstrak cleartext password / NTLM hash.

**IOC:**
- Proses: `procdump.exe` (disguised) mengakses `lsass.exe`
- Artefak file: `lsass.dmp`
- String pattern: `sekurlsa`, `wdigest`

---

## STUDI KASUS 4: CTF — Mencari Flag di Memory Dump

### Skenario
Soal CTF forensik memberikan file `challenge.mem` dan meminta peserta menemukan flag yang disembunyikan di memory, kemungkinan terkait aplikasi yang sempat dibuka pelaku (Notepad, browser, atau clipboard).

### Langkah Investigasi

**1. Cek profile & OS:**
```bash
vol.py -f challenge.mem imageinfo
```

**2. Cari string flag langsung di seluruh memory (cara cepat, sering berhasil di CTF):**
```bash
strings challenge.mem | grep -i "flag{"
# atau kalau formatnya beda:
strings challenge.mem | grep -iE "flag\{|CTF\{|FLAG_"
```

**3. Jika tidak ketemu langsung, cek proses yang berjalan:**
```bash
vol.py -f challenge.mem --profile=Win7SP1x64 pslist
```
➡️ Terlihat proses `notepad.exe` sedang berjalan.

**4. Cek isi buffer Notepad (Volatility 2 punya plugin khusus):**
```bash
vol.py -f challenge.mem --profile=Win7SP1x64 notepad
```
➡️ Menampilkan teks yang sedang diketik di Notepad — sering berisi flag langsung di CTF.

**5. Cek clipboard (kadang flag di-copy paste):**
```bash
vol.py -f challenge.mem --profile=Win7SP1x64 clipboard
```

**6. Jika flag disembunyikan dalam file (misal gambar/dokumen yang dibuka), cari via filescan lalu dumpfiles:**
```bash
vol.py -f challenge.mem --profile=Win7SP1x64 filescan | grep -i "secret\|flag\|.png\|.txt"
vol.py -f challenge.mem --profile=Win7SP1x64 dumpfiles -Q <offset> -D output/
```

**7. Jika flag ada di riwayat command / terminal (Linux memory dump):**
```bash
vol3 -f challenge.mem linux.bash
```

**8. Jika flag disembunyikan via steganografi dalam gambar yang di-dump dari VAD:**
```bash
vol.py -f challenge.mem --profile=Win7SP1x64 vaddump -p <PID> -D output/
# lanjut analisis dengan tool stego seperti zsteg, steghide, binwalk
```

### Kesimpulan Kasus
Untuk soal CTF, urutan tercepat biasanya:
1. `strings` mentah dulu (quick win)
2. Cek proses aktif (`pslist`) untuk melihat aplikasi relevan yang dibuka pelaku
3. Manfaatkan plugin spesifik aplikasi (`notepad`, `clipboard`, `iehistory`, `screenshot`)
4. Kalau masih nihil, baru masuk ke `filescan` + `dumpfiles` untuk ekstraksi file mentah

---

## 18. Referensi Cepat (Quick Reference Table)

| Kebutuhan | Perintah Cepat (Vol2) |
|---|---|
| Cek profile | `imageinfo` |
| List proses | `pslist`, `pstree`, `psscan` |
| Proses tersembunyi | bandingkan `pslist` vs `psscan` |
| Command line proses | `cmdline` |
| Koneksi jaringan | `netscan` |
| Code injection | `malfind` |
| Service | `svcscan` |
| Registry Run key (persistence) | `printkey -K "...CurrentVersion\Run"` |
| Riwayat command | `cmdscan`, `consoles` |
| Hash password | `hashdump` |
| Dump proses | `procdump -p <PID> -D <dir>` |
| List file di memory | `filescan` |
| Dump file dari memory | `dumpfiles -Q <offset> -D <dir>` |
| Cari string flag (CTF) | `strings <file> \| grep flag` |
| Notepad buffer (CTF) | `notepad` |
| Clipboard (CTF) | `clipboard` |

---

## Catatan Tambahan untuk Latihan CTF

- Volatility hanyalah **titik masuk**. Setelah menemukan proses/file mencurigakan, biasanya lanjut ke analisis statis (`strings`, `file`, disassembler seperti Ghidra/IDA) atau dinamis (sandbox) di luar Volatility.
- Kombinasikan dengan pengetahuan MBR/GPT (lihat dokumen sebelumnya) jika soal melibatkan **full disk image**, bukan hanya memory dump — kadang satu soal CTF menggabungkan disk forensic + memory forensic dalam satu chain.
- Selalu cek dulu apakah image yang diberikan itu **RAM dump** (butuh Volatility) atau **disk image** (butuh FTK Imager/Autopsy/hex editor) — jangan sampai salah tool dari awal.
- Simpan semua output plugin ke file (`> output.txt`) agar mudah di-`grep` ulang tanpa perlu re-run plugin yang lambat.
