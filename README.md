# NIDS Network Attack Detector

## 📋 Deskripsi Proyek

NIDS (Network Intrusion Detection System) Network Attack Detector adalah sistem deteksi intrusi jaringan yang menggunakan machine learning untuk menganalisis traffic jaringan dan mendeteksi serangan keamanan. Sistem ini mendukung dua mode operasi: analisis file PCAP dan monitoring real-time.

## 🏗️ Struktur Proyek

```
nids_network_attack_detector/
├── .env                    # Environment variables dan konfigurasi sensitif
├── .venv/                  # Virtual environment Python
├── README.md              # Dokumentasi proyek (file ini)
├── app.py                 # Aplikasi Flask utama - web server dan routing
├── config.py              # Konfigurasi aplikasi dan parameter sistem
├── login_live_monitoring.py # Modul autentikasi untuk live monitoring
├── real_time_alerts.py    # Handler untuk alert real-time dan notifikasi
├── requirements.txt       # Dependencies Python yang diperlukan
│
├── main/                  # Core analysis modules
│   ├── analyst.py         # Machine learning engine dengan RandomForest
│   ├── rules.py           # Rule-based detection engine
│   ├── logs/              # Log files sistem
│   └── reports/           # Generated analysis reports
│
├── static/                # Frontend assets
│   ├── css/
│   │   ├── app.css        # Styling untuk aplikasi
│   │   └── style.css      # Additional styles
│   └── js/
│       ├── app.js         # JavaScript logic utama
│       └── script.js      # Additional scripts
│
├── templates/             # HTML templates (Jinja2)
│   ├── dashboard.html     # Dashboard utama dengan visualisasi
│   ├── guide.html         # Panduan penggunaan sistem
│   └── index.html         # Landing page dan upload interface
│
├── uploads/               # Directory untuk file PCAP yang diupload
│   └── *.pcap/*.pcapng    # File PCAP untuk analisis
│
└── venv/                  # Alternative virtual environment
```

## 🔄 Alur Kerja Sistem

### 1. Mode Analisis File PCAP

```mermaid
graph TD
    A[Upload PCAP File] --> B[File Validation]
    B --> C[Packet Extraction]
    C --> D[Feature Engineering]
    D --> E[ML Analysis - RandomForest]
    E --> F[Rule-based Detection]
    F --> G[Alert Generation]
    G --> H[Dashboard Visualization]
    H --> I[Export Reports]
```

**Langkah-langkah:**

1. **Upload**: User mengupload file PCAP melalui `index.html`
2. **Processing**: `app.py` menerima file dan menyimpan ke `/uploads`
3. **Analysis**: `analyst.py` mengekstrak fitur dan menjalankan ML model
4. **Detection**: `rules.py` menerapkan rule-based detection
5. **Visualization**: Results ditampilkan di `dashboard.html`
6. **Reporting**: Generate PDF reports melalui JavaScript

### 2. Mode Live Monitoring

```mermaid
graph TD
    A[Network Interface] --> B[Real-time Packet Capture]
    B --> C[Stream Processing]
    C --> D[ML Classification]
    D --> E[Rule Matching]
    E --> F[Alert Triggering]
    F --> G[Real-time Dashboard]
    G --> H[Notification System]
```

**Langkah-langkah:**

1. **Authentication**: Login melalui `login_live_monitoring.py`
2. **Capture**: Real-time packet capture dari network interface
3. **Processing**: Stream processing dengan `analyst.py`
4. **Detection**: Real-time rule matching dengan `rules.py`
5. **Alerting**: `real_time_alerts.py` mengirim notifikasi
6. **Monitoring**: Live dashboard updates

## 📁 Penjelasan File Utama

### Core Application Files

| File               | Fungsi                                               | Teknologi       |
| ------------------ | ---------------------------------------------------- | --------------- |
| `app.py`           | Web server utama, routing, file upload handling      | Flask, Werkzeug |
| `config.py`        | Konfigurasi database, ML parameters, system settings | Python Config   |
| `requirements.txt` | Dependencies: Flask, scikit-learn, scapy, pandas     | pip             |

### Analysis Engine

| File              | Fungsi                                                | Teknologi            |
| ----------------- | ----------------------------------------------------- | -------------------- |
| `main/analyst.py` | Machine learning engine dengan RandomForestClassifier | scikit-learn, pandas |
| `main/rules.py`   | Rule-based detection engine, signature matching       | Python, regex        |
| `main/logs/`      | System logs, analysis logs, error tracking            | Logging              |
| `main/reports/`   | Generated PDF reports, analysis summaries             | jsPDF                |

### Frontend Components

| File                       | Fungsi                                   | Teknologi            |
| -------------------------- | ---------------------------------------- | -------------------- |
| `templates/index.html`     | Landing page, file upload interface      | HTML5, Bootstrap     |
| `templates/dashboard.html` | Main dashboard, charts, analysis results | Chart.js, Bootstrap  |
| `templates/guide.html`     | User guide, documentation                | HTML5                |
| `static/css/app.css`       | Main styling, responsive design          | CSS3, Bootstrap      |
| `static/js/app.js`         | Dashboard logic, chart rendering         | JavaScript, Chart.js |

### Monitoring & Security

| File                       | Fungsi                                | Teknologi       |
| -------------------------- | ------------------------------------- | --------------- |
| `login_live_monitoring.py` | Authentication untuk live monitoring  | Flask-Login     |
| `real_time_alerts.py`      | Real-time alert system, notifications | WebSocket, SMTP |

## 🚀 Setup dan Instalasi

### 1. Prerequisites

```bash
# Python 3.8+ required
python --version

# Git untuk cloning
git --version
```

### 2. Clone Repository

```bash
git clone <repository-url>
cd nids_network_attack_detector
```

### 3. Virtual Environment Setup

```bash
# Buat virtual environment
python -m venv .venv

# Aktivasi virtual environment
# Windows:
.venv\Scripts\activate

# Linux/Mac:
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
# Install semua dependencies
pip install -r requirements.txt

# Dependencies utama:
# - Flask (web framework)
# - scikit-learn (machine learning)
# - scapy (packet analysis)
# - pandas (data processing)
# - numpy (numerical computing)
```

### 5. Environment Configuration

```bash
# Buat file .env
cp .env.example .env

# Edit konfigurasi
# .env file:
FLASK_ENV=development
SECRET_KEY=your-secret-key
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=100MB
ML_MODEL_PATH=models/
LOG_LEVEL=INFO
```

### 6. Directory Setup

```bash
# Buat directory yang diperlukan
mkdir -p main/logs
mkdir -p main/reports
mkdir -p uploads
mkdir -p models

# Set permissions (Linux/Mac)
chmod 755 uploads
chmod 755 main/logs
chmod 755 main/reports
```

### 7. Database Setup (jika diperlukan)

```bash
# Initialize database
python -c "from app import init_db; init_db()"
```

## 🏃‍♂️ Menjalankan Aplikasi

### Mode Development

```bash
# Jalankan Flask development server
python app.py

# Atau dengan Flask CLI
export FLASK_APP=app.py
export FLASK_ENV=development
flask run

# Akses aplikasi di: http://localhost:5000
```

### Mode Production

```bash
# Menggunakan Gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Atau dengan uWSGI
pip install uwsgi
uwsgi --http :5000 --wsgi-file app.py --callable app
```

## 📊 Penggunaan Sistem

### 1. Analisis File PCAP

1. **Upload File**:

   - Buka `http://localhost:5000`
   - Pilih file PCAP (.pcap/.pcapng)
   - Klik "Analyze"

2. **View Results**:

   - Dashboard menampilkan hasil analisis
   - Charts menunjukkan distribusi serangan
   - Table menampilkan detail alerts

3. **Export Reports**:
   - Executive Summary (PDF)
   - Detailed Report (PDF)

### 2. Live Monitoring

1. **Login**:

   - Akses `/live-monitoring`
   - Login dengan credentials

2. **Start Monitoring**:

   - Pilih network interface
   - Set detection parameters
   - Start real-time capture

3. **Monitor Alerts**:
   - Real-time dashboard updates
   - Alert notifications
   - Live statistics

## 🔧 Konfigurasi Advanced

### Machine Learning Model

```python
# config.py
ML_CONFIG = {
    'model_type': 'RandomForest',
    'n_estimators': 100,
    'max_depth': 10,
    'random_state': 42,
    'feature_selection': True,
    'cross_validation': True
}
```

### Detection Rules

```python
# rules.py configuration
RULE_CONFIG = {
    'enable_signature_detection': True,
    'enable_anomaly_detection': True,
    'threshold_sensitivity': 'medium',
    'custom_rules_path': 'rules/custom.rules'
}
```

### Network Interface

```python
# Live monitoring configuration
NETWORK_CONFIG = {
    'interface': 'eth0',  # atau 'auto' untuk auto-detect
    'promiscuous_mode': True,
    'buffer_size': 65536,
    'timeout': 1000
}
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied saat Packet Capture**:

   ```bash
   # Linux: Jalankan dengan sudo atau set capabilities
   sudo setcap cap_net_raw+ep /usr/bin/python3
   ```

2. **Module Import Error**:

   ```bash
   # Pastikan virtual environment aktif
   pip install -r requirements.txt
   ```

3. **File Upload Error**:
   ```bash
   # Check upload directory permissions
   chmod 755 uploads/
   ```

### Logs Location

- Application logs: `main/logs/app.log`
- Analysis logs: `main/logs/analysis.log`
- Error logs: `main/logs/error.log`

## 📈 Performance Optimization

### Untuk File PCAP Besar

```python
# config.py
PERFORMANCE_CONFIG = {
    'chunk_size': 10000,  # Process packets in chunks
    'parallel_processing': True,
    'memory_limit': '2GB',
    'cache_results': True
}
```

### Untuk Live Monitoring

```python
# real_time_alerts.py
REALTIME_CONFIG = {
    'buffer_size': 1000,
    'batch_processing': True,
    'alert_throttling': True,
    'max_alerts_per_minute': 100
}
```

## 🔒 Security Considerations

1. **File Upload Security**:

   - Validasi file type dan size
   - Scan untuk malware
   - Isolasi upload directory

2. **Network Monitoring**:

   - Encrypted communication
   - Access control
   - Audit logging

3. **Data Privacy**:
   - Anonymize sensitive data
   - Secure storage
   - Data retention policies

## 🧠 Implementasi Rule-Based Detection

Bagian ini menjelaskan bagaimana mesin deteksi berbasis rule di proyek bekerja dari hulu ke hilir: bagaimana data paket dibentuk, bagaimana rule dievaluasi, dan bagaimana hasilnya dipakai di dashboard.

### Struktur Rule (`main/rules.py`)

Semua rule didefinisikan dalam list `rules_list`. Setiap item memiliki:

- `name`: nama rule/jenis serangan
- `severity`: tingkat keparahan (`high`, `medium`, `low`)
- `description`: penjelasan singkat
- `conditions`: syarat yang harus dipenuhi paket agar dianggap match

Contoh:

```python
rules_list = [
    {
        'name': 'TCP_SYN_Flood',
        'severity': 'high',
        'description': 'Possible TCP SYN Flood Attack detected',
        'conditions': {
            'protocol': 'TCP',
            'flags': 2  # SYN flag
        }
    }
]
```

### Format `conditions` yang didukung

Mesin rule mendukung beberapa bentuk kondisi pada field DataFrame (`protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `packet_length`, `flags`):

- Kesetaraan langsung: `{'protocol': 'TCP'}` atau `{'dst_port': 80}`
- Keanggotaan list/tuple: `{'dst_port': [80, 443]}`
- Operator perbandingan via dict:
  - Lebih besar: `{'packet_length': {'gt': 512}}`
  - Lebih kecil: `{'packet_length': {'lt': 100}}`
  - Rentang: `{'packet_length': {'range': (64, 1514)}}`
  - Tidak sama: `{'protocol': {'neq': 'UDP'}}`

### Alur Analisis (`main/analyst.py`)

1. `pcap_to_dataframe(file_path)` mengubah PCAP menjadi DataFrame dengan kolom: `timestamp`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `packet_length`, `flags`.
   - `protocol` diisi `TCP`/`UDP`/`ICMP` bila layer terkait ada, atau `Unknown` bila tidak terdeteksi.
2. `analyze_pcap(file_path)` menginisialisasi `analysis_results`:
   - `alerts`: list alert (maks 10 alert pertama per rule untuk performa)
   - `summary.total_packets`: jumlah baris DataFrame
   - `summary.protocols`: hasil `df['protocol'].value_counts().to_dict()` (jumlah paket per protokol)
   - `summary.attack_types`: dictionary kosong yang akan diisi jumlah paket yang match tiap rule
3. Untuk setiap rule di `rules_list`:
   - Buat `mask = True` untuk seluruh baris
   - Terapkan setiap `conditions` sesuai format di atas secara vektor (pandas)
   - `matches = df[mask]` berisi semua paket yang memenuhi rule
   - Tambahkan alert untuk `matches.head(10)` dengan field penting dari paket (src/dst IP/port, protocol, timestamp)
   - Update ringkasan:
     - `summary.total_alerts += len(matches)`
     - `summary.attack_types[rule_name] = summary.attack_types.get(rule_name, 0) + len(matches)`

### Sumber Data untuk Dashboard

- Attack Types Distribution: memakai `summary.attack_types` → jumlah paket yang cocok terhadap masing-masing rule.
- Protocol Distribution: memakai `summary.protocols` → jumlah paket per protokol dari seluruh PCAP.
- Severity Levels, Top Source/Destination IPs: dihitung dari `alerts` yang ditampilkan (subset dari paket match).

### Catatan Penting

- Batas alert: maksimal 10 alert per rule ditampilkan untuk performa. Angka pada grafik Attack Types bisa lebih besar karena merepresentasikan total paket match, bukan jumlah alert yang ditampilkan.
- Menambah rule baru: cukup tambahkan entri baru ke `rules_list`. Jika ada paket yang match, label rule akan muncul otomatis di grafik Attack Types.
- Field yang umum dipakai pada `conditions`: `protocol`, `dst_port`, `src_port`, `packet_length`, `flags`. Anda dapat mengkombinasikan equality, keanggotaan list, dan operator perbandingan.

### Contoh Rule ICS Tambahan

```python
{
  'name': 'Modbus_TCP_Suspect',
  'severity': 'medium',
  'description': 'Modbus/TCP traffic on default port (ICS) detected',
  'conditions': {'protocol': 'TCP', 'dst_port': 502}
}
```

### Cara Uji Cepat

1. Upload file PCAP dari halaman utama (`templates/index.html`).
2. Setelah analisis selesai, Anda akan diarahkan ke dashboard.
3. Verifikasi:
   - Panel “Attack Types (Packet Count)” menunjukkan label rule yang match.
   - Panel “Protocol Distribution” menunjukkan jumlah paket per protokol.
   - Perbedaan antara jumlah alert tabel dan grafik Attack Types sesuai batas 10 alert per rule.

## 📚 Dependencies Detail

```txt
# Core Framework
Flask==2.3.3
Werkzeug==2.3.7

# Machine Learning
scikit-learn==1.3.0
pandas==2.0.3
numpy==1.24.3

# Network Analysis
scapy==2.5.0
networkx==3.1

# Data Processing
sqlalchemy==2.0.20
psycopg2-binary==2.9.7

# Utilities
requests==2.31.0
python-dotenv==1.0.0
```

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

MIT License - see LICENSE file for details.

---

**Developed by Desta Fauzi H**
**Version 1.0.0**

---

## 🟣 Setup & Migration Guide (Windows)

Panduan lengkap untuk memindahkan proyek ke device lain dan men‑setup hingga siap digunakan. Fokus pada Windows 10/11; Linux/Mac serupa dengan perbedaan kecil pada perintah shell.

### Prasyarat
- Python: rekomendasi `3.12` (kompatibel wheel banyak paket). `3.13` juga bisa dipakai—ketergantungan `netifaces` sudah dihapus dan diganti `psutil`.
- Npcap: diperlukan untuk packet capture di Windows. Unduh dari `https://npcap.com` dan centang opsi “WinPcap API-compatible mode”.
- Jalankan terminal sebagai Administrator saat menjalankan server dan saat capture.
- Opsi Database:
  - PostgreSQL (disarankan untuk histori dan filter kuat).
  - Alternatif MySQL (Laragon) jika ingin memakai bawaan Laragon.

### Memindahkan Proyek ke Device Baru
- Salin folder proyek `nids_network_attack_detector/` ke device baru.
- Jangan bawa `venv/` atau `.venv/` jika ukurannya besar; buat venv baru di device target.
- Pastikan file `.env` berisi konfigurasi yang sesuai untuk device baru (lihat bagian Konfigurasi `.env`).
- Jika memakai database, migrasikan data dengan alat bawaan:
  - PostgreSQL: `pg_dump -U <user> -d nids_db -f backup.sql` lalu `psql -U <user> -d nids_db -f backup.sql`.
  - MySQL: `mysqldump -u <user> -p nids_db > backup.sql` lalu `mysql -u <user> -p nids_db < backup.sql`.

### Instalasi Langkah‑demi‑Langkah (Windows)
1. Masuk ke folder proyek: `cd nids_network_attack_detector`
2. Buat dan aktifkan virtual environment:
   - Buat venv (rekomendasi Python 3.12):
     - `py -3.12 -m venv .venv`
   - Aktifkan: `.\.venv\Scripts\activate`
3. Perbarui pip/setuptools/wheel: `pip install -U pip setuptools wheel`
4. Install dependencies: `pip install -r requirements.txt`
   - Catatan: `netifaces` telah dihapus; deteksi interface memakai `psutil`.
5. Install Npcap dan restart jika diminta.
6. Siapkan database (pilih salah satu):
   - PostgreSQL (disarankan):
     - Install PostgreSQL untuk Windows atau pakai Docker.
     - Buat DB dan user:
       - `psql -U postgres` lalu:
         - `CREATE DATABASE nids_db;`
         - `CREATE USER nids_user WITH PASSWORD 'nids_password';`
         - `GRANT ALL PRIVILEGES ON DATABASE nids_db TO nids_user;`
     - Set `DATABASE_URL=postgresql+psycopg2://nids_user:nids_password@localhost:5432/nids_db` di `.env`.
   - MySQL (Laragon):
     - Start MySQL dari Laragon (`Start All`).
     - Buat DB dan user:
       - `mysql -u root -p` → `CREATE DATABASE nids_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
       - `CREATE USER 'nids_user'@'localhost' IDENTIFIED BY 'nids_password';`
       - `GRANT ALL PRIVILEGES ON nids_db.* TO 'nids_user'@'localhost';`
       - `FLUSH PRIVILEGES;`
     - Install driver: `pip install pymysql`
     - Set `DATABASE_URL=mysql+pymysql://nids_user:nids_password@127.0.0.1:3306/nids_db` di `.env`.

### Konfigurasi `.env`
Tambahkan file `.env` di root proyek (contoh variabel penting):

```
FLASK_ENV=development
SECRET_KEY=change-this-secret
UPLOAD_FOLDER=uploads
LOG_LEVEL=INFO
DATABASE_URL=postgresql+psycopg2://nids_user:nids_password@localhost:5432/nids_db
```

Jika tidak memakai database, aplikasi tetap jalan untuk live dashboard; historis log akan terbatas pada in‑memory buffer.

### Inisialisasi Database
- Tabel dibuat otomatis saat aplikasi start via helper `init_db()` di `db.py`.
- Opsional jalankan manual:
  - `python -c "from db import init_db; init_db()"`

### Menjalankan Aplikasi
1. Buka PowerShell sebagai Administrator.
2. Aktifkan venv: `.\.venv\Scripts\activate`
3. Jalankan: `python app.py`
4. Buka `http://127.0.0.1:5000/`.

### Menggunakan Aplikasi
- Analisis PCAP:
  - Dari halaman utama, upload file `.pcap`/`.pcapng` → lihat hasil di dashboard.
- Live Monitoring:
  - Masuk ke halaman live dashboard (menu “Live Monitoring”).
  - Start monitoring via tombol atau endpoint `POST /api/monitoring/start` dengan JSON `{"interface": "Ethernet"}`. Jika kosong, sistem auto‑detect interface aktif.
  - Status: `GET /api/monitoring/status`.
  - Logs realtime (buffer 50 item): `GET /api/monitoring/logs`.
  - Alerts live via SSE: `GET /api/monitoring/alerts/stream`.
  - Histori berbasis DB: `GET /api/history/logs` dan `GET /api/history/alerts`.
    - Filter `limit`, `src_ip`, `protocol`, `type`, `severity`, `since` tersedia sebagai query params.
  - Stop monitoring: `POST /api/monitoring/stop`.

### Catatan Teknis Penting
- Buffer realtime log dibatasi 50 item untuk menjaga performa UI dan menghindari “stuck” pada waktu lama.
- Penulisan ke database dilakukan secara asinkron di thread terpisah agar jalur live tidak terblokir I/O.
- SSE untuk alerts aktif; jika ingin SSE untuk logs, dapat ditambahkan endpoint tambahan (`/api/monitoring/logs/stream`).
- Deteksi interface menggunakan `psutil`; tidak membutuhkan `netifaces`.

### Troubleshooting Cepat
- Packet capture tidak bergerak (jam UI tidak maju):
  - Pastikan Npcap terinstal dan server dijalankan sebagai Administrator.
  - Periksa nama interface: di Windows sering `Ethernet` atau `Wi‑Fi`. Gunakan `POST /api/monitoring/start` dengan `{"interface":"<nama>"}`.
  - Cek `network_monitor.log` untuk error seperti permission/driver.
- `pip install` gagal:
  - Gunakan Python 3.12 untuk kompatibilitas wheel lebih baik.
  - Pastikan `pip install -U pip setuptools wheel` sebelum install.
- PostgreSQL tidak terkoneksi:
  - Periksa `DATABASE_URL` dan bahwa service PostgreSQL berjalan (`services.msc` atau Docker container).
- MySQL Laragon:
  - Pastikan `pymysql` terinstal dan kredensial sesuai dengan user/DB yang dibuat.

### Migrasi ke Perangkat Lain (Ringkas)
- Backup DB (opsional) → restore di device baru.
- Copy folder proyek → buat venv baru → install requirements.
- Set `.env` di device baru → jalankan `python app.py` sebagai Administrator.
- Verifikasi:
  - `GET /api/monitoring/status` → pastikan `is_monitoring=true` saat capture berjalan.
  - `GET /api/monitoring/logs` → terlihat maksimal 50 entri terbaru yang bergerak.
  - SSE alerts muncul di live dashboard saat ada event.

### Keamanan & Privasi
- Jangan commit `.env` ke repository publik.
- Gunakan `SECRET_KEY` unik per device.
- Batasi akses ke endpoint kontrol (`/api/monitoring/start/stop`) dengan autentikasi peran “control”.

Jika Anda menginginkan otomatisasi setup (script PowerShell untuk membuat venv, install paket, dan menyiapkan `.env` sesuai pilihan database), beri tahu saya—saya bisa menambahkan skrip `tools/setup.ps1` untuk mempercepat proses.
