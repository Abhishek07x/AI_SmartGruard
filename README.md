# 🛡 SmartGuard — Adaptive Authentication Engine

<div align="center">

![SmartGuard Banner](https://img.shields.io/badge/SmartGuard-v4.0-3b82f6?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**An AI-powered Risk-Based Authentication system trained on the Kaggle RBA Dataset (4M+ real login events).**  
Automatically detects suspicious logins, triggers OTP verification, or blocks threats — in real time.

[Features](#-features) · [Installation](#-installation) · [How It Works](#-how-it-works) · [API Reference](#-api-reference) · [Configuration](#️-configuration-reference)

</div>

---

## 📌 What is SmartGuard?

SmartGuard is a **Risk-Based Authentication (RBA)** engine that evaluates every login attempt using a machine learning model trained on real-world attack data. Instead of treating all logins the same, it assigns a **risk score (0–100)** and responds adaptively:

| Risk Score | Decision | Action |
|---|---|---|
| **0 – 34** | ✅ ALLOW | Direct access granted |
| **35 – 69** | 🔐 OTP | Email OTP sent for step-up verification |
| **70 – 100** | 🚫 BLOCK | Access denied, threat logged |

---

## ✨ Features

### 🤖 Machine Learning Core
- **GradientBoostingClassifier** trained on Kaggle's RBA Dataset (60,000–80,000 events)
- **AUC-ROC: 0.9974** — near-perfect attack detection
- 7 engineered features: Country, Device, Browser, OS, Network RTT, Attack IP Flag, Hour of Day
- Supports real Kaggle data or auto-generated synthetic fallback

### 📍 Live Location Detection (2-Layer)
- **Layer 1 — Browser GPS:** Uses `navigator.geolocation` + OpenStreetMap reverse geocoding
- **Layer 2 — IP Geolocation:** Server-side fallback via `ip-api.com` (no API key needed)
- Country dropdown auto-fills from detected location
- Location stored with every login event (city, region, lat/lon, source)

### 🔐 Complete OTP Flow
- 6-digit OTP sent via Gmail SMTP (or shown in console in demo mode)
- 5-minute countdown timer with visual expiry warning
- Max 3 attempts before session invalidation
- Resend functionality with rate limiting
- OTP outcomes tracked in DB: `verified` / `failed` / `pending`

### 🚫 Threat Blocking
- Dedicated block page with full threat signal breakdown
- Severity levels: CRITICAL / HIGH / MEDIUM / LOW
- Signals detected: Known Attack IP, Impossible Travel, High-Risk Country, Multiple Failed Logins, Bot-like Typing Speed, High RTT, Off-hours Access

### 📋 Full Login History
- All events stored in SQLite — no data loss on restart
- Filterable by decision: All / Allowed / OTP / Blocked
- Paginated (50 per page)
- Columns: Location (with source icon 📍/🌐/⌨), Device, Browser, OS, Risk Score, Outcome, RTT, Timestamp

### 🔬 Analysis & Conclusions Tab
- Auto-generated security conclusion in plain English
- Risk distribution chart (Low / Medium / High)
- Login activity by hour (peak attack time highlighted)
- Top threat signals ranking
- OTP effectiveness metrics (verified vs failed)
- Top attack-origin countries
- Model performance summary

### 🛡 Security
- **PBKDF2** password hashing (200,000 iterations, unique salt)
- **JWT** authentication with configurable expiry
- **GDPR-compliant** IP masking (`x.x.xxx.xxx`) and UUID5-anonymized user IDs
- Rate limiting on all sensitive endpoints
- No plaintext credentials stored anywhere

---

## 🗂 Project Structure

```
SmartGuard/
├── backend/
│   ├── app.py              # Flask API — all endpoints
│   └── db.py               # SQLite database layer (PBKDF2, full history)
├── frontend/
│   └── index.html          # Single-file UI (no framework needed)
├── models/
│   ├── model.pkl           # Trained GradientBoosting model
│   ├── le_country.pkl      # Label encoder — Country
│   ├── le_device.pkl       # Label encoder — Device
│   ├── le_browser.pkl      # Label encoder — Browser
│   ├── le_os.pkl           # Label encoder — OS
│   ├── schema.json         # Feature schema + model metadata
│   └── importances.json    # Feature importance scores
├── scripts/
│   ├── dataset.py          # Dataset generator (Kaggle or synthetic)
│   └── train.py            # Model training script
├── data/
│   ├── smartguard.db       # SQLite database (auto-created on first run)
│   └── smartguard_dataset.csv  # Training data (auto-generated)
├── .env                    # Your configuration (copy from .env.example)
├── .env.example            # Config template
└── start.sh                # One-click startup script
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourusername/smartguard.git
cd smartguard
```

### Step 2 — Configure environment

```bash
cp .env.example .env
```

Open `.env` and set your values:

```env
# Required
JWT_SECRET=your_random_secret_key_here
ADMIN_SETUP_KEY=YourStrongAdminPassword123

# Optional — Gmail OTP (leave defaults for demo/console mode)
SMTP_EMAIL=your_gmail@gmail.com
SMTP_APP_PASSWORD=your_16_char_app_password
SMTP_DEMO_MODE=true          # Set to false to send real emails

# Optional — Real Kaggle dataset
KAGGLE_USERNAME=your_kaggle_username
KAGGLE_KEY=your_kaggle_api_key
```

### Step 3 — One-click start

```bash
bash start.sh
```

This automatically:
1. Installs all Python dependencies
2. Generates the training dataset (synthetic or Kaggle)
3. Trains the ML model
4. Starts the Flask backend on port 5050

### Step 4 — Open the frontend

Open `frontend/index.html` directly in your browser — **no web server needed.**

---

## 🔧 Manual Setup (Alternative)

```bash
# Install dependencies
pip install flask flask-cors scikit-learn pandas numpy python-dotenv

# Generate dataset
python3 scripts/dataset.py

# Train model
python3 scripts/train.py

# Start backend
python3 backend/app.py
```

---

## 🎮 Usage

### Default Credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `SmartGuard_Setup_2024` (or your `ADMIN_SETUP_KEY`) |
| User | any email | any password |

> ⚠️ **Change the admin password immediately after first login via Dashboard → Change PW.**

### Try These Scenarios

**Scenario 1 — Normal Login → ALLOW**
- Country: United States · Device: Desktop · RTT: ~200ms
- Expected: ✅ Direct access granted

**Scenario 2 — Suspicious Login → OTP**
- Country: Russia or China · Device: Mobile
- Expected: 🔐 OTP challenge (check console in demo mode)

**Scenario 3 — High-Risk Login → BLOCK**
- Country: North Korea · Attack IP: Yes · Failed Attempts: 5+
- Expected: 🚫 Block page with detailed threat signals

---

## 🧠 How It Works

```
User Login Attempt
       │
       ▼
┌─────────────────────────────────┐
│   1. Live Location Detection    │
│   GPS → IP Geolocation → Manual │
└─────────────────┬───────────────┘
                  │
                  ▼
┌─────────────────────────────────┐
│   2. Feature Extraction         │
│   Country · Device · Browser    │
│   OS · RTT · Attack IP · Hour   │
└─────────────────┬───────────────┘
                  │
                  ▼
┌─────────────────────────────────┐
│   3. ML Risk Scoring            │
│   GradientBoostingClassifier    │
│   AUC-ROC: 0.9974               │
│   + Rule-based signal boosters  │
└─────────────────┬───────────────┘
                  │
          ┌───────┴────────┐
          │   Risk Score   │
          └───────┬────────┘
     ┌────────────┼────────────┐
     │            │            │
  0–34         35–69        70–100
     │            │            │
     ▼            ▼            ▼
  ALLOW         OTP          BLOCK
  Direct     Send Email    Log & Alert
  Access    Verification
```

### Feature Importance (trained model)

| Feature | Importance |
|---|---|
| 🔴 Attack IP Flag | 54.3% |
| 🟠 Network RTT | 39.7% |
| 🟡 Country | 5.2% |
| 🟢 Hour of Day | 0.6% |
| 🔵 OS | 0.2% |
| 🔵 Device Type | 0.1% |
| 🔵 Browser | 0.1% |

---

## 📡 API Reference

### Public Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check + model status |
| `GET/POST` | `/api/location` | IP geolocation for current client |
| `POST` | `/api/auth/login` | Admin login → returns JWT token |
| `POST` | `/api/user/check` | Evaluate login risk (main endpoint) |
| `POST` | `/api/user/verify-otp` | Verify 6-digit OTP |
| `POST` | `/api/user/resend-otp` | Resend OTP to email |

### Admin Endpoints (JWT Bearer Token Required)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/dashboard` | Overview stats + recent events |
| `GET` | `/api/admin/history` | Full paginated login history |
| `GET` | `/api/admin/analysis` | Aggregated analysis & metrics |
| `GET` | `/api/admin/features` | Model feature importances |
| `POST` | `/api/admin/evaluate` | Manual risk evaluation |
| `POST` | `/api/admin/simulate` | Simulate N random login events |
| `POST` | `/api/admin/change-password` | Change admin password |

### Example: Check Login Risk

```bash
curl -X POST http://localhost:5050/api/user/check \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "country": "Russia",
    "device": "Mobile",
    "browser": "Chrome",
    "os": "Android",
    "rtt_ms": 12000,
    "is_attack_ip": 1,
    "failed_attempts": 5
  }'
```

**Response:**
```json
{
  "decision": "BLOCK",
  "risk": 87,
  "label": "🚫 Block & Alert",
  "color": "#ef4444",
  "ml_prob": 0.8234,
  "factors": [
    {"s": "Known Attack IP",       "sev": "critical", "d": "IP flagged in threat database"},
    {"s": "High-Risk Country",     "sev": "high",     "d": "Login from Russia"},
    {"s": "Multiple Failed Logins","sev": "high",     "d": "5 failed attempts"}
  ],
  "masked_ip": "103.24.xxx.xxx",
  "timestamp": "2024-03-27T14:32:11"
}
```

---

## ⚙️ Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | auto-random | Secret key for signing JWT tokens |
| `ADMIN_SETUP_KEY` | `SmartGuard_Setup_2024` | Initial admin password on first run |
| `PORT` | `5050` | Backend server port |
| `SMTP_EMAIL` | — | Gmail address for sending OTP emails |
| `SMTP_APP_PASSWORD` | — | Gmail App Password (16 characters) |
| `SMTP_DEMO_MODE` | `true` | `true` = show OTP in console, `false` = send real email |
| `KAGGLE_USERNAME` | — | Your Kaggle username (for real dataset) |
| `KAGGLE_KEY` | — | Your Kaggle API key |

### Setting Up Gmail OTP 

1. Enable **2-Factor Authentication** on your Google account
2. Go to **Google Account → Security → App Passwords**
3. Generate a new App Password for "Mail"
4. Add to `.env`:

```env
SMTP_EMAIL=youremail@gmail.com
SMTP_APP_PASSWORD=xxxx xxxx xxxx xxxx
SMTP_DEMO_MODE=false
```

---

## 📊 Dataset

SmartGuard uses the **Kaggle RBA Dataset** — 4M+ real login events with labeled account takeover attempts (IEEE 2021).

**Without Kaggle credentials**, the system auto-generates a 60,000-event synthetic dataset that is statistically faithful to the paper's distributions:
- 10% attack rate (matching published RBA paper)
- Realistic country, device, browser, and RTT distributions
- Properly labeled attack events

**To use real Kaggle data**, add your credentials to `.env`, then:

```bash
python3 scripts/dataset.py   # Downloads dasgroup/rba-dataset
python3 scripts/train.py     # Retrains model on real data
```

---

## 🔒 Security Design

| Concern | Implementation |
|---|---|
| Password storage | PBKDF2-HMAC-SHA256, 200,000 iterations, unique random salt per user |
| Session tokens | HMAC-SHA256 JWT, configurable expiry, JTI nonce per token |
| OTP security | SHA-256 hashed, `secrets.compare_digest` (timing-safe comparison) |
| IP logging | GDPR-masked as `x.x.xxx.xxx` — raw IPs never persisted |
| User IDs | UUID5 anonymization — original emails never stored |
| Rate limiting | Per-IP sliding window on all sensitive endpoints |
| Brute force | 3 OTP attempts max; 0.5s artificial delay on failed admin auth |

---

## 🧪 Simulation & Testing

From **Admin Dashboard → Evaluator** tab:

1. **Manual Evaluation** — Set any combination of country, device, RTT, attack flags and see instant ML decision with factor breakdown
2. **Simulate 25 Events** — Auto-generates mixed normal/attack traffic, populates history and analysis tabs

---

## 📈 Roadmap

- [ ] WebSocket live event feed on dashboard
- [ ] Email alert to admin on every BLOCK event
- [ ] IP blocklist management UI
- [ ] Multi-admin support with roles
- [ ] Export login history as CSV / PDF
- [ ] Docker + docker-compose setup
- [ ] Geo-map visualization of attack origins
- [ ] TOTP (Authenticator App) support alongside email OTP

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

```bash
# Fork the repo, then:
git checkout -b feature/your-feature-name
git commit -m "feat: add your feature"
git push origin feature/your-feature-name
# Open a Pull Request
```

---



---

## 🙏 Acknowledgements

- **Niels Vanderloock** — Kaggle RBA Dataset (IEEE 2021 paper on Risk-Based Authentication)
- **Scikit-learn** — GradientBoostingClassifier implementation
- **ip-api.com** — Free IP geolocation API (no key required)
- **OpenStreetMap / Nominatim** — Free reverse geocoding for GPS coordinates

---

<div align="center">

**SmartGuard v4.0** · Built with Python, Flask & Scikit-Learn  
*Protecting every login with AI-powered risk analysis.*

</div>
