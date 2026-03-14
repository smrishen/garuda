# Garuda: Scam Reporting Platform 🦅

Garuda is a decentralized-style scam reporting platform designed to help users report, verify, and stay safe from digital scams. It provides a robust API for tracking various types of fraudulent activities, from phishing to job scams.

## 🚀 Features

- **Anonymous Reporting**: Report scams with descriptions and optional contact details (phone, email, website).
- **Evidence Uploads**: Save screenshots of scam attempts for others to see.
- **Community Verification**: Users can vote on reports as "Experienced" or "Suspicious" to build trust.
- **Advanced Search**: Quickly search for phone numbers, emails, or websites to see if they've been reported before.
- **Safety Tips**: A built-in database of common safety practices and tips to avoid scams.
- **Scam Heatmap Data**: Aggregated statistics on the most common types of scams.

## 🛠️ Tech Stack

- **Backend**: [FastAPI](https://fastapi.tiangolo.com/) (Python)
- **Database**: [SQLite](https://sqlite.org/) (via `sqlite3` and SQL)
- **Validation**: [Pydantic](https://docs.pydantic.dev/)
- **API Runtime**: [Uvicorn](https://www.uvicorn.org/)

## 📋 Installation

### 1. Clone the repository
```bash
git clone https://github.com/diyashetty2256/garuda.git
cd garuda
```

### 2. Set up a Virtual Environment
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize the Database
```bash
python database.py
```

## 🏃 Running the Application

Start the development server:
```bash
uvicorn main:app --reload
```
The API will be available at `http://127.0.0.1:8000`.

- **Interactive API Docs**: `http://127.0.0.1:8000/docs`
- **Alternative Docs (Redoc)**: `http://127.0.0.1:8000/redoc`

## 🗄️ Database Schema

The platform uses two main tables:
- `scams`: Stores report details, screenshot paths, and community votes.
- `safety_tips`: Stores curated safety advice across categories like "OTP Scams" and "Job Scams".

## 🛡️ Security
The project uses **SQL Parameterization** (Placeholders) to prevent SQL injection attacks, ensuring that all user-provided data is treated strictly as text.

## 🤝 Contributing
1. **Fork** the repository.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Open a **Pull Request**.

---
