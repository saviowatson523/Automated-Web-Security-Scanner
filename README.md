# 🔒 Automated Cybersecurity Web Scanner

A simple web-based security scanner built with **Python** and **Streamlit** that automatically checks security headers, HTTPS configuration, and CORS settings of any website — displaying results as **Pass**, **Warning**, or **Fail** with actionable recommendations.

---

## 👨‍💻 Author

| Field           | Details                              |
|-----------------|--------------------------------------|
| **Name**        | Savio Watson                         |
| **Institution** | Lachoo Memorial College, Jodhpur     |
| **Submitted**   | 22 October 2026                      |

---

## 📋 Features

- 🔍 **9 automated security checks** on any public URL
- ✅ **Pass / ⚠️ Warning / ❌ Fail** verdicts with explanations
- 📊 **Security score** out of 100 with overall posture rating
- 💡 **Actionable recommendations** for every failed or warned check
- 📥 **Export results** as CSV or JSON
- 🌐 Works entirely in the browser — no specialist tools needed

---

## 🛡️ Security Checks Performed

| # | Check | Risk Addressed |
|---|-------|---------------|
| 1 | HTTPS / SSL | Man-in-the-middle attacks |
| 2 | Strict-Transport-Security (HSTS) | Protocol downgrade attacks |
| 3 | Content-Security-Policy (CSP) | Cross-Site Scripting (XSS) |
| 4 | X-Frame-Options | Clickjacking |
| 5 | X-Content-Type-Options | MIME-type sniffing |
| 6 | Referrer-Policy | Sensitive URL leakage |
| 7 | Permissions-Policy | Unauthorised browser feature access |
| 8 | CORS (Access-Control-Allow-Origin) | Cross-origin data theft |
| 9 | Server / Technology Disclosure | Server fingerprinting |

---

## 🗂️ Project Structure

```
cybersecurity/
├── app.py            # Main application — scanner logic + Streamlit UI
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## ⚙️ Requirements

- Python 3.9 or higher
- Internet connection (to reach target URLs)

---

## 🚀 How to Run

### Step 1 — Navigate to the project folder
```bash
cd d:\cybersecuirty
```

### Step 2 — (Optional) Create a virtual environment
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Launch the app
```bash
python -m streamlit run app.py
```

The app will open automatically in your browser at:
```
http://localhost:8501
```

### Stop the app
Press **Ctrl + C** in the terminal.

---

## 📦 Dependencies

| Package      | Version   | Purpose                        |
|--------------|-----------|-------------------------------|
| `streamlit`  | ≥ 1.35.0  | Browser-based UI framework     |
| `requests`   | ≥ 2.31.0  | HTTP requests to target URLs   |

Install all dependencies with:
```bash
pip install -r requirements.txt
```

---

## 📤 Exporting Results

After a scan completes, two download buttons appear at the bottom of the page:

- **Download as CSV** — opens in Excel or any spreadsheet tool
- **Download as JSON** — structured format for programmatic use

---

## 💡 Usage Example

1. Run the app with `python -m streamlit run app.py`
2. Enter a URL in the input box, e.g. `https://example.com`
3. Click **🔍 Scan Now**
4. Review the Pass/Warning/Fail results
5. Download the report as CSV or JSON

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorised security testing only**.  
Always obtain explicit permission before scanning websites you do not own.  
Unauthorised scanning may violate applicable laws and terms of service.

---

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla HTTP Observatory](https://observatory.mozilla.org/)
- [MDN Web Docs — HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [Requests Library](https://requests.readthedocs.io/)
