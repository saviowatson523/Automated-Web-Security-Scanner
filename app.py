import streamlit as st
import requests
import json
import csv
import io
from urllib.parse import urlparse
from datetime import datetime

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Web Security Scanner",
    page_icon="🔒",
    layout="wide",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_headers(url: str, timeout: int = 10):
    """Fetch response headers; follow redirects and capture final URL."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=True)
        return resp, resp.headers, resp.url, None
    except requests.exceptions.SSLError as e:
        return None, {}, url, f"SSL Error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, {}, url, f"Connection Error: {e}"
    except requests.exceptions.Timeout:
        return None, {}, url, "Request timed out."
    except Exception as e:
        return None, {}, url, str(e)


# ── Individual checks ─────────────────────────────────────────────────────────

def check_https(original_url: str, final_url: str, ssl_error: str | None) -> dict:
    parsed = urlparse(final_url)
    if ssl_error:
        return {
            "check": "HTTPS / SSL",
            "status": "Fail",
            "detail": ssl_error,
            "recommendation": "Fix the SSL certificate. Ensure it is valid, not self-signed (for production), and not expired.",
        }
    if parsed.scheme == "https":
        return {
            "check": "HTTPS / SSL",
            "status": "Pass",
            "detail": "Site is served over HTTPS.",
            "recommendation": "",
        }
    return {
        "check": "HTTPS / SSL",
        "status": "Fail",
        "detail": "Site is NOT served over HTTPS.",
        "recommendation": "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
    }


def check_hsts(headers: dict) -> dict:
    val = headers.get("Strict-Transport-Security", "")
    if not val:
        return {
            "check": "Strict-Transport-Security (HSTS)",
            "status": "Fail",
            "detail": "Header is missing.",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        }
    max_age = 0
    for part in val.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=")[1])
            except ValueError:
                pass
    if max_age < 31536000:
        return {
            "check": "Strict-Transport-Security (HSTS)",
            "status": "Warning",
            "detail": f"max-age is {max_age}s (recommended ≥ 31536000).",
            "recommendation": "Increase max-age to at least 31536000 (1 year).",
        }
    return {
        "check": "Strict-Transport-Security (HSTS)",
        "status": "Pass",
        "detail": f"Present with max-age={max_age}.",
        "recommendation": "",
    }


def check_csp(headers: dict) -> dict:
    val = headers.get("Content-Security-Policy", "")
    if not val:
        return {
            "check": "Content-Security-Policy (CSP)",
            "status": "Fail",
            "detail": "Header is missing.",
            "recommendation": "Define a CSP to restrict which sources may load scripts, styles, and other resources.",
        }
    if "unsafe-inline" in val or "unsafe-eval" in val:
        return {
            "check": "Content-Security-Policy (CSP)",
            "status": "Warning",
            "detail": "CSP present but uses 'unsafe-inline' or 'unsafe-eval'.",
            "recommendation": "Remove 'unsafe-inline'/'unsafe-eval' to prevent XSS attacks.",
        }
    return {
        "check": "Content-Security-Policy (CSP)",
        "status": "Pass",
        "detail": "CSP header is present and does not allow unsafe directives.",
        "recommendation": "",
    }


def check_x_frame(headers: dict) -> dict:
    val = headers.get("X-Frame-Options", "")
    if not val:
        return {
            "check": "X-Frame-Options",
            "status": "Fail",
            "detail": "Header is missing.",
            "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        }
    if val.upper() in ("DENY", "SAMEORIGIN"):
        return {
            "check": "X-Frame-Options",
            "status": "Pass",
            "detail": f"Set to '{val}'.",
            "recommendation": "",
        }
    return {
        "check": "X-Frame-Options",
        "status": "Warning",
        "detail": f"Unexpected value: '{val}'.",
        "recommendation": "Use DENY or SAMEORIGIN.",
    }


def check_x_content_type(headers: dict) -> dict:
    val = headers.get("X-Content-Type-Options", "")
    if val.lower() == "nosniff":
        return {
            "check": "X-Content-Type-Options",
            "status": "Pass",
            "detail": "Set to 'nosniff'.",
            "recommendation": "",
        }
    return {
        "check": "X-Content-Type-Options",
        "status": "Fail",
        "detail": "Header is missing or not set to 'nosniff'.",
        "recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    }


def check_referrer_policy(headers: dict) -> dict:
    val = headers.get("Referrer-Policy", "")
    safe_values = {
        "no-referrer", "no-referrer-when-downgrade",
        "strict-origin", "strict-origin-when-cross-origin",
    }
    if not val:
        return {
            "check": "Referrer-Policy",
            "status": "Warning",
            "detail": "Header is missing.",
            "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage.",
        }
    if val.lower() in safe_values:
        return {
            "check": "Referrer-Policy",
            "status": "Pass",
            "detail": f"Set to '{val}'.",
            "recommendation": "",
        }
    return {
        "check": "Referrer-Policy",
        "status": "Warning",
        "detail": f"Value '{val}' may leak referrer information.",
        "recommendation": "Use strict-origin-when-cross-origin or stricter.",
        }


def check_permissions_policy(headers: dict) -> dict:
    val = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
    if not val:
        return {
            "check": "Permissions-Policy",
            "status": "Warning",
            "detail": "Header is missing.",
            "recommendation": "Add Permissions-Policy to restrict browser features (camera, microphone, geolocation, etc.).",
        }
    return {
        "check": "Permissions-Policy",
        "status": "Pass",
        "detail": "Header is present.",
        "recommendation": "",
    }


def check_cors(headers: dict) -> dict:
    acao = headers.get("Access-Control-Allow-Origin", "")
    if not acao:
        return {
            "check": "CORS (Access-Control-Allow-Origin)",
            "status": "Pass",
            "detail": "Header not present — CORS is not broadly enabled.",
            "recommendation": "",
        }
    if acao == "*":
        return {
            "check": "CORS (Access-Control-Allow-Origin)",
            "status": "Fail",
            "detail": "Wildcard '*' allows any origin to make cross-origin requests.",
            "recommendation": "Restrict CORS to specific trusted origins instead of '*'.",
        }
    return {
        "check": "CORS (Access-Control-Allow-Origin)",
        "status": "Pass",
        "detail": f"Restricted to: {acao}",
        "recommendation": "",
    }


def check_server_disclosure(headers: dict) -> dict:
    val = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")
    issues = []
    if val:
        issues.append(f"Server: {val}")
    if x_powered:
        issues.append(f"X-Powered-By: {x_powered}")
    if issues:
        return {
            "check": "Server / Technology Disclosure",
            "status": "Warning",
            "detail": "Banners expose server info: " + ", ".join(issues),
            "recommendation": "Remove or obscure Server and X-Powered-By headers to reduce fingerprinting.",
        }
    return {
        "check": "Server / Technology Disclosure",
        "status": "Pass",
        "detail": "No server/technology banners detected.",
        "recommendation": "",
    }


# ── Run all checks ─────────────────────────────────────────────────────────────

def run_scan(url: str):
    url = normalize_url(url)
    resp, headers, final_url, error = fetch_headers(url)

    results = []
    results.append(check_https(url, final_url, error))

    if resp is not None:
        results.append(check_hsts(headers))
        results.append(check_csp(headers))
        results.append(check_x_frame(headers))
        results.append(check_x_content_type(headers))
        results.append(check_referrer_policy(headers))
        results.append(check_permissions_policy(headers))
        results.append(check_cors(headers))
        results.append(check_server_disclosure(headers))

    return results, final_url, resp


# ── Download helpers ───────────────────────────────────────────────────────────

def results_to_csv(results: list, target_url: str) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["check", "status", "detail", "recommendation"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()


def results_to_json(results: list, target_url: str) -> str:
    payload = {
        "scanned_url": target_url,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }
    return json.dumps(payload, indent=2)


# ── UI ─────────────────────────────────────────────────────────────────────────

STATUS_EMOJI = {"Pass": "✅", "Warning": "⚠️", "Fail": "❌"}
STATUS_COLOR = {"Pass": "green", "Warning": "orange", "Fail": "red"}

st.title("🔒 Automated Web Security Scanner")
st.markdown(
    "Enter a URL below to scan its **security headers**, **HTTPS configuration**, and **CORS settings**."
)

with st.form("scan_form"):
    url_input = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Include https:// or the scanner will add it automatically.",
    )
    submitted = st.form_submit_button("🔍 Scan Now", use_container_width=True)

if submitted and url_input.strip():
    with st.spinner("Scanning… this may take a few seconds."):
        results, final_url, resp = run_scan(url_input)

    st.markdown(f"**Scanned URL:** `{final_url}`  |  **Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    st.divider()

    # ── Summary ──────────────────────────────────────────────────────────────
    passes   = sum(1 for r in results if r["status"] == "Pass")
    warnings = sum(1 for r in results if r["status"] == "Warning")
    fails    = sum(1 for r in results if r["status"] == "Fail")
    total    = len(results)
    score    = int((passes / total) * 100) if total else 0

    st.subheader("📊 Security Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Score", f"{score} / 100")
    col2.metric("✅ Pass",    passes)
    col3.metric("⚠️ Warning", warnings)
    col4.metric("❌ Fail",    fails)

    if score >= 80:
        st.success("Overall posture: **Good** — a few tweaks may still help.")
    elif score >= 50:
        st.warning("Overall posture: **Moderate** — several issues need attention.")
    else:
        st.error("Overall posture: **Poor** — critical security headers are missing.")

    st.divider()

    # ── Detailed results ──────────────────────────────────────────────────────
    st.subheader("🔎 Detailed Results")
    for r in results:
        emoji = STATUS_EMOJI[r["status"]]
        color = STATUS_COLOR[r["status"]]
        with st.expander(f"{emoji} {r['check']}  —  **:{color}[{r['status']}]**"):
            st.markdown(f"**Finding:** {r['detail']}")
            if r["recommendation"]:
                st.markdown(f"**Recommendation:** {r['recommendation']}")

    st.divider()

    # ── Downloads ─────────────────────────────────────────────────────────────
    st.subheader("📥 Download Results")
    dl1, dl2 = st.columns(2)
    with dl1:
        st.download_button(
            label="⬇️ Download as CSV",
            data=results_to_csv(results, final_url),
            file_name="scan_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with dl2:
        st.download_button(
            label="⬇️ Download as JSON",
            data=results_to_json(results, final_url),
            file_name="scan_results.json",
            mime="application/json",
            use_container_width=True,
        )

elif submitted:
    st.warning("Please enter a URL before scanning.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption("🔒 Web Security Scanner — for educational and authorised testing purposes only.")
