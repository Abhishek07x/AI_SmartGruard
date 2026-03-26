"""SmartGuard — Gmail SMTP OTP Service"""
import smtplib, ssl, hashlib, secrets, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')

EMAIL    = os.getenv('SMTP_EMAIL','')
APP_PASS = os.getenv('SMTP_APP_PASSWORD','')
DEMO     = os.getenv('SMTP_DEMO_MODE','true').lower() == 'true'

def gen_otp():
    return ''.join(str(secrets.randbelow(10)) for _ in range(6))

def hash_otp(otp):
    return hashlib.sha256(f"sg_{otp}".encode()).hexdigest()

def verify(otp, h):
    return secrets.compare_digest(hash_otp(otp), h)

def send(to, name, otp, risk, signals, ip, country):
    if DEMO or not EMAIL or 'your_gmail' in EMAIL:
        print(f"\n{'='*45}\n[DEMO OTP] To:{to}  OTP:{otp}  Risk:{risk}\n{'='*45}\n")
        return {'ok': True, 'demo_otp': otp}

    rc = '#ef4444' if risk >= 70 else '#f59e0b'
    sigs = ''.join(f'<li style="color:#94a3b8;font-size:13px">⚠ {s}</li>' for s in signals)
    html = f"""<div style="background:#060a12;padding:32px;font-family:Arial">
<div style="max-width:520px;margin:0 auto;background:#0d1220;border-radius:16px;border:1px solid rgba(99,179,237,0.2);overflow:hidden">
<div style="padding:24px 32px;border-bottom:1px solid rgba(99,179,237,0.1)">
  <span style="font-size:20px;font-weight:800;color:#e2e8f0">🛡 Smart<span style="color:#60a5fa">Guard</span></span>
  <span style="float:right;background:{rc}22;border:1px solid {rc}55;color:{rc};padding:3px 10px;border-radius:20px;font-size:11px">RISK {risk}/100</span>
</div>
<div style="padding:28px 32px">
  <p style="color:#94a3b8;font-size:14px">Hello <strong style="color:#e2e8f0">{name}</strong>,</p>
  <p style="color:#64748b;font-size:13px;margin-bottom:22px">Suspicious login detected. Use this OTP to verify:</p>
  <div style="background:#111827;border:2px solid #3b82f6;border-radius:12px;padding:22px;text-align:center">
    <div style="font-size:38px;font-weight:800;letter-spacing:14px;color:#60a5fa;font-family:monospace">{otp}</div>
    <p style="color:#475569;font-size:11px;margin:8px 0 0">Valid <strong style="color:#f59e0b">5 minutes</strong> · Do not share</p>
  </div>
  <div style="background:#1a1510;border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:14px;margin:18px 0">
    <p style="color:#f59e0b;font-size:11px;margin:0 0 8px;font-weight:700">DETECTED SIGNALS</p>
    <ul style="margin:0;padding-left:16px">{sigs}</ul>
    <p style="color:#475569;font-size:11px;margin:8px 0 0">{country} · {ip}</p>
  </div>
  <p style="color:#f87171;font-size:12px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:8px;padding:10px">
    🚨 Not you? Change your password immediately.</p>
</div>
<div style="background:#080c16;padding:14px 32px;border-top:1px solid rgba(99,179,237,0.08)">
  <p style="color:#1e2d40;font-size:11px;margin:0">SmartGuard · Do not reply</p>
</div></div></div>"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"SmartGuard — OTP Verification"
        msg['From']    = f"SmartGuard <{EMAIL}>"
        msg['To']      = to
        msg.attach(MIMEText(f"SmartGuard OTP: {otp} (valid 5 min)", 'plain'))
        msg.attach(MIMEText(html, 'html'))
        ctx = ssl.create_default_context()
        with smtplib.SMTP('smtp.gmail.com', 587) as s:
            s.ehlo(); s.starttls(context=ctx)
            s.login(EMAIL, APP_PASS)
            s.sendmail(EMAIL, to, msg.as_string())
        return {'ok': True}
    except smtplib.SMTPAuthenticationError:
        return {'ok': False, 'err': 'Gmail auth failed — check App Password in .env'}
    except Exception as e:
        return {'ok': False, 'err': str(e)}
