"""Optional HTML + plain-text email notifications for KVNRadar.

Only SMTP configuration comes from environment. Existing outbox messages remain
unchanged so Telegram and Compass retain their current payloads.
"""
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from html import escape
import os
import re
import smtplib
import ssl
from urllib.parse import urlsplit

_VERSION = '0.6.6'
_SUCCESS = ('OK_FULL', 'OK_TCP', 'OK_DNS', 'OK_ICMP', 'OK_TLS', 'OK_HTTP', 'OK_TRACE')


def _address(text):
    text = str(text or '').strip()
    if '\n' in text or '\r' in text or len(text) > 254:
        raise ValueError('Invalid SMTP email address')
    name, address = parseaddr(text)
    if not address or address != text or not re.fullmatch(r'[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', address):
        raise ValueError('Invalid SMTP email address')
    return address


def settings():
    host = os.getenv('SMTP_HOST', '').strip()
    sender = os.getenv('SMTP_FROM', '').strip()
    recipients = os.getenv('SMTP_TO', '').strip()
    if not host or not sender or not recipients:
        return None
    if not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host) or '@' in host or '/' in host:
        raise ValueError('Invalid SMTP_HOST')
    try:
        port = int(os.getenv('SMTP_PORT', '587'))
        timeout = int(os.getenv('SMTP_TIMEOUT', '15'))
    except ValueError as exc:
        raise ValueError('Invalid SMTP port or timeout') from exc
    if not 1 <= port <= 65535 or not 1 <= timeout <= 30:
        raise ValueError('SMTP port or timeout out of range')
    mode = os.getenv('SMTP_TLS_MODE', 'starttls').strip().lower()
    if mode not in ('starttls', 'ssl'):
        raise ValueError('SMTP_TLS_MODE must be starttls or ssl; plaintext SMTP is not supported')
    to = [_address(s) for s in re.split(r'[,;]', recipients) if s.strip()]
    if not 1 <= len(to) <= 20 or len(set(to)) != len(to):
        raise ValueError('SMTP_TO must contain 1-20 unique email addresses')
    user = os.getenv('SMTP_USERNAME', '').strip()
    password = os.getenv('SMTP_PASSWORD', '')
    if bool(user) != bool(password):
        raise ValueError('SMTP_USERNAME and SMTP_PASSWORD must both be set, or both be empty')
    return {'host': host, 'port': port, 'timeout': timeout, 'mode': mode,
            'from': _address(sender), 'to': to, 'user': user, 'password': password}


def enabled():
    return bool(os.getenv('SMTP_HOST', '').strip() and os.getenv('SMTP_FROM', '').strip()
                and os.getenv('SMTP_TO', '').strip())


def _fields(message):
    lines = str(message or '').splitlines()
    headline = lines[0][:180] if lines else 'KVNRadar notification'
    data = {}
    extras = []
    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            if re.fullmatch(r'[\w /-]{1,40}', key):
                data[key] = value[:1000]
                continue
        if line.strip():
            extras.append(line[:300])
    return headline, data, extras


def _type(headline, fields):
    upper = headline.upper()
    status = fields.get('Status', '').upper()
    if 'RECOVERED' in upper or status.startswith(_SUCCESS):
        return 'recovered', 'Service recovered', 'Resolved', '#1ab96b', '#e5f8ed'
    if 'BLOCKLIST' in upper:
        return 'blocklist', 'Blocklist change detected', 'Notice', '#dc8a19', '#fff3df'
    return 'incident', 'Monitoring alert', 'Attention', '#e04448', '#fdebec'


def _dashboard_link():
    raw = os.getenv('SMTP_DASHBOARD_URL', '').strip()
    if not raw:
        return ''
    try:
        x = urlsplit(raw)
        if x.scheme != 'https' or not x.hostname or x.username or x.password or x.query or x.path not in ('', '/'):
            return ''
        if x.fragment and x.fragment not in ('overview', 'history', 'hosts', 'blocklists'):
            return ''
        port = ':' + str(x.port) if x.port else ''
        return f'https://{x.hostname}{port}/#{x.fragment or "overview"}'
    except ValueError:
        return ''


def render(message):
    headline, fields, extras = _fields(message)
    kind, title, badge, accent, pale = _type(headline, fields)
    target = fields.get('Target') or fields.get('Host') or fields.get('Resource') or 'Infrastructure event'
    items = [('Monitor', target)]
    for key in ('Agent', 'Status', 'Bytes', 'HTTP', 'Time', 'Match', 'Matches', 'Error'):
        val = fields.get(key, '').strip()
        if val and val not in ('None', 'none'):
            items.append(({'Time': 'Observed at', 'HTTP': 'HTTP response'}.get(key, key), val))
    if extras:
        items.append(('Details', ' · '.join(extras)[:900]))
    if len(items) == 1:
        items.append(('Event', headline))
    rows = ''.join(
        '<tr><td style="padding:13px 0 5px;color:#748094;font-size:12px;line-height:18px;vertical-align:top;width:126px;">'
        + escape(label) + '</td><td style="padding:13px 0 5px;color:#182431;font-size:14px;line-height:20px;'
        'font-weight:600;overflow-wrap:anywhere;border-bottom:1px solid #e7ecf0;">'
        + escape(value) + '</td></tr>'
        for label, value in items
    )
    link = _dashboard_link()
    action = ('<tr><td style="padding:12px 28px 30px;text-align:center">'
              '<a href="' + escape(link, quote=True) + '" style="display:inline-block;background:#19ba69;color:#fff;'
              'padding:13px 22px;border-radius:9px;font-size:14px;font-weight:700;text-decoration:none;">'
              'Open KVNRadar dashboard</a></td></tr>') if link else ''
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title></head>
<body style="margin:0;padding:0;background:#f3f6f5;font-family:Arial,Helvetica,sans-serif;color:#182431;">
<table role="presentation" cellspacing="0" cellpadding="0" width="100%" style="background:#f3f6f5;"><tr><td align="center" style="padding:32px 14px;">
<table role="presentation" cellspacing="0" cellpadding="0" width="100%" style="max-width:620px;border-collapse:separate;">
<tr><td style="background:#121b27;padding:29px 30px;border-radius:16px 16px 0 0;">
<table role="presentation" width="100%"><tr><td style="color:#fff;font-size:23px;font-weight:800;letter-spacing:-.5px;"> <span style="color:#26cb78;">●</span> KVNRadar</td><td align="right" style="font-size:11px;color:#bdc9d7;">INFRASTRUCTURE MONITOR</td></tr></table>
<div style="color:#fff;font-size:28px;font-weight:700;line-height:1.25;margin-top:30px;">{escape(title)}</div>
<div style="font-size:14px;color:#d0dae5;margin-top:9px;overflow-wrap:anywhere;">{escape(target)}</div>
</td></tr>
<tr><td style="background:white;padding:29px 30px 8px;border:1px solid #e2e8ed;border-top:none;">
<span style="display:inline-block;background:{pale};color:{accent};font-size:12px;font-weight:800;letter-spacing:.4px;padding:9px 14px;border-radius:18px;">{escape(badge.upper())}</span>
<p style="font-size:14px;color:#5e6d7b;line-height:1.65;margin:20px 0 14px;">{escape('The monitor has recovered. The latest incident is resolved.' if kind=='recovered' else 'A blocklist result has changed. Review the current state in KVNRadar.' if kind=='blocklist' else 'KVNRadar detected a change requiring your attention.')}</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f8fafb;border-radius:12px;padding:7px 16px 16px;border-collapse:separate;">{rows}</table>
<p style="font-size:12px;color:#798695;line-height:1.6;margin:18px 0;">This notification was generated automatically by KVNRadar.</p>
</td></tr>
{action}
<tr><td style="background:#f3f6f5;text-align:center;padding:20px;color:#83909b;font-size:11px;">KVNRadar · Self-hosted infrastructure monitoring · v{_VERSION}</td></tr>
</table></td></tr></table></body></html>'''
    plain = (f'KVNRadar — {title}\n\n' + '\n'.join(f'{k}: {v}' for k,v in items) +
             ('\n\nDashboard: ' + link if link else '') + '\n\nGenerated automatically by KVNRadar.\n')
    subject = f'[KVNRadar] {title}: {target}'
    # Prevent mail header injection and overly long headers.
    subject = re.sub(r'[\r\n\x00-\x1f\x7f]+', ' ', subject)[:190]
    return subject, plain, html


def send(message):
    cfg = settings()
    if cfg is None:
        return None
    subject, plain, html = render(message)
    mail = EmailMessage()
    mail['Subject'] = subject
    mail['From'] = formataddr(('KVNRadar', cfg['from']))
    mail['To'] = ', '.join(cfg['to'])
    mail.set_content(plain)
    mail.add_alternative(html, subtype='html')
    tls = ssl.create_default_context()
    if cfg['mode'] == 'ssl':
        client = smtplib.SMTP_SSL(cfg['host'], cfg['port'], timeout=cfg['timeout'], context=tls)
    else:
        client = smtplib.SMTP(cfg['host'], cfg['port'], timeout=cfg['timeout'])
    with client as smtp:
        if cfg['mode'] == 'starttls':
            smtp.ehlo()
            smtp.starttls(context=tls)
            smtp.ehlo()
        if cfg['user']:
            smtp.login(cfg['user'], cfg['password'])
        smtp.send_message(mail)
    return True
