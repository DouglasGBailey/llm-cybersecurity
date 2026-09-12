require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));

const PORT = process.env.PORT || 3010;
const TO_EMAIL = process.env.TO_EMAIL || 'terminalvelocityai@gmail.com';
const FROM_EMAIL = 'Secure Verification Services <noreply@terminalvelocityai.tech>';
const SITE_NAME = 'Secure Verification Services';

// Same local relay pattern used by the other pm2-managed contact forms on
// this host (Stalwart mail server listening on 127.0.0.1:25) — no auth,
// no external SMTP creds needed.
const mailer = nodemailer.createTransport({
  host: '127.0.0.1',
  port: 25,
  secure: false,
  tls: { rejectUnauthorized: false },
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Strip anything that could be used for header/content injection via
// multi-line input in fields that end up in a header (e.g. name -> From/Reply-To adjacent text).
function singleLine(str, maxLen) {
  return String(str).replace(/[\r\n]+/g, ' ').trim().slice(0, maxLen);
}

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please try again later.' },
});

app.post('/api/contact', contactLimiter, async (req, res) => {
  const body = req.body || {};
  const name = singleLine(body.name || '', 120);
  const email = singleLine(body.email || '', 200);
  const message = String(body.message || '').slice(0, 5000).trim();
  const company = body.company; // honeypot — real users never fill this in

  if (company) {
    // Silently pretend success to not tip off bots.
    return res.json({ ok: true });
  }

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email, and message are required.' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const notifyHtml = `
<h2>New contact form submission — ${escHtml(SITE_NAME)}</h2>
<table cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;max-width:600px;font-family:sans-serif;">
  <tr style="background:#f5f5f5">
    <td style="border:1px solid #ddd;font-weight:bold;width:120px">Name</td>
    <td style="border:1px solid #ddd">${escHtml(name)}</td>
  </tr>
  <tr>
    <td style="border:1px solid #ddd;font-weight:bold">Email</td>
    <td style="border:1px solid #ddd">${escHtml(email)}</td>
  </tr>
  <tr style="background:#f5f5f5">
    <td style="border:1px solid #ddd;font-weight:bold">Message</td>
    <td style="border:1px solid #ddd;white-space:pre-wrap">${escHtml(message)}</td>
  </tr>
</table>
`;

  const autoReplyHtml = `
<p>Hi ${escHtml(name)},</p>
<p>Thanks for reaching out to ${escHtml(SITE_NAME)} — we've received your message and will get back to you in good time.</p>
<p>For your records, here's what you sent us:</p>
<blockquote style="border-left:3px solid #4fe3a1;margin:0;padding:8px 16px;color:#444;white-space:pre-wrap">${escHtml(message)}</blockquote>
<p>— The ${escHtml(SITE_NAME)} team</p>
`;

  try {
    await mailer.sendMail({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: email,
      subject: `[${SITE_NAME}] New contact form message from ${name}`,
      html: notifyHtml,
    });

    await mailer.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Thanks for contacting ${SITE_NAME}`,
      html: autoReplyHtml,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Contact form SMTP error:', err);
    res.status(500).json({ error: 'Failed to send your message — please try again shortly.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Must bind 0.0.0.0, not 127.0.0.1: nginx runs inside Docker and reaches
// this host process via the docker0 bridge IP (172.17.0.1), not loopback.
app.listen(PORT, '0.0.0.0', () => {
  console.log(`contact-api listening on 0.0.0.0:${PORT}`);
});
