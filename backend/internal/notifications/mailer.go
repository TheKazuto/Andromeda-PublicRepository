// Package notifications fires user-facing alerts (email + webhook) for
// quota thresholds and pricing changes.
//
// The mailer interface is intentionally tiny so it can be backed by SMTP,
// Postmark, SendGrid, etc. The default implementation uses net/smtp,
// which talks to anything that speaks RFC 5321 (Postmark, SES, Resend
// SMTP, Gmail, Mailgun, etc).
package notifications

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// smtpDialTimeout caps how long a single Send blocks waiting on the
// remote SMTP host before failing. Without a timeout an unresponsive
// host can pin goroutines forever — the worker fleet would silently
// grind to a halt under load.
const smtpDialTimeout = 10 * time.Second

// Mailer sends a single email. Implementations must be safe for concurrent
// use — the workers may dispatch multiple alerts in parallel.
type Mailer interface {
	Send(msg Message) error
}

// Message is the minimal email envelope. PlainBody is mandatory; HTMLBody
// is optional and, when present, is offered as multipart/alternative.
type Message struct {
	From      string // "Andromeda <noreply@shinkalabs.com>"
	To        string // recipient email address
	Subject   string
	PlainBody string
	HTMLBody  string
}

// SMTPConfig configures the net/smtp mailer.
type SMTPConfig struct {
	Host     string // "smtp.postmarkapp.com"
	Port     int    // 587 (STARTTLS) or 465 (TLS) or 25 (plain — never in prod)
	Username string
	Password string
	From     string // default From for messages that omit it
}

// NewSMTPMailer returns a mailer that connects to host:port for every send
// (no connection pooling — alerts are low-volume). When cfg is empty,
// NewSMTPMailer returns a noop mailer that logs and discards.
func NewSMTPMailer(cfg SMTPConfig, logger *slog.Logger) Mailer {
	if cfg.Host == "" {
		logger.Warn("notifications: SMTP not configured — emails will be discarded")
		return &noopMailer{logger: logger}
	}
	return &smtpMailer{cfg: cfg, logger: logger}
}

type noopMailer struct{ logger *slog.Logger }

func (n *noopMailer) Send(msg Message) error {
	n.logger.Info("notifications: email skipped (no mailer configured)",
		"to", msg.To, "subject", msg.Subject)
	return nil
}

type smtpMailer struct {
	cfg    SMTPConfig
	logger *slog.Logger
}

// sanitizeHeader strips CR/LF and NUL from a single SMTP header value.
// Without this an attacker who can influence Subject/From/To (gift
// messages, plan names sourced from the dashboard, etc.) could inject
// extra headers via CRLF and add Bcc:, alter the Reply-To, or smuggle
// a second message body. This is the classic SMTP-header-injection
// vulnerability — the fix is to refuse line terminators outright.
func sanitizeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\x00", "")
	return strings.TrimSpace(v)
}

func (m *smtpMailer) Send(msg Message) error {
	if msg.To == "" {
		return errors.New("missing To")
	}
	if msg.PlainBody == "" {
		return errors.New("missing PlainBody")
	}
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	if msg.From == "" {
		msg.From = m.cfg.From
	}
	if msg.From == "" {
		return errors.New("missing From and SMTPConfig.From")
	}
	if _, err := mail.ParseAddress(msg.From); err != nil {
		return fmt.Errorf("invalid sender: %w", err)
	}

	body := buildMIME(msg)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))

	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	switch m.cfg.Port {
	case 465:
		// Implicit TLS — net/smtp doesn't support this directly. Dial
		// the underlying TCP socket with a bounded timeout, then wrap
		// in TLS and hand to NewClient.
		dialer := &net.Dialer{Timeout: smtpDialTimeout}
		rawConn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("dial smtp: %w", err)
		}
		// Bound the entire SMTP exchange too so a hung server can't
		// indefinitely block on subsequent reads/writes.
		_ = rawConn.SetDeadline(time.Now().Add(smtpDialTimeout * 6))
		tlsConn := tls.Client(rawConn, &tls.Config{ServerName: m.cfg.Host})
		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return fmt.Errorf("smtp tls handshake: %w", err)
		}
		c, err := smtp.NewClient(tlsConn, m.cfg.Host)
		if err != nil {
			_ = tlsConn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
		defer c.Close()
		if m.cfg.Username != "" {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
		return sendOnClient(c, msg.From, msg.To, body)
	default:
		// 587 (STARTTLS) and 25 — net/smtp handles STARTTLS upgrade.
		// smtp.SendMail does not expose a Dialer hook, so wrap the
		// dial+exchange manually to enforce a timeout.
		return sendWithSTARTTLS(addr, m.cfg.Host, auth, msg.From, msg.To, body)
	}
}

// sendWithSTARTTLS is the timed-out equivalent of smtp.SendMail for the
// 587/25 path. It dials with a deadline, optionally upgrades to TLS via
// STARTTLS, authenticates, and delivers the message.
func sendWithSTARTTLS(addr, host string, auth smtp.Auth, from, to string, body []byte) error {
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(smtpDialTimeout * 6))
	c, err := smtp.NewClient(rawConn, host)
	if err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	return sendOnClient(c, from, to, body)
}

func sendOnClient(c *smtp.Client, from, to string, body []byte) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return c.Quit()
}

// buildMIME assembles a minimal RFC 5322 + MIME 1.0 message. Every
// header value is sanitised so a CRLF in From/To/Subject cannot inject
// arbitrary headers downstream. When HTML body is empty, sends as
// text/plain; otherwise sends multipart/alternative.
func buildMIME(msg Message) []byte {
	var buf bytes.Buffer
	from := sanitizeHeader(msg.From)
	to := sanitizeHeader(msg.To)
	subject := sanitizeHeader(msg.Subject)
	host := hostOf(from)
	boundary := "andromeda-mp-" + randomBoundary()

	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + to + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Message-ID: <" + randomMsgID() + "@" + host + ">\r\n")

	if msg.HTMLBody == "" {
		buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(msg.PlainBody)
		return buf.Bytes()
	}

	buf.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	buf.WriteString("\r\n")

	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(msg.PlainBody)
	buf.WriteString("\r\n")

	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(msg.HTMLBody)
	buf.WriteString("\r\n")

	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes()
}

func hostOf(addr string) string {
	if i := strings.Index(addr, "@"); i >= 0 {
		// strip trailing > if From is "Name <name@host>"
		host := addr[i+1:]
		if j := strings.Index(host, ">"); j >= 0 {
			host = host[:j]
		}
		return host
	}
	return "localhost"
}

// randomHex produces a hex string of n bytes from crypto/rand. Used for
// MIME boundaries and Message-IDs — collision-resistance matters more
// for spam-filter friendliness than security here.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a static suffix; the worst case is a duplicate
		// boundary which only affects message rendering, not delivery.
		return fmt.Sprintf("static-%d", n)
	}
	return hex.EncodeToString(b)
}

func randomBoundary() string {
	return randomHex(12)
}

func randomMsgID() string {
	return "andromeda-" + randomHex(8)
}
