// Email — magic link templates.
// All user-facing text in English (international audience).

const ESCAPE_HTML_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ESCAPE_HTML_MAP[ch] ?? ch)
}

export type EmailTemplateIntent = 'login' | 'link'

export interface MagicLinkTemplateInput {
  intent: EmailTemplateIntent
  link: string
  ttlMinutes: number
}

export interface RenderedTemplate {
  subject: string
  html: string
  text: string
}

const SUBJECTS: Record<EmailTemplateIntent, string> = {
  login: 'Your sign-in link',
  link: 'Confirm your new sign-in method',
}

const HEADLINES: Record<EmailTemplateIntent, string> = {
  login: 'Sign in to Andromeda',
  link: 'Confirm new sign-in method',
}

const INSTRUCTIONS: Record<EmailTemplateIntent, string> = {
  login:
    'Click the button below to finish signing in. This link can be used once and expires in {ttl} minutes.',
  link:
    'Click the button below to add this email as an additional sign-in method on your account. This link can be used once and expires in {ttl} minutes.',
}

const FOOTER_DISCLAIMER =
  'If you did not request this email, you can safely ignore it — no further action will be taken.'

export function renderMagicLinkEmail(input: MagicLinkTemplateInput): RenderedTemplate {
  const ttl = String(input.ttlMinutes)
  const safeLink = escapeHtml(input.link)
  const instruction = INSTRUCTIONS[input.intent].replace('{ttl}', ttl)
  const headline = HEADLINES[input.intent]
  const subject = SUBJECTS[input.intent]

  const html = `<!doctype html>
<html lang="en">
  <body style="margin:0;padding:0;background-color:#f6f6f6;font-family:Inter,Arial,sans-serif;color:#111;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f6f6f6;padding:40px 0;">
      <tr>
        <td align="center">
          <table width="560" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;padding:40px;">
            <tr>
              <td>
                <h1 style="margin:0 0 16px;font-size:22px;font-weight:600;color:#111;">${escapeHtml(headline)}</h1>
                <p style="margin:0 0 24px;font-size:15px;line-height:1.55;color:#333;">${escapeHtml(instruction)}</p>
                <p style="margin:0 0 24px;">
                  <a href="${safeLink}" style="display:inline-block;padding:12px 24px;background-color:#111;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;">Sign in</a>
                </p>
                <p style="margin:0 0 8px;font-size:13px;color:#555;">Or copy and paste this URL into your browser:</p>
                <p style="margin:0 0 24px;font-size:13px;color:#555;word-break:break-all;">${safeLink}</p>
                <hr style="border:none;border-top:1px solid #eee;margin:24px 0;" />
                <p style="margin:0;font-size:12px;color:#888;line-height:1.5;">${escapeHtml(FOOTER_DISCLAIMER)}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`

  const text = [headline, '', instruction, '', `Sign in: ${input.link}`, '', FOOTER_DISCLAIMER].join('\n')

  return { subject, html, text }
}

export function buildMagicLinkUrl(frontendCallbackUrl: string, token: string): string {
  const url = new URL(frontendCallbackUrl)
  url.searchParams.set('token', token)
  return url.toString()
}
