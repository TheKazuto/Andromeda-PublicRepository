package notifications

import (
	"fmt"
	"strings"
	"time"
)

// QuotaTemplateInput carries the values rendered into the threshold email.
type QuotaTemplateInput struct {
	Email        string
	PlanCode     string
	ThresholdPct int
	TokensUsed   int64
	TokensLimit  int64
	OverageUsed  int64
	PeriodEnd    time.Time
	DashboardURL string
}

// RenderQuotaSubject returns the subject line for the threshold email.
func RenderQuotaSubject(in QuotaTemplateInput) string {
	switch in.ThresholdPct {
	case 80:
		return fmt.Sprintf("[Andromeda] %s plan: 80%% of monthly tokens used", titlePlan(in.PlanCode))
	case 95:
		return fmt.Sprintf("[Andromeda] %s plan: 95%% used — quota almost exhausted", titlePlan(in.PlanCode))
	case 100:
		return fmt.Sprintf("[Andromeda] %s plan: token quota reached", titlePlan(in.PlanCode))
	case 200:
		return fmt.Sprintf("[Andromeda] %s plan: overage cap reached", titlePlan(in.PlanCode))
	default:
		return fmt.Sprintf("[Andromeda] %s plan: %d%% of tokens used", titlePlan(in.PlanCode), in.ThresholdPct)
	}
}

// RenderQuotaBody returns the plain-text body for the threshold email.
func RenderQuotaBody(in QuotaTemplateInput) string {
	var b strings.Builder
	pctUsed := percent(in.TokensUsed+in.OverageUsed, in.TokensLimit)

	switch in.ThresholdPct {
	case 80:
		fmt.Fprintf(&b, "Hi,\n\nYou've used %d%% of your monthly token allowance on the %s plan.\n",
			pctUsed, titlePlan(in.PlanCode))
		fmt.Fprintf(&b, "\nUsage so far: %s / %s tokens.\n",
			formatNumber(in.TokensUsed+in.OverageUsed), formatNumber(in.TokensLimit))
		fmt.Fprintf(&b, "Period resets on %s.\n",
			in.PeriodEnd.Format("January 2, 2006"))
		b.WriteString("\nNo action is required. We're flagging this so the rate doesn't surprise you.\n")
	case 95:
		fmt.Fprintf(&b, "Hi,\n\nYou're approaching your monthly limit on the %s plan — %d%% used.\n",
			titlePlan(in.PlanCode), pctUsed)
		fmt.Fprintf(&b, "\nUsage so far: %s / %s tokens.\n",
			formatNumber(in.TokensUsed+in.OverageUsed), formatNumber(in.TokensLimit))
		fmt.Fprintf(&b, "Period resets on %s.\n",
			in.PeriodEnd.Format("January 2, 2006"))
		b.WriteString("\nIf you expect heavier usage this period, consider upgrading or enabling overage.\n")
	case 100:
		fmt.Fprintf(&b, "Hi,\n\nYour %s plan has reached its monthly token quota.\n",
			titlePlan(in.PlanCode))
		b.WriteString("\nNew API requests will return HTTP 402 (quota_exceeded) until:\n")
		fmt.Fprintf(&b, "  - The next period rolls over on %s, OR\n",
			in.PeriodEnd.Format("January 2, 2006"))
		b.WriteString("  - You upgrade your plan, OR\n")
		b.WriteString("  - You enable overage (requires a card on file).\n")
	case 200:
		fmt.Fprintf(&b, "Hi,\n\nYour %s plan has hit the overage hard cap (2× monthly tokens).\n",
			titlePlan(in.PlanCode))
		b.WriteString("\nFor safety, the gateway will refuse further calls until the period rolls over\n")
		fmt.Fprintf(&b, "on %s.\n", in.PeriodEnd.Format("January 2, 2006"))
		b.WriteString("\nIf this volume is expected, please contact support to raise the cap or move to an enterprise contract.\n")
	}

	if in.DashboardURL != "" {
		fmt.Fprintf(&b, "\nManage usage and plan: %s\n", in.DashboardURL)
	}
	b.WriteString("\n— Andromeda\n")
	return b.String()
}

// PricingTemplateInput carries the values rendered into the pricing-change
// notification email.
type PricingTemplateInput struct {
	Email        string
	PlanCode     string
	ChangeType   string
	OldValue     *int64
	NewValue     int64
	EffectiveAt  time.Time
	Reason       string
	DashboardURL string
}

func RenderPricingSubject(in PricingTemplateInput) string {
	return fmt.Sprintf("[Andromeda] Upcoming pricing change for %s — effective %s",
		titlePlan(in.PlanCode), in.EffectiveAt.Format("Jan 2, 2006"))
}

func RenderPricingBody(in PricingTemplateInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Hi,\n\nWe're notifying you 30 days in advance of an upcoming change to your %s plan.\n",
		titlePlan(in.PlanCode))

	fmt.Fprintf(&b, "\nWhat changes: %s\n", describeChangeType(in.ChangeType))
	if in.OldValue != nil {
		fmt.Fprintf(&b, "Previous value: %s\n", formatChangeValue(in.ChangeType, *in.OldValue))
	}
	fmt.Fprintf(&b, "New value: %s\n", formatChangeValue(in.ChangeType, in.NewValue))
	fmt.Fprintf(&b, "Effective: %s\n", in.EffectiveAt.Format("January 2, 2006 at 15:04 MST"))

	if strings.TrimSpace(in.Reason) != "" {
		fmt.Fprintf(&b, "\nReason: %s\n", in.Reason)
	}

	b.WriteString("\nYour current billing period continues at the previous price; the change applies on renewal.\n")

	if in.DashboardURL != "" {
		fmt.Fprintf(&b, "\nReview details: %s\n", in.DashboardURL)
	}
	b.WriteString("\n— Andromeda\n")
	return b.String()
}

// GiftPurchaseTemplateInput carries values rendered into the email
// confirming a paid gift card purchase.
type GiftPurchaseTemplateInput struct {
	BuyerEmail      string
	PlanCode        string
	DurationMonths  int
	PaidAmountCents int
	RedeemURL       string
	Message         string
}

func RenderGiftPurchaseSubject(in GiftPurchaseTemplateInput) string {
	return fmt.Sprintf("[Andromeda] Your gift card for %s — ready to share",
		titlePlan(in.PlanCode))
}

func RenderGiftPurchaseBody(in GiftPurchaseTemplateInput) string {
	var b strings.Builder
	b.WriteString("Hi,\n\nThanks for buying an Andromeda gift card!\n\n")

	fmt.Fprintf(&b, "What you bought: %s, %d %s\n",
		titlePlan(in.PlanCode), in.DurationMonths, monthLabel(in.DurationMonths))
	if in.PaidAmountCents > 0 {
		fmt.Fprintf(&b, "Amount paid: $%d.%02d\n",
			in.PaidAmountCents/100, in.PaidAmountCents%100)
	}

	b.WriteString("\nShare this link with the recipient — they redeem it after signing in to Andromeda:\n")
	if in.RedeemURL != "" {
		fmt.Fprintf(&b, "\n  %s\n", in.RedeemURL)
	}

	if strings.TrimSpace(in.Message) != "" {
		fmt.Fprintf(&b, "\nMessage you included for them:\n  \"%s\"\n", in.Message)
	}

	b.WriteString("\nThe gift expires in 12 months. Refunds are available within 7 days if it has not been redeemed.\n")
	b.WriteString("\n— Andromeda\n")
	return b.String()
}

func monthLabel(n int) string {
	if n == 1 {
		return "month"
	}
	return "months"
}

// ----- helpers -----

func titlePlan(code string) string {
	if code == "" {
		return "your"
	}
	return strings.ToUpper(code[:1]) + code[1:]
}

func formatNumber(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func percent(num, denom int64) int {
	if denom <= 0 {
		return 0
	}
	return int((num * 100) / denom)
}

func describeChangeType(t string) string {
	switch t {
	case "plan_price":
		return "monthly subscription price"
	case "plan_annual_price":
		return "annual subscription price"
	case "plan_tokens":
		return "monthly token allowance"
	case "plan_read_rps":
		return "read requests per second limit"
	case "plan_tx_rps":
		return "transaction requests per second limit"
	case "plan_overage":
		return "overage rate (price per 1,000 extra tokens)"
	case "route_cost":
		return "token cost of an API route"
	default:
		return t
	}
}

func formatChangeValue(changeType string, v int64) string {
	switch changeType {
	case "plan_price", "plan_annual_price":
		return fmt.Sprintf("$%d.%02d", v/100, v%100)
	case "plan_overage":
		return fmt.Sprintf("$%d.%02d per 1,000 tokens", v/100, v%100)
	case "plan_tokens":
		return fmt.Sprintf("%s tokens / month", formatNumber(v))
	case "plan_read_rps", "plan_tx_rps":
		return fmt.Sprintf("%d requests / second", v)
	case "route_cost":
		return fmt.Sprintf("%d tokens", v)
	default:
		return fmt.Sprintf("%d", v)
	}
}
