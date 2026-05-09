package notifications

import (
	"context"
	"log/slog"
	"strings"

	"github.com/shinkalabs/andromeda-backend/internal/billing"
)

// GiftObserver implements billing.GiftPurchaseObserver. After a paid gift
// card is minted, it sends the buyer the redeem URL via SMTP. Failures
// are logged and never bubble up — the webhook handler must always ack
// to Stripe even if the email side-effect failed.
type GiftObserver struct {
	mailer       Mailer
	dashboardURL string
	fromAddr     string
	logger       *slog.Logger
}

func NewGiftObserver(mailer Mailer, dashboardURL, fromAddr string, logger *slog.Logger) *GiftObserver {
	return &GiftObserver{
		mailer:       mailer,
		dashboardURL: dashboardURL,
		fromAddr:     fromAddr,
		logger:       logger,
	}
}

func (g *GiftObserver) OnGiftPurchased(ctx context.Context, ev billing.GiftPurchaseEvent) {
	if ev.GiftCard == nil {
		return
	}
	if ev.BuyerEmail == "" {
		g.logger.Warn("gift purchase: no buyer email; skipping receipt",
			"gift", ev.GiftCard.ID)
		return
	}

	redeemURL := buildRedeemURL(g.dashboardURL, ev.GiftCard.RedeemToken)
	paid := 0
	if ev.GiftCard.PaidAmountCents != nil {
		paid = *ev.GiftCard.PaidAmountCents
	}
	body := RenderGiftPurchaseBody(GiftPurchaseTemplateInput{
		BuyerEmail:      ev.BuyerEmail,
		PlanCode:        ev.GiftCard.PlanCode,
		DurationMonths:  ev.GiftCard.DurationMonths,
		PaidAmountCents: paid,
		RedeemURL:       redeemURL,
		Message:         ev.GiftCard.Message,
	})
	subject := RenderGiftPurchaseSubject(GiftPurchaseTemplateInput{
		PlanCode: ev.GiftCard.PlanCode,
	})

	if err := g.mailer.Send(Message{
		From:      g.fromAddr,
		To:        ev.BuyerEmail,
		Subject:   subject,
		PlainBody: body,
	}); err != nil {
		g.logger.Warn("gift purchase email failed",
			"err", err, "to", ev.BuyerEmail, "gift", ev.GiftCard.ID)
		return
	}
	g.logger.Info("gift purchase email sent",
		"to", ev.BuyerEmail, "gift", ev.GiftCard.ID, "plan", ev.GiftCard.PlanCode)
}

func buildRedeemURL(baseURL, token string) string {
	suffix := "/redeem?token=" + token
	if baseURL == "" {
		return suffix
	}
	return strings.TrimRight(baseURL, "/") + suffix
}
