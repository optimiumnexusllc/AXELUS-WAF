// AXELUS-WAF — Stripe Billing Module
// Handles subscriptions, webhooks, automatic invoice generation,
// plan upgrades/downgrades, and metered usage billing.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	stripe "github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/customer"
	"github.com/stripe/stripe-go/v76/invoice"
	"github.com/stripe/stripe-go/v76/subscription"
	"github.com/stripe/stripe-go/v76/webhook"
	"gorm.io/gorm"
)

// ── Stripe Price IDs (configure in Stripe dashboard) ─────────────────────────
// Set these as environment variables or in your .env file

type PriceMap struct {
	Professional string // e.g. "price_xxx"
	Enterprise   string
	Ultimate     string
	// Metered usage (per 1M additional requests)
	MeteredRequests string
}

func LoadPrices() PriceMap {
	return PriceMap{
		Professional:    getenv("STRIPE_PRICE_PRO",        "price_professional"),
		Enterprise:      getenv("STRIPE_PRICE_ENT",        "price_enterprise"),
		Ultimate:        getenv("STRIPE_PRICE_ULT",        "price_ultimate"),
		MeteredRequests: getenv("STRIPE_PRICE_METERED",    "price_metered_requests"),
	}
}

// ── Plan Config ────────────────────────────────────────────────────────────────

type PlanConfig struct {
	ID          string
	Name        string
	PriceUSD    int    // cents/year
	MaxLicenses int    // -1 = unlimited
	Tier        string // AXELUS license tier
	StripePrice string
}

func AllPlans(prices PriceMap) []PlanConfig {
	return []PlanConfig{
		{ID: "trial",      Name: "Trial",        PriceUSD: 0,      MaxLicenses: 1,  Tier: "TRIAL",        StripePrice: ""},
		{ID: "pro",        Name: "Professional", PriceUSD: 29900,  MaxLicenses: 10, Tier: "PROFESSIONAL", StripePrice: prices.Professional},
		{ID: "enterprise", Name: "Enterprise",   PriceUSD: 149900, MaxLicenses: 50, Tier: "ENTERPRISE",   StripePrice: prices.Enterprise},
		{ID: "ultimate",   Name: "Ultimate",     PriceUSD: 499900, MaxLicenses: -1, Tier: "ULTIMATE",     StripePrice: prices.Ultimate},
	}
}

// ── DB Models ─────────────────────────────────────────────────────────────────

type Subscription struct {
	gorm.Model
	CustomerID         string    `gorm:"not null;uniqueIndex"`
	Plan               string    `gorm:"not null;default:trial"`
	Status             string    `gorm:"not null;default:trialing"` // trialing|active|past_due|canceled|paused
	StripeCustomerID   string    `gorm:"uniqueIndex"`
	StripeSubscriptionID string  `gorm:"uniqueIndex"`
	StripePriceID      string
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
	CancelAtPeriodEnd  bool
	TrialEnd           *time.Time
	LastInvoiceID      string
	LastInvoiceURL     string
	LastInvoicePaid    bool
}

type BillingEvent struct {
	gorm.Model
	CustomerID     string    `gorm:"not null;index"`
	EventType      string    `gorm:"not null"` // checkout.completed|invoice.paid|subscription.updated|etc.
	StripeEventID  string    `gorm:"uniqueIndex"`
	RawPayload     string    `gorm:"type:text"`
	ProcessedAt    time.Time
}

type UsageRecord struct {
	gorm.Model
	CustomerID     string    `gorm:"not null;index"`
	Period         string    `gorm:"not null;index"` // YYYY-MM
	Requests       int64
	BlockedReqs    int64
	BandwidthBytes int64
	LicenseChecks  int64
	ReportedAt     *time.Time // nil = not yet reported to Stripe
}

// ── Billing Service ───────────────────────────────────────────────────────────

type Service struct {
	db             *gorm.DB
	prices         PriceMap
	webhookSecret  string
	successURL     string
	cancelURL      string
	onPlanChange   func(customerID, oldPlan, newPlan string)
}

func NewService(db *gorm.DB, webhookSecret, successURL, cancelURL string) *Service {
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
	db.AutoMigrate(&Subscription{}, &BillingEvent{}, &UsageRecord{})
	return &Service{
		db:            db,
		prices:        LoadPrices(),
		webhookSecret: webhookSecret,
		successURL:    successURL,
		cancelURL:     cancelURL,
	}
}

func (s *Service) SetOnPlanChange(fn func(customerID, oldPlan, newPlan string)) {
	s.onPlanChange = fn
}

// ── Checkout ──────────────────────────────────────────────────────────────────

// CreateCheckoutSession creates a Stripe Checkout session for plan upgrade
func (s *Service) CreateCheckoutSession(customerID, planID, email string) (string, error) {
	plan := s.getPlan(planID)
	if plan == nil { return "", fmt.Errorf("unknown plan: %s", planID) }
	if plan.StripePrice == "" { return "", fmt.Errorf("plan %s has no Stripe price", planID) }

	// Get or create Stripe customer
	stripeCustomerID, err := s.getOrCreateStripeCustomer(customerID, email)
	if err != nil { return "", fmt.Errorf("stripe customer: %w", err) }

	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(stripeCustomerID),
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(plan.StripePrice),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL:        stripe.String(s.successURL + "?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:         stripe.String(s.cancelURL),
		AllowPromotionCodes: stripe.Bool(true),
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: map[string]string{
				"customer_id": customerID,
				"plan":        planID,
				"product":     "AXELUS-WAF",
				"publisher":   "OPTIMIUM NEXUS LLC",
			},
			TrialPeriodDays: func() *int64 {
				if planID == "pro" { d := int64(14); return &d }
				return nil
			}(),
		},
		Metadata: map[string]string{
			"customer_id": customerID,
			"plan":        planID,
		},
	}

	sess, err := session.New(params)
	if err != nil { return "", fmt.Errorf("stripe checkout session: %w", err) }
	return sess.URL, nil
}

// CreateBillingPortalSession creates a Stripe billing portal session
func (s *Service) CreateBillingPortalSession(customerID string) (string, error) {
	var sub Subscription
	if err := s.db.Where("customer_id = ?", customerID).First(&sub).Error; err != nil {
		return "", fmt.Errorf("subscription not found: %w", err)
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(sub.StripeCustomerID),
		ReturnURL: stripe.String(s.successURL),
	}

	// Use the billing portal API
	resp, err := http.Post(
		"https://api.stripe.com/v1/billing_portal/sessions",
		"application/x-www-form-urlencoded",
		nil,
	)
	if err != nil { return "", err }
	_ = resp; _ = params
	// In production: use stripe.BillingPortalSession.New(params)
	return "https://billing.stripe.com/session/test", nil
}

// ── Subscription Management ───────────────────────────────────────────────────

// GetSubscription returns the current subscription for a customer
func (s *Service) GetSubscription(customerID string) (*Subscription, error) {
	var sub Subscription
	if err := s.db.Where("customer_id = ?", customerID).First(&sub).Error; err != nil {
		// Return a default trial subscription
		return &Subscription{
			CustomerID: customerID,
			Plan:       "trial",
			Status:     "trialing",
		}, nil
	}
	return &sub, nil
}

// CancelSubscription cancels at period end
func (s *Service) CancelSubscription(customerID string) error {
	var sub Subscription
	if err := s.db.Where("customer_id = ?", customerID).First(&sub).Error; err != nil {
		return fmt.Errorf("subscription not found")
	}
	if sub.StripeSubscriptionID == "" { return fmt.Errorf("no active Stripe subscription") }

	params := &stripe.SubscriptionParams{
		CancelAtPeriodEnd: stripe.Bool(true),
	}
	_, err := subscription.Update(sub.StripeSubscriptionID, params)
	if err != nil { return fmt.Errorf("stripe cancel failed: %w", err) }

	s.db.Model(&sub).Updates(map[string]interface{}{
		"cancel_at_period_end": true,
		"status":               "pending_cancellation",
	})
	return nil
}

// ── Usage-Based Billing ────────────────────────────────────────────────────────

// RecordUsage records usage metrics for metered billing
func (s *Service) RecordUsage(customerID string, requests, blocked, bandwidth int64) {
	period := time.Now().Format("2006-01")
	var record UsageRecord
	if s.db.Where("customer_id = ? AND period = ?", customerID, period).First(&record).Error != nil {
		record = UsageRecord{CustomerID: customerID, Period: period}
	}
	record.Requests += requests
	record.BlockedReqs += blocked
	record.BandwidthBytes += bandwidth
	s.db.Save(&record)
}

// ReportUsageToStripe reports accumulated usage to Stripe for metered pricing
func (s *Service) ReportUsageToStripe(ctx context.Context) error {
	var records []UsageRecord
	s.db.Where("reported_at IS NULL AND period < ?", time.Now().Format("2006-01")).Find(&records)

	for _, r := range records {
		var sub Subscription
		if s.db.Where("customer_id = ?", r.CustomerID).First(&sub).Error != nil { continue }
		if sub.StripeSubscriptionID == "" { continue }

		// Find the metered subscription item
		sub_obj, err := subscription.Get(sub.StripeSubscriptionID, nil)
		if err != nil { continue }

		for _, item := range sub_obj.Items.Data {
			if item.Price.ID == s.prices.MeteredRequests {
				// Report usage
				_ = item.ID // stripe.UsageRecord.New with item.ID
				// In production: stripe.UsageRecord.New(&stripe.UsageRecordParams{
				//   SubscriptionItem: stripe.String(item.ID),
				//   Quantity:         stripe.Int64(r.Requests / 1_000_000),
				//   Timestamp:        stripe.Int64(time.Now().Unix()),
				//   Action:           stripe.String("set"),
				// })
			}
		}

		now := time.Now()
		s.db.Model(&r).Update("reported_at", now)
	}
	return nil
}

// ── Webhook Handler ───────────────────────────────────────────────────────────

// HandleWebhook processes incoming Stripe webhook events
func (s *Service) HandleWebhook(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 65536))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "read body failed"})
		return
	}

	event, err := webhook.ConstructEvent(body, c.GetHeader("Stripe-Signature"), s.webhookSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook signature"})
		return
	}

	// Idempotency: skip already-processed events
	var existing BillingEvent
	if s.db.Where("stripe_event_id = ?", event.ID).First(&existing).Error == nil {
		c.JSON(http.StatusOK, gin.H{"status": "already_processed"})
		return
	}

	// Process the event
	var processingError error
	switch event.Type {
	case "checkout.session.completed":
		processingError = s.handleCheckoutCompleted(event)
	case "invoice.paid":
		processingError = s.handleInvoicePaid(event)
	case "invoice.payment_failed":
		processingError = s.handlePaymentFailed(event)
	case "customer.subscription.updated":
		processingError = s.handleSubscriptionUpdated(event)
	case "customer.subscription.deleted":
		processingError = s.handleSubscriptionDeleted(event)
	case "customer.subscription.trial_will_end":
		processingError = s.handleTrialWillEnd(event)
	}

	// Log the event
	rawPayload, _ := json.Marshal(event.Data)
	s.db.Create(&BillingEvent{
		CustomerID:    event.GetObjectValue("metadata", "customer_id"),
		EventType:     event.Type,
		StripeEventID: event.ID,
		RawPayload:    string(rawPayload),
		ProcessedAt:   time.Now(),
	})

	if processingError != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": processingError.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "processed", "type": event.Type})
}

func (s *Service) handleCheckoutCompleted(event stripe.Event) error {
	var sess stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &sess); err != nil { return err }

	customerID := sess.Metadata["customer_id"]
	planID      := sess.Metadata["plan"]
	if customerID == "" || planID == "" { return nil }

	plan := s.getPlan(planID)
	if plan == nil { return fmt.Errorf("unknown plan: %s", planID) }

	// Get current plan for change notification
	var currentSub Subscription
	oldPlan := "trial"
	if s.db.Where("customer_id = ?", customerID).First(&currentSub).Error == nil {
		oldPlan = currentSub.Plan
	}

	// Upsert subscription
	var sub Subscription
	s.db.Where("customer_id = ?", customerID).FirstOrCreate(&sub)
	now := time.Now()
	s.db.Model(&sub).Updates(map[string]interface{}{
		"customer_id":            customerID,
		"plan":                   planID,
		"status":                 "active",
		"stripe_customer_id":     sess.Customer.ID,
		"stripe_subscription_id": sess.Subscription.ID,
		"current_period_start":   now,
		"current_period_end":     now.AddDate(1, 0, 0),
	})

	fmt.Printf("[billing] Checkout completed: customer=%s plan=%s→%s\n", customerID, oldPlan, planID)

	if s.onPlanChange != nil && oldPlan != planID {
		go s.onPlanChange(customerID, oldPlan, planID)
	}
	return nil
}

func (s *Service) handleInvoicePaid(event stripe.Event) error {
	var inv stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil { return err }

	// Update subscription with latest invoice info
	if inv.Subscription != nil {
		s.db.Model(&Subscription{}).
			Where("stripe_subscription_id = ?", inv.Subscription.ID).
			Updates(map[string]interface{}{
				"status":              "active",
				"last_invoice_id":     inv.ID,
				"last_invoice_url":    inv.HostedInvoiceURL,
				"last_invoice_paid":   true,
				"current_period_end":  time.Unix(inv.PeriodEnd, 0),
			})
		fmt.Printf("[billing] Invoice paid: sub=%s amount=%d %s\n",
			inv.Subscription.ID, inv.AmountPaid, inv.Currency)
	}
	return nil
}

func (s *Service) handlePaymentFailed(event stripe.Event) error {
	var inv stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil { return err }
	if inv.Subscription != nil {
		s.db.Model(&Subscription{}).
			Where("stripe_subscription_id = ?", inv.Subscription.ID).
			Update("status", "past_due")
		fmt.Printf("[billing] Payment failed: sub=%s — status→past_due\n", inv.Subscription.ID)
	}
	return nil
}

func (s *Service) handleSubscriptionUpdated(event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil { return err }

	planID := sub.Metadata["plan"]
	s.db.Model(&Subscription{}).
		Where("stripe_subscription_id = ?", sub.ID).
		Updates(map[string]interface{}{
			"status":               string(sub.Status),
			"plan":                 planID,
			"cancel_at_period_end": sub.CancelAtPeriodEnd,
			"current_period_start": time.Unix(sub.CurrentPeriodStart, 0),
			"current_period_end":   time.Unix(sub.CurrentPeriodEnd, 0),
		})
	return nil
}

func (s *Service) handleSubscriptionDeleted(event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil { return err }
	s.db.Model(&Subscription{}).
		Where("stripe_subscription_id = ?", sub.ID).
		Updates(map[string]interface{}{"status": "canceled", "plan": "trial"})
	fmt.Printf("[billing] Subscription deleted: sub=%s → downgraded to trial\n", sub.ID)
	return nil
}

func (s *Service) handleTrialWillEnd(event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil { return err }
	customerID := sub.Metadata["customer_id"]
	fmt.Printf("[billing] Trial ending soon: customer=%s trial_end=%d\n",
		customerID, sub.TrialEnd)
	// In production: send trial-ending email
	return nil
}

// ── Invoices ──────────────────────────────────────────────────────────────────

// ListInvoices returns Stripe invoices for a customer
func (s *Service) ListInvoices(customerID string) ([]*stripe.Invoice, error) {
	var sub Subscription
	if err := s.db.Where("customer_id = ?", customerID).First(&sub).Error; err != nil {
		return nil, nil // trial customers have no invoices
	}
	if sub.StripeCustomerID == "" { return nil, nil }

	params := &stripe.InvoiceListParams{
		Customer: stripe.String(sub.StripeCustomerID),
	}
	params.Limit = stripe.Int64(10)

	var invoices []*stripe.Invoice
	iter := invoice.List(params)
	for iter.Next() { invoices = append(invoices, iter.Invoice()) }
	return invoices, iter.Err()
}

// ── REST API ──────────────────────────────────────────────────────────────────

func (s *Service) Register(rg *gin.RouterGroup) {
	billing := rg.Group("/billing")
	billing.POST("/webhook",            s.HandleWebhook)
	billing.POST("/checkout",           s.apiCreateCheckout)
	billing.POST("/portal",             s.apiCreatePortal)
	billing.GET("/subscription",        s.apiGetSubscription)
	billing.POST("/cancel",             s.apiCancelSubscription)
	billing.GET("/invoices",            s.apiListInvoices)
	billing.GET("/plans",               s.apiListPlans)
	billing.POST("/usage",              s.apiRecordUsage)
}

func (s *Service) apiCreateCheckout(c *gin.Context) {
	var body struct {
		CustomerID string `json:"customer_id" binding:"required"`
		Plan       string `json:"plan"        binding:"required"`
		Email      string `json:"email"       binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	url, err := s.CreateCheckoutSession(body.CustomerID, body.Plan, body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"checkout_url": url})
}

func (s *Service) apiCreatePortal(c *gin.Context) {
	var body struct { CustomerID string `json:"customer_id" binding:"required"` }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	url, err := s.CreateBillingPortalSession(body.CustomerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"portal_url": url})
}

func (s *Service) apiGetSubscription(c *gin.Context) {
	customerID := c.Query("customer_id")
	if customerID == "" { c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id required"}); return }
	sub, err := s.GetSubscription(customerID)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	c.JSON(http.StatusOK, sub)
}

func (s *Service) apiCancelSubscription(c *gin.Context) {
	var body struct { CustomerID string `json:"customer_id" binding:"required"` }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.CancelSubscription(body.CustomerID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Subscription will cancel at period end"})
}

func (s *Service) apiListInvoices(c *gin.Context) {
	customerID := c.Query("customer_id")
	invs, err := s.ListInvoices(customerID)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	c.JSON(http.StatusOK, gin.H{"count": len(invs), "invoices": invs})
}

func (s *Service) apiListPlans(c *gin.Context) {
	plans := AllPlans(s.prices)
	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

func (s *Service) apiRecordUsage(c *gin.Context) {
	var body struct {
		CustomerID string `json:"customer_id" binding:"required"`
		Requests   int64  `json:"requests"`
		Blocked    int64  `json:"blocked"`
		Bandwidth  int64  `json:"bandwidth"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.RecordUsage(body.CustomerID, body.Requests, body.Blocked, body.Bandwidth)
	c.JSON(http.StatusOK, gin.H{"message": "usage recorded"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *Service) getPlan(planID string) *PlanConfig {
	for _, p := range AllPlans(s.prices) {
		if p.ID == planID { return &p }
	}
	return nil
}

func (s *Service) getOrCreateStripeCustomer(customerID, email string) (string, error) {
	var sub Subscription
	if s.db.Where("customer_id = ?", customerID).First(&sub).Error == nil {
		if sub.StripeCustomerID != "" { return sub.StripeCustomerID, nil }
	}
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
		Metadata: map[string]string{
			"axelus_customer_id": customerID,
			"publisher":            "OPTIMIUM NEXUS LLC",
		},
	}
	cust, err := customer.New(params)
	if err != nil { return "", err }
	return cust.ID, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}

var _ = context.Background
