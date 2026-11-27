package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultStoreBaseURL = "https://api-app.vectra-pro.net/v1/guard"

type storeCatalogReport struct {
	State    string         `json:"state"` // "live" | "soon" | "error"
	Products []storeProduct `json:"products,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	Rc       int            `json:"rc"`
}

type storeProduct struct {
	ID          string   `json:"id"` // "proxy" | "vectra_card" | "claude_account"
	Title       string   `json:"title"`
	Subtitle    string   `json:"subtitle"`
	Available   bool     `json:"available"`
	PriceLabel  string   `json:"priceLabel,omitempty"`
	Countries   []string `json:"countries,omitempty"`
	AmountsUSD  []int    `json:"amountsUsd,omitempty"`
	Months      []int    `json:"months,omitempty"`
	BundleLabel string   `json:"bundleLabel,omitempty"`
}

type storeOrderReport struct {
	State      string          `json:"state"` // "pending" | "paid" | "expired" | "soon" | "error"
	OrderID    string          `json:"orderId,omitempty"`
	PaymentURL string          `json:"paymentUrl,omitempty"`
	Item       *storePurchased `json:"item,omitempty"`
	Detail     string          `json:"detail,omitempty"`
	Rc         int             `json:"rc"`
}

type storePurchased struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"` // "proxy" | "vectra_card" | "claude_account"
	Title          string `json:"title"`
	Country        string `json:"country,omitempty"`
	ExpiresAt      string `json:"expiresAt,omitempty"`
	ProxyLine      string `json:"proxyLine,omitempty"`
	CardNumber     string `json:"cardNumber,omitempty"`
	CardExp        string `json:"cardExp,omitempty"`
	CardCVC        string `json:"cardCvc,omitempty"`
	BillingAddress string `json:"billingAddress,omitempty"`
	AmountUSD      int    `json:"amountUsd,omitempty"`
	AccountEmail   string `json:"accountEmail,omitempty"`
	AccountPass    string `json:"accountPass,omitempty"`
	BindService    string `json:"bindService,omitempty"`
}

func storeBaseURL() string {
	if custom := strings.TrimSpace(os.Getenv("AI_GUARD_STORE_URL")); custom != "" {
		return strings.TrimRight(custom, "/")
	}
	return defaultStoreBaseURL
}

func defaultStoreProducts() []storeProduct {
	return []storeProduct{
		{
			ID:        "proxy",
			Title:     "Чистый прокси",
			Subtitle:  "Статический IP без скачков и банов",
			Available: false,
			Countries: []string{"Нидерланды", "Германия", "США", "Финляндия", "Великобритания", "Сингапур", "Япония"},
			Months:    []int{1, 3},
		},
		{
			ID:         "vectra_card",
			Title:      "Карта Vectra Pay",
			Subtitle:   "Для оплаты Claude, ChatGPT и Cursor",
			Available:  false,
			AmountsUSD: []int{20, 100, 200},
		},
		{
			ID:          "claude_account",
			Title:       "Аккаунт Claude",
			Subtitle:    "Верифицированный · можно сразу с IP",
			Available:   false,
			BundleLabel: "Добавить личный IP",
		},
	}
}

func storeFetchCatalog(ctx context.Context) storeCatalogReport {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, storeBaseURL()+"/catalog", nil)
	if err != nil {
		return storeCatalogReport{State: "soon", Products: defaultStoreProducts(), Rc: 0}
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return storeCatalogReport{State: "soon", Products: defaultStoreProducts(), Rc: 0}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return storeCatalogReport{State: "soon", Products: defaultStoreProducts(), Rc: 0}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return storeCatalogReport{State: "soon", Products: defaultStoreProducts(), Rc: 0}
	}
	var parsed struct {
		Products []storeProduct `json:"products"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Products) == 0 {
		return storeCatalogReport{State: "soon", Products: defaultStoreProducts(), Rc: 0}
	}
	anyLive := false
	for _, p := range parsed.Products {
		if p.Available {
			anyLive = true
			break
		}
	}
	state := "soon"
	if anyLive {
		state = "live"
	}
	return storeCatalogReport{State: state, Products: parsed.Products, Rc: 0}
}

func storeCreateOrder(ctx context.Context, payload []byte) storeOrderReport {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, storeBaseURL()+"/orders", bytes.NewReader(payload))
	if err != nil {
		return storeOrderReport{State: "error", Detail: err.Error(), Rc: 1}
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return storeOrderReport{State: "soon", Detail: "Сервис оплаты скоро заработает.", Rc: 1}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return storeOrderReport{State: "error", Detail: err.Error(), Rc: 1}
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
		return storeOrderReport{State: "soon", Detail: "Сервис оплаты скоро заработает.", Rc: 1}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return storeOrderReport{State: "error", Detail: fmt.Sprintf("Сервер ответил %s", resp.Status), Rc: 1}
	}
	var report storeOrderReport
	if err := json.Unmarshal(body, &report); err != nil || report.OrderID == "" {
		return storeOrderReport{State: "error", Detail: "Некорректный ответ сервера оплаты.", Rc: 1}
	}
	if report.State == "" {
		report.State = "pending"
	}
	report.Rc = 0
	return report
}

func storePollOrder(ctx context.Context, orderID string) storeOrderReport {
	cleanID := strings.TrimSpace(orderID)
	if cleanID == "" || strings.ContainsAny(cleanID, "/\\?# ") {
		return storeOrderReport{State: "error", Detail: "Некорректный номер заказа.", Rc: 1}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, storeBaseURL()+"/orders/"+cleanID, nil)
	if err != nil {
		return storeOrderReport{State: "error", Detail: err.Error(), Rc: 1}
	}
	req.Header.Set("User-Agent", "AI-Exit-Guard")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return storeOrderReport{State: "error", Detail: err.Error(), Rc: 1}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return storeOrderReport{State: "error", Detail: err.Error(), Rc: 1}
	}
	if resp.StatusCode != http.StatusOK {
		return storeOrderReport{State: "error", Detail: fmt.Sprintf("Сервер ответил %s", resp.Status), Rc: 1}
	}
	var report storeOrderReport
	if err := json.Unmarshal(body, &report); err != nil || report.State == "" {
		return storeOrderReport{State: "error", Detail: "Некорректный статус заказа.", Rc: 1}
	}
	report.OrderID = cleanID
	report.Rc = 0
	return report
}

func storeCommand(ctx context.Context, action, arg string) int {
	var out any
	switch action {
	case "catalog":
		out = storeFetchCatalog(ctx)
	case "order":
		out = storeCreateOrder(ctx, []byte(arg))
	case "poll":
		out = storePollOrder(ctx, arg)
	default:
		fmt.Fprintln(os.Stderr, "unknown store action:", action)
		return 2
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return 1
	}
	return 0
}
