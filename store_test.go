package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStoreCatalogFallbackSoon(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("AI_GUARD_STORE_URL", srv.URL)
	rep := storeFetchCatalog(context.Background())
	if rep.State != "soon" || rep.Rc != 0 || len(rep.Products) != 3 {
		t.Fatalf("unexpected fallback catalog: %+v", rep)
	}
}

func TestStoreCatalogLiveAndOrderFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"products": []storeProduct{{ID: "proxy", Title: "Чистый прокси", Available: true, PriceLabel: "490 ₽"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/orders":
			_ = json.NewEncoder(w).Encode(storeOrderReport{
				State:      "pending",
				OrderID:    "ord_123",
				PaymentURL: "https://pay.vectra-pro.net/pay/ord_123",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/orders/ord_123":
			_ = json.NewEncoder(w).Encode(storeOrderReport{
				State: "paid",
				Item: &storePurchased{
					ID:        "item_1",
					Kind:      "proxy",
					Title:     "Нидерланды",
					Country:   "NL",
					ProxyLine: "socks5://u:p@nl1.example:1080",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("AI_GUARD_STORE_URL", srv.URL)

	cat := storeFetchCatalog(context.Background())
	if cat.State != "live" || len(cat.Products) != 1 || !cat.Products[0].Available {
		t.Fatalf("expected live catalog, got %+v", cat)
	}
	ord := storeCreateOrder(context.Background(), []byte(`{"productId":"proxy","country":"Нидерланды","months":1}`))
	if ord.Rc != 0 || ord.OrderID != "ord_123" || ord.PaymentURL == "" {
		t.Fatalf("unexpected order response: %+v", ord)
	}
	polled := storePollOrder(context.Background(), "ord_123")
	if polled.Rc != 0 || polled.State != "paid" || polled.Item == nil || polled.Item.ProxyLine == "" {
		t.Fatalf("unexpected poll response: %+v", polled)
	}
}
