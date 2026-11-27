# AI Exit Guard Store API Contract

Base URL: `https://api-app.vectra-pro.net/v1/guard` (overrideable via `AI_GUARD_STORE_URL` for staging).

When the backend returns `404` / `503` or is unreachable, the app falls back to a calm «Скоро» state with disabled payment buttons. As soon as `GET /catalog` returns `200 OK` with `"available": true`, the Store activates automatically without requiring an app update.

## 1. `GET /catalog`

Returns available products, prices, and options.

```json
{
  "products": [
    {
      "id": "proxy",
      "title": "Чистый прокси",
      "subtitle": "Статический IP без скачков и банов",
      "available": true,
      "priceLabel": "490 ₽ / мес",
      "countries": ["Нидерланды", "Германия", "США", "Финляндия", "Великобритания", "Сингапур", "Япония"],
      "months": [1, 3]
    },
    {
      "id": "vectra_card",
      "title": "Карта Vectra Pay",
      "subtitle": "Для оплаты Claude, ChatGPT и Cursor",
      "available": true,
      "priceLabel": "от $20",
      "amountsUsd": [20, 100, 200]
    },
    {
      "id": "claude_account",
      "title": "Аккаунт Claude",
      "subtitle": "Верифицированный · можно сразу с IP",
      "available": true,
      "priceLabel": "от 1 490 ₽",
      "bundleLabel": "Добавить личный IP"
    }
  ]
}
```

## 2. `POST /orders`

Creates a payment order and returns a browser checkout URL (SBP / card / crypto via Vectra Pay).

Request examples:
- Proxy: `{"productId": "proxy", "country": "Нидерланды", "months": 1}`
- Vectra Pay card: `{"productId": "vectra_card", "amountUsd": 20}`
- Claude account: `{"productId": "claude_account", "withProxy": true}`

Response (`200` / `201`):
```json
{
  "state": "pending",
  "orderId": "ord_01J...",
  "paymentUrl": "https://pay.vectra-pro.net/checkout/ord_01J..."
}
```

## 3. `GET /orders/{orderId}`

Polled by AI Exit Guard every 3 seconds after opening `paymentUrl`.

Response while unpaid:
```json
{"state": "pending", "orderId": "ord_01J..."}
```

Response when paid (`item.kind` is `"proxy"`, `"vectra_card"`, or `"claude_account"`):
```json
{
  "state": "paid",
  "orderId": "ord_01J...",
  "item": {
    "id": "item_01J...",
    "kind": "vectra_card",
    "title": "Карта Vectra Pay · $20",
    "country": "US",
    "amountUsd": 20,
    "cardNumber": "4815000011119042",
    "cardExp": "09/29",
    "cardCvc": "419",
    "billingAddress": "131 Continental Dr, Newark, DE 19713"
  }
}
```

For `kind: "proxy"` or `kind: "claude_account"` with bundled IP, include `proxyLine` (`socks5://user:pass@host:port`) and optional `bindService` (`"Claude"`). Guard automatically saves the purchase into Keychain (macOS) / DPAPI (Windows) and connects/binds the proxy.
