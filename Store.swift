import AppKit
import SwiftUI

struct StoreProduct: Codable, Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let available: Bool
    let priceLabel: String?
    let countries: [String]?
    let amountsUsd: [Int]?
    let months: [Int]?
    let bundleLabel: String?
}

struct StorePurchased: Codable, Identifiable {
    let id: String
    let kind: String
    let title: String
    let country: String?
    let expiresAt: String?
    let proxyLine: String?
    let cardNumber: String?
    let cardExp: String?
    let cardCvc: String?
    let billingAddress: String?
    let amountUsd: Int?
    let accountEmail: String?
    let accountPass: String?
    let bindService: String?
}

private struct StoreCatalogReport: Decodable {
    let state: String
    let products: [StoreProduct]?
    let detail: String?
}

private struct StoreOrderReport: Decodable {
    let state: String
    let orderId: String?
    let paymentUrl: String?
    let item: StorePurchased?
    let detail: String?
    let rc: Int?
}

enum StoreVault {
    private static let vaultName = "store"
    static func load() -> [StorePurchased] {
        guard let data = try? LocalVault.read(name: vaultName),
              let decoded = try? JSONDecoder().decode([StorePurchased].self, from: data) else {
            return []
        }
        return decoded
    }
    static func save(_ items: [StorePurchased]) {
        guard let data = try? JSONEncoder().encode(items) else { return }
        try? LocalVault.save(data, name: vaultName)
    }
}

final class StoreModel: ObservableObject {
    @Published var screen: String? = nil
    @Published var products: [StoreProduct] = [
        StoreProduct(id: "proxy", title: "Чистый прокси", subtitle: "Статический IP без скачков и банов",
                     available: false, priceLabel: nil,
                     countries: ["Нидерланды", "Германия", "США", "Финляндия", "Великобритания", "Сингапур", "Япония"],
                     amountsUsd: nil, months: [1, 3], bundleLabel: nil),
        StoreProduct(id: "vectra_card", title: "Карта Vectra Pay", subtitle: "Для оплаты Claude, ChatGPT и Cursor",
                     available: false, priceLabel: nil, countries: nil, amountsUsd: [20, 100, 200], months: nil, bundleLabel: nil),
        StoreProduct(id: "claude_account", title: "Аккаунт Claude", subtitle: "Верифицированный · можно сразу с IP",
                     available: false, priceLabel: nil, countries: nil, amountsUsd: nil, months: nil, bundleLabel: "Добавить личный IP")
    ]
    @Published var purchases: [StorePurchased] = []
    @Published var selectedCountry = "Нидерланды"
    @Published var selectedMonths = 1
    @Published var selectedAmount = 20
    @Published var includePersonalIP = true
    @Published var busy = false
    @Published var statusMessage = ""
    @Published var copiedKey = ""
    @Published var revealedPasswordId = ""
    private var pollTimer: Timer?

    init() {
        purchases = StoreVault.load()
    }

    var isOpen: Bool { screen != nil }

    func open(_ target: String = "list") {
        statusMessage = ""
        screen = target
        refreshCatalog()
    }

    func goBack() {
        pollTimer?.invalidate()
        pollTimer = nil
        statusMessage = ""
        guard let current = screen else { return }
        if current == "list" {
            screen = nil
        } else if current.hasPrefix("item:") {
            screen = "purchases"
        } else {
            screen = "list"
        }
    }

    func product(_ id: String) -> StoreProduct? {
        products.first { $0.id == id }
    }

    func copyText(_ text: String, key: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copiedKey = key
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.3) { [weak self] in
            if self?.copiedKey == key { self?.copiedKey = "" }
        }
    }

    func refreshCatalog() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let p = Process()
            p.executableURL = Bundle.main.resourceURL?.appendingPathComponent("guard")
            p.arguments = ["store-catalog"]
            let out = Pipe()
            p.standardOutput = out
            p.standardError = Pipe()
            guard (try? p.run()) != nil else { return }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            guard let line = data.split(separator: 10).last,
                  let report = try? JSONDecoder().decode(StoreCatalogReport.self, from: Data(line)),
                  let items = report.products, !items.isEmpty else { return }
            DispatchQueue.main.async {
                self?.products = items
            }
        }
    }

    func createOrder(_ payload: [String: Any], onPaid: @escaping (StorePurchased) -> Void) {
        guard !busy,
              let jsonData = try? JSONSerialization.data(withJSONObject: payload),
              let jsonStr = String(data: jsonData, encoding: .utf8) else { return }
        busy = true
        statusMessage = "Создаём заказ…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let p = Process()
            p.executableURL = Bundle.main.resourceURL?.appendingPathComponent("guard")
            p.arguments = ["store-order", jsonStr]
            let out = Pipe()
            p.standardOutput = out
            p.standardError = Pipe()
            var report: StoreOrderReport?
            if (try? p.run()) != nil {
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                if let line = data.split(separator: 10).last {
                    report = try? JSONDecoder().decode(StoreOrderReport.self, from: Data(line))
                }
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.busy = false
                guard let report, (report.rc ?? 1) == 0, let orderId = report.orderId,
                      let urlStr = report.paymentUrl, let url = URL(string: urlStr) else {
                    self.statusMessage = report?.detail ?? "Сервис оплаты скоро заработает."
                    return
                }
                NSWorkspace.shared.open(url)
                self.statusMessage = "Ждём подтверждения оплаты…"
                self.startPolling(orderId: orderId, onPaid: onPaid)
            }
        }
    }

    private func startPolling(orderId: String, onPaid: @escaping (StorePurchased) -> Void) {
        pollTimer?.invalidate()
        var attempts = 0
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] timer in
            guard let self else { timer.invalidate(); return }
            attempts += 1
            if attempts > 100 {
                timer.invalidate()
                self.statusMessage = "Время ожидания оплаты истекло."
                return
            }
            DispatchQueue.global(qos: .utility).async {
                let p = Process()
                p.executableURL = Bundle.main.resourceURL?.appendingPathComponent("guard")
                p.arguments = ["store-poll", orderId]
                let out = Pipe()
                p.standardOutput = out
                p.standardError = Pipe()
                guard (try? p.run()) != nil else { return }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                guard let line = data.split(separator: 10).last,
                      let rep = try? JSONDecoder().decode(StoreOrderReport.self, from: Data(line)) else { return }
                DispatchQueue.main.async {
                    if rep.state == "paid", let item = rep.item {
                        timer.invalidate()
                        self.purchases.insert(item, at: 0)
                        StoreVault.save(self.purchases)
                        self.statusMessage = "Готово! Сохранено в «Мои покупки»."
                        self.screen = "item:" + item.id
                        onPaid(item)
                    } else if rep.state == "expired" || rep.state == "error" {
                        timer.invalidate()
                        self.statusMessage = rep.detail ?? "Заказ не оплачен."
                    }
                }
            }
        }
    }
}

struct StoreView: View {
    @ObservedObject var store: StoreModel
    @ObservedObject var proxy: ProxyClient

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if store.screen == "list" {
                Text("Магазин").font(.title2.bold())
                VStack(spacing: 0) {
                    storeRow(icon: "globe", tint: .blue, title: "Чистый прокси",
                             subtitle: "Статический IP без скачков и банов") { store.screen = "proxy" }
                    Divider()
                    storeRow(icon: "creditcard.fill", tint: .blue, title: "Карта Vectra Pay",
                             subtitle: "Для оплаты Claude, ChatGPT и Cursor") { store.screen = "card" }
                    Divider()
                    storeRow(icon: "sparkles", tint: .orange, title: "Аккаунт Claude",
                             subtitle: "Верифицированный · можно сразу с IP") { store.screen = "claude" }
                }.background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 12))

                VStack(spacing: 0) {
                    storeRow(icon: "checkmark.seal.fill", tint: .green, title: "Мои покупки",
                             subtitle: "Карты, аккаунты и прокси",
                             trailing: store.purchases.isEmpty ? "" : "\(store.purchases.count)") {
                        store.screen = "purchases"
                    }
                }.background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 12))
            } else if store.screen == "proxy" {
                let prod = store.product("proxy")
                let countries = prod?.countries ?? ["Нидерланды", "Германия", "США", "Финляндия", "Великобритания", "Сингапур", "Япония"]
                Text("Чистый прокси").font(.title2.bold())
                Text("Выделенный IP, проверенный для Claude, ChatGPT и Antigravity.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Страна").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Picker("Страна", selection: $store.selectedCountry) {
                        ForEach(countries, id: \.self) { Text($0).tag($0) }
                    }.labelsHidden()
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("Срок").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Picker("Срок", selection: $store.selectedMonths) {
                        Text("1 месяц").tag(1)
                        Text("3 месяца").tag(3)
                    }.pickerStyle(.segmented).labelsHidden()
                }
                orderButton(available: prod?.available == true,
                            title: prod?.available == true ? "Оплатить" : "Оплатить · Скоро") {
                    store.createOrder(["productId": "proxy", "country": store.selectedCountry, "months": store.selectedMonths]) { item in
                        if let line = item.proxyLine, !line.isEmpty {
                            proxy.addPurchasedProxy(country: item.country ?? store.selectedCountry, line: line)
                        }
                    }
                }
                Text("После оплаты прокси сам добавится в Guard и подключится.")
                    .font(.caption).foregroundStyle(.secondary)
            } else if store.screen == "card" {
                let prod = store.product("vectra_card")
                Text("Карта Vectra Pay").font(.title2.bold())
                Text("Предоплаченная Visa с готовым Billing Address под оплату ИИ.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Номинал").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Picker("Номинал", selection: $store.selectedAmount) {
                        Text("$20").tag(20)
                        Text("$100").tag(100)
                        Text("$200").tag(200)
                    }.pickerStyle(.segmented).labelsHidden()
                }
                orderButton(available: prod?.available == true,
                            title: prod?.available == true ? "Выпустить карту" : "Выпустить карту · Скоро") {
                    store.createOrder(["productId": "vectra_card", "amountUsd": store.selectedAmount]) { _ in }
                }
                Text("После оплаты карта появится в «Мои покупки» с копированием в 1 клик.")
                    .font(.caption).foregroundStyle(.secondary)
            } else if store.screen == "claude" {
                let prod = store.product("claude_account")
                Text("Аккаунт Claude").font(.title2.bold())
                Text("Верифицированный аккаунт с доступом к почте.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Добавить личный IP").font(.body.weight(.semibold))
                        Text("Привяжется к Claude автоматически").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Добавить личный IP", isOn: $store.includePersonalIP)
                        .labelsHidden().toggleStyle(.switch).controlSize(.small)
                }.padding(12).background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 10))
                orderButton(available: prod?.available == true,
                            title: prod?.available == true ? "Оплатить" : "Оплатить · Скоро") {
                    store.createOrder(["productId": "claude_account", "withProxy": store.includePersonalIP]) { item in
                        if let line = item.proxyLine, !line.isEmpty {
                            proxy.addPurchasedProxy(country: item.country ?? "US", line: line)
                        }
                    }
                }
                Text("Логин, пароль и почта сохранятся в «Мои покупки».")
                    .font(.caption).foregroundStyle(.secondary)
            } else if store.screen == "purchases" {
                Text("Мои покупки").font(.title2.bold())
                if store.purchases.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Покупок пока нет").font(.headline)
                        Text("Купленные прокси, карты Vectra Pay и аккаунты появятся здесь и сохранятся в Связке ключей macOS.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                     .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 12))
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(store.purchases.enumerated()), id: \.element.id) { idx, item in
                            if idx > 0 { Divider() }
                            let icon = item.kind == "vectra_card" ? "creditcard.fill" : item.kind == "claude_account" ? "sparkles" : "globe"
                            let tint: Color = item.kind == "claude_account" ? .orange : .blue
                            storeRow(icon: icon, tint: tint, title: item.title,
                                     subtitle: item.expiresAt.map { "До " + $0 } ?? "Активно") {
                                store.screen = "item:" + item.id
                            }
                        }
                    }.background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 12))
                }
            } else if let current = store.screen, current.hasPrefix("item:"),
                      let item = store.purchases.first(where: { "item:" + $0.id == current }) {
                Text(item.title).font(.title2.bold())
                VStack(spacing: 0) {
                    if let num = item.cardNumber, !num.isEmpty {
                        copyRow(label: "Номер карты", value: num, key: "num")
                        Divider()
                    }
                    if let exp = item.cardExp, !exp.isEmpty {
                        let cvc = item.cardCvc ?? ""
                        copyRow(label: "Срок и CVC", value: cvc.isEmpty ? exp : "\(exp) · \(cvc)", key: "exp")
                        Divider()
                    }
                    if let addr = item.billingAddress, !addr.isEmpty {
                        copyRow(label: "Billing Address", value: addr, key: "addr")
                    }
                    if let email = item.accountEmail, !email.isEmpty {
                        copyRow(label: "Почта / Логин", value: email, key: "email")
                        Divider()
                    }
                    if let pass = item.accountPass, !pass.isEmpty {
                        let shown = store.revealedPasswordId == item.id
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Пароль").font(.caption2).foregroundStyle(.secondary)
                                Text(shown ? pass : "••••••••••••").font(.system(.caption, design: .monospaced))
                            }
                            Spacer()
                            Button(shown ? "Скрыть" : "Показать") {
                                store.revealedPasswordId = shown ? "" : item.id
                            }.buttonStyle(.borderless).font(.caption)
                            Button(store.copiedKey == "pass" ? "Скопировано" : "Копировать") {
                                store.copyText(pass, key: "pass")
                            }.buttonStyle(.borderless).font(.caption.weight(.semibold))
                        }.padding(12)
                    }
                    if let line = item.proxyLine, !line.isEmpty {
                        copyRow(label: "Строка прокси", value: line, key: "proxy")
                    }
                }.background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 12))
                if let line = item.proxyLine, !line.isEmpty {
                    Button("Подключить этот прокси") {
                        proxy.addPurchasedProxy(country: item.country ?? "", line: line)
                    }.buttonStyle(.borderedProminent)
                }
                Text("Хранится зашифрованно в Связке ключей macOS.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            if !store.statusMessage.isEmpty {
                Text(store.statusMessage).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func storeRow(icon: String, tint: Color, title: String, subtitle: String,
                          trailing: String = "", action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon).foregroundStyle(tint).frame(width: 26, height: 26)
                    .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.body.weight(.semibold))
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if !trailing.isEmpty {
                    Text(trailing).font(.caption).foregroundStyle(.secondary)
                }
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.secondary)
            }.padding(12).contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func copyRow(label: String, value: String, key: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption2).foregroundStyle(.secondary)
                Text(value).font(.system(.caption, design: .monospaced)).lineLimit(1)
            }
            Spacer()
            Button(store.copiedKey == key ? "Скопировано" : "Копировать") {
                store.copyText(value, key: key)
            }.buttonStyle(.borderless).font(.caption.weight(.semibold))
        }.padding(12)
    }

    private func orderButton(available: Bool, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).frame(maxWidth: .infinity)
        }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!available || store.busy)
    }
}
