import SwiftUI

struct GuardPanel: View {
    @ObservedObject var model: Monitor
    @ObservedObject private var proxy: ProxyClient
    @ObservedObject private var store: StoreModel
    @ObservedObject private var updater: AppUpdater
    init(model:Monitor) {
        self.model=model
        self.proxy=model.proxy
        self.store=model.store
        self.updater=model.updater
    }
    private func paused(_ service:String?) -> Bool {
        if proxy.paused {return true}
        guard let service,let plan=proxy.plan else{return false}
        return plan.CommonPaused == true && plan.Profiles[service] == nil
    }
    private func needsProxy(_ service: String?) -> Bool {
        service == "Antigravity" && proxy.plan == nil && !proxy.paused
    }
    private let googleProxyReason = "Guard проверяет выход Google только через настроенный прокси."
    private func hosts(_ service:String) -> [String] {
        Monitor.serviceHosts(service)
    }
    private var selectedHosts:[String] {model.selectedService.map(hosts) ?? model.monitoredHosts}
    private var verdict:Recommendation {model.displayed(selectedHosts)}
    private var proxyMode:Bool { model.proxy.proxyOnly && model.proxy.ready }
    private var appVersion: String? {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    }
    private var obsidianBg: Color { Color(red: 17/255, green: 18/255, blue: 22/255) }
    private var obsidianCard: Color { Color(red: 25/255, green: 27/255, blue: 33/255) }
    private var ambientGlowColor: Color {
        if model.store.isOpen { return Color.blue.opacity(0.16) }
        if paused(model.selectedService) || needsProxy(model.selectedService) || proxyMode { return Color.blue.opacity(0.11) }
        switch verdict {
        case .clear: return Color(red: 52/255, green: 211/255, blue: 153/255).opacity(0.15)
        case .caution: return Color(red: 245/255, green: 158/255, blue: 11/255).opacity(0.15)
        case .avoid: return Color(red: 248/255, green: 113/255, blue: 113/255).opacity(0.16)
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {
                if model.permissions || model.selectedService != nil || model.proxySettings || model.showConnections || model.store.isOpen {
                    Button {
                        if model.store.isOpen { model.store.goBack() }
                        else if model.showConnections {model.showConnections=false}
                        else if model.proxySettings {proxy.replacing=false;model.proxySettings=false}
                        else if model.showHistory {model.showHistory=false}
                        else if model.technical {model.technical=false}
                        else {model.permissions=false;model.selectedService=nil}
                    } label:{
                        Label("Назад",systemImage:"chevron.left")
                    }.buttonStyle(.plain)
                } else {
                    ZStack {
                        RoundedRectangle(cornerRadius: 7, style: .continuous)
                            .fill(LinearGradient(colors: [Color.primary.opacity(0.14), Color.primary.opacity(0.06)], startPoint: .top, endPoint: .bottom))
                            .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Color.primary.opacity(0.14), lineWidth: 1))
                        Image(systemName: "shield")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.primary)
                        Circle()
                            .fill(Color.green)
                            .frame(width: 4, height: 4)
                    }.frame(width: 24, height: 24)
                }
                Text("AI Exit Guard").font(.headline)
                if let appVersion {
                    Text(verbatim: appVersion)
                        .font(.caption2.weight(.medium)).monospacedDigit()
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 5, style: .continuous).strokeBorder(Color.primary.opacity(0.08), lineWidth: 1))
                }
                Spacer()
                if !model.permissions && !model.showConnections && !model.proxySettings && !model.store.isOpen && model.selectedService == nil {
                    Button { model.store.open("list") } label:{
                        HStack(spacing:4) {
                            Image(systemName:"bag.fill").font(.caption2)
                            Text("Магазин").font(.caption.weight(.medium))
                        }
                        .foregroundStyle(Color.accentColor)
                        .padding(.horizontal,10)
                        .padding(.vertical,4.5)
                        .background(Color.accentColor.opacity(0.16),in:Capsule())
                        .overlay(Capsule().strokeBorder(Color.accentColor.opacity(0.32),lineWidth:1))
                    }.buttonStyle(.plain).accessibilityLabel("Магазин")
                    Button {model.permissions=true;model.readPermissions()} label:{
                        Image(systemName:"gearshape")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary.opacity(0.85))
                            .frame(width: 26, height: 26)
                            .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                            .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Color.primary.opacity(0.10), lineWidth: 1))
                    }.buttonStyle(.plain).accessibilityLabel("Настройки")
                }
            }
            if model.store.isOpen {
                StoreView(store:model.store,proxy:model.proxy)
            } else if model.showConnections {
                ConnectionsPanel(list:model.connections,proxy:model.proxy,height:model.connectionHeight)
            } else if model.proxySettings {
                ProxyEditor(proxy:model.proxy, openBuyProxy: { model.proxySettings=false; model.store.open("proxy") })
            } else if model.permissions {
                Text("Настройки").font(.system(size:24,weight:.bold))
                Button("Общий прокси"){model.proxySettings=true}.buttonStyle(.link)
                setting("bell","Уведомления",model.notificationState,model.notificationState=="Разрешены" ? "Тест" : model.notificationState=="Выключены" ? "Настройки" : "Разрешить",model.notifications)
                setting("power","Запуск при входе",model.loginState,model.loginState=="Выключен" ? "Включить" : "Настройки",model.login)
                Divider()
                HStack(alignment:.top,spacing:10) {
                    Image(systemName:"lock.shield").frame(width:24).padding(.top,2)
                    VStack(alignment:.leading,spacing:2) {
                        Text("Защищённый DNS (DoT)")
                        Text(model.systemDNSState.label).font(.caption).foregroundStyle(.secondary)
                        Text("Обходит сбоящий DNS VPN и провайдера через DNS-over-TLS.").font(.caption2).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                    }
                    Spacer(minLength:4)
                    Toggle("Защищённый DNS (DoT)",isOn:Binding(get:{ model.systemDNSEnabled },set:{ model.setSystemDNSEnabled($0) }))
                        .labelsHidden().toggleStyle(.switch).controlSize(.small)
                }.padding(.vertical,6)
                Divider()
                AntigravityPatchRow(patch:model.antigravity)
                AppUpdateRow(updater:model.updater)
                Button("Активные подключения"){model.showConnections=true}.buttonStyle(.link)
                Button(model.reportCopied ? "Отчёт скопирован" : "Скопировать отчёт"){model.copyDiagnosticReport()}.buttonStyle(.link)
                if !model.proxy.managesDomains && model.killSwitch.state != .off {
                    KillSwitchCard(lock:model.killSwitch,proxy:model.proxy)
                }
                if !model.repairedMCPHosts.isEmpty {
                    Text("Временный DNS для MCP").font(.headline)
                    Text(model.repairedMCPHosts.joined(separator: ", ")).font(.caption).textSelection(.enabled)
                    Button("Снять до перезапуска Guard", action: model.suspendMCPDNS)
                }
                Divider()
                Button("Завершить AI Exit Guard"){ NSApp.terminate(nil) }
            } else if model.showHistory, let service=model.selectedService {
                Text("История IP").font(.title2.bold())
                Text("Две смены за 15 минут — предупреждение для новых адресов.").font(.callout)
                ScrollView {
                    VStack(alignment:.leading,spacing:8) {
                        ForEach(hosts(service),id:\.self){host in
                            Text(Monitor.label(host)).font(.headline)
                            let entries=Array(model.history.visits(host).reversed())
                            if entries.isEmpty {Text("Пока нет адресов").foregroundStyle(.secondary)}
                            ForEach(entries.indices,id:\.self){i in
                                let visit=entries[i]
                                HStack {
                                    VStack(alignment:.leading){Text(visit.ip).textSelection(.enabled);Text(visit.last.formatted(date:.abbreviated,time:.shortened)).font(.caption).foregroundStyle(.secondary)}
                                    Spacer()
                                    Text(visit.approved ? "Был разрешён" : "Замечен").font(.caption)
                                }
                            }
                            Divider()
                        }
                    }
                }.frame(height:230)
            } else if model.technical, let service=model.selectedService {
                Text("Технические сведения").font(.title2.bold())
                ForEach(hosts(service),id:\.self){host in
                    Divider()
                    diagnostics(host,service)
                }
                Divider()
                Button(model.reportCopied ? "Отчёт скопирован" : "Скопировать отчёт"){model.copyDiagnosticReport()}.buttonStyle(.link)
            } else {
                if model.selectedService == nil && model.updater.showBanner {
                    UpdateBanner(updater:model.updater)
                }
                if paused(model.selectedService) {
                    VStack(alignment:.leading,spacing:6) {
                        Label("Прокси на паузе",systemImage:"pause.circle").font(.title2.bold())
                        Text("Чтобы продолжить, откройте «Прокси» и подключите сохранённый профиль.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                    }.padding(.vertical,6)
                } else if needsProxy(model.selectedService) {
                    Text("Antigravity").font(.subheadline.weight(.semibold))
                    Label("Нужен прокси", systemImage: "network").font(.title2.bold())
                    Text(googleProxyReason).font(.callout)
                    Button("Настроить общий прокси") { model.proxySettings = true }
                } else if proxyMode && model.selectedService == nil {
                    VStack(alignment:.leading,spacing:6) {
                        Label(model.online ? "Только прокси" : "Нет сети",systemImage:model.online ? "network" : "wifi.slash")
                            .font(.title2.bold())
                        Text(model.online ? "Адрес можно проверить вручную." : "Соединение восстановится, когда появится интернет.")
                            .font(.callout).foregroundStyle(.secondary)
                    }.frame(maxWidth:.infinity,alignment:.leading).padding(.vertical,6)
                } else if proxyMode && model.fresh.isDisjoint(with:selectedHosts) {
                    Text(model.selectedService ?? "Прокси").font(.title2.bold())
                    Text(model.running ? "Проверяем адрес…" : "Адрес ещё не проверен.").foregroundStyle(.secondary)
                } else {
                    let heroTint = Color(nsColor: verdict.color)
                    HStack(spacing: 12) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(heroTint.opacity(0.18))
                                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(heroTint.opacity(0.38), lineWidth: 1))
                            Image(systemName: verdict.symbol)
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundStyle(heroTint)
                        }.frame(width: 36, height: 36)
                        VStack(alignment:.leading,spacing:3) {
                            if let service=model.selectedService {
                                Text(service.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                            }
                            Text(verdict.title).font(.system(size: 16.5, weight: .semibold))
                            Text(model.explanation(for:selectedHosts)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                        }
                    }
                    .padding(12)
                    .frame(maxWidth:.infinity,alignment:.leading)
                    .background(
                        LinearGradient(colors: [heroTint.opacity(0.13), Color.primary.opacity(0.04)], startPoint: .top, endPoint: .bottom),
                        in: RoundedRectangle(cornerRadius:12, style: .continuous)
                    )
                    .overlay(RoundedRectangle(cornerRadius:12, style: .continuous).strokeBorder(heroTint.opacity(0.26), lineWidth: 1))
                }
                if let service=model.selectedService {
                    if !needsProxy(service) {
                        DisclosureGroup("Прокси для "+service) {
                            ServiceProxyEditor(service:service,proxy:model.proxy).id(service).padding(.top,6)
                        }
                    }
                    let routes=hosts(service)
                    if service=="Antigravity" {
                        if !needsProxy(service), let code=model.rows[Monitor.googleHost]?.TraceCountry,!code.isEmpty {
                            LabeledContent("Страна у Google",value:Locale(identifier:"ru").localizedString(forRegionCode:code) ?? code)
                        }
                    } else {
                    usage("В браузере",routes[0])
                    if service=="Claude" {
                        usage("Claude Code · напрямую",routes[1])
                    } else {
                        usage("Codex · вход через ChatGPT",routes[0])
                        usage("Codex · с ключом OpenAI",routes[1])
                    }
                    Text("Оценка по адресу сервиса. При отдельном прокси или другом провайдере маршрут командной строки может отличаться.").font(.caption).foregroundStyle(.secondary)
                    }
                    Button("История IP"){model.showHistory=true}.buttonStyle(.link)
                    Button("Технические сведения"){model.technical=true}.buttonStyle(.link)
                    Button(model.reportCopied ? "Отчёт скопирован" : "Скопировать отчёт"){model.copyDiagnosticReport()}.buttonStyle(.link)
                } else {
                    VStack(alignment:.leading,spacing:0){
                        Text("СЕРВИСЫ").font(.system(size: 10.5, weight: .semibold)).foregroundStyle(.secondary).padding(.bottom,5)
                        serviceRow("Claude","sun.max.fill",.orange)
                        Divider().opacity(0.5)
                        serviceRow("ChatGPT","bubble.left.and.bubble.right.fill",.teal)
                        Divider().opacity(0.5)
                        serviceRow("Antigravity","sparkles",.indigo)
                    }
                    .padding(12)
                    .background(obsidianCard,in:RoundedRectangle(cornerRadius:12, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius:12, style: .continuous).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
                }
                if model.selectedService == nil {
                    MainProxyCard(monitor:model,proxy:proxy)
                    Button {model.showConnections=true} label:{
                        HStack(spacing: 10) {
                            squircleIcon("arrow.left.arrow.right", tint: .secondary)
                            Text("Активные подключения").font(.body.weight(.medium))
                            Spacer()
                            Image(systemName:"chevron.right").font(.caption2).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .background(obsidianCard,in:RoundedRectangle(cornerRadius:12, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius:12, style: .continuous).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
                        .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    VectraConnectBanner()
                }
                if !needsProxy(model.selectedService) {
                    Divider()
                    HStack{
                        if model.running { ProgressView().controlSize(.small).accessibilityLabel("Идёт проверка") }
                        VStack(alignment:.leading,spacing:2){
                            Text(model.running ? "Проверяем адрес…" : model.fresh.compactMap{model.rows[$0]?.Checked}.max().flatMap{ISO8601DateFormatter().date(from:$0)}.map{"Проверено в "+$0.formatted(date:.omitted,time:.shortened)} ?? "Адрес ещё не проверен").font(.caption)
                            if model.proxy.expected.isEmpty && !proxy.paused { Text("Только наблюдение").font(.caption).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        Button(action:model.check){Text("Проверить адрес")}.buttonStyle(.borderedProminent).disabled(model.running || !model.online || !model.directProbeAllowed)
                    }
                }
            }
        }.padding(18).frame(width:408).fixedSize(horizontal:false,vertical:true)
        .background(
            ZStack(alignment: .top) {
                obsidianBg
                RadialGradient(colors: [ambientGlowColor, Color.clear], center: .top, startRadius: 10, endRadius: 240)
            }
        )
        .preferredColorScheme(.dark)
        .onAppear { model.updater.checkOnce() }
    }
    func usage(_ label:String,_ host:String)->some View {
        HStack {
            Text(label);Spacer()
            if paused(model.selectedService) {Text("На паузе").font(.caption).foregroundStyle(.secondary)}
            else if proxyMode && !model.fresh.contains(host) {Text("Нет проверки").font(.caption).foregroundStyle(.secondary)}
            else {status(model.displayed([host]))}
        }
    }
    func squircleIcon(_ symbol:String, tint:Color) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(tint == .secondary ? Color.primary.opacity(0.06) : tint.opacity(0.14))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(tint == .secondary ? Color.primary.opacity(0.10) : tint.opacity(0.26), lineWidth: 1))
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(tint)
        }.frame(width: 28, height: 28)
    }
    func status(_ state:Recommendation)->some View {
        let label: String
        switch state {
        case .clear: label = "Низкий риск"
        case .caution: label = proxyMode ? "Есть замечание" : "Повремените"
        case .avoid: label = proxyMode ? "Высокий риск" : "Не входить"
        }
        let tint = Color(nsColor: state.color)
        return Label(label,systemImage:state.symbol)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 8).padding(.vertical, 3.5)
            .background(tint.opacity(0.13), in: Capsule())
            .overlay(Capsule().strokeBorder(tint.opacity(0.26), lineWidth: 1))
    }
    func serviceRow(_ name:String,_ symbol:String,_ tint:Color)->some View {
        let routes = hosts(name)
        let checkedRoutes = proxyMode ? routes.filter { model.fresh.contains($0) } : routes
        let state = model.displayed(routes)
        let finding = routes.map { model.displayedFinding($0) }.max { $0.rawValue < $1.rawValue }
        return Button { model.selectedService=name; model.technical=false } label: {
            HStack(alignment:.center,spacing:10) {
                squircleIcon(symbol, tint: tint)
                VStack(alignment:.leading,spacing:2) {
                    Text(name).font(.body.weight(.semibold))
                    if needsProxy(name) {
                        Text(googleProxyReason).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                    } else if !paused(name), !checkedRoutes.isEmpty, let finding {
                        let subtitle: String = !model.online ? "Нет сети"
                            : (finding.verdict == .clear && state != .clear ? "Ждём подтверждения прокси"
                            : (model.shortIssue(for: routes) ?? finding.shortReason))
                        Text(subtitle)
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                    }
                }
                Spacer(minLength: 6)
                if paused(name) {
                    Text("На паузе").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
                        .padding(.horizontal, 8).padding(.vertical, 3.5)
                        .background(Color.primary.opacity(0.06), in: Capsule())
                } else if needsProxy(name) {
                    Text("Нужен прокси").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
                        .padding(.horizontal, 8).padding(.vertical, 3.5)
                        .background(Color.primary.opacity(0.06), in: Capsule())
                } else if checkedRoutes.isEmpty {
                    Text(model.proxy.plan?.Profiles[name] == nil ? "Общий прокси" : "Свой прокси")
                        .font(.caption2.weight(.medium)).foregroundStyle(.secondary)
                        .padding(.horizontal, 8).padding(.vertical, 3.5)
                        .background(Color.primary.opacity(0.06), in: Capsule())
                } else { status(state) }
                Image(systemName:"chevron.right").font(.caption2).foregroundStyle(.secondary)
            }.padding(.vertical,8).contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityElement(children:.combine)
    }
    func setting(_ icon:String,_ title:String,_ status:String,_ action:String,_ f:@escaping()->Void)->some View{
        HStack{ Image(systemName:icon).frame(width:24); VStack(alignment:.leading){Text(title);Text(status).font(.caption).foregroundStyle(.secondary)};Spacer();Button(action,action:f) }.padding(.vertical,6)
    }
    @ViewBuilder func diagnostics(_ host:String,_ name:String)->some View {
                if let r=model.rows[host]{
                    let current=model.fresh.contains(host)
                    VStack(alignment:.leading,spacing:3){
                        Text(r.Host).fontWeight(.semibold)
                        Text(current ? model.finding(r.Host).explanation : "Предыдущая проверка")
                        if !r.Detail.isEmpty {Text("Подробности: "+r.Detail)}
                        if let code=r.TraceCountry, !code.isEmpty {Text("Страна выхода   "+(Locale(identifier:"ru").localizedString(forRegionCode:code) ?? code))}
                        if !r.IP.isEmpty {Text("IP проверки домена   "+r.IP)}
                        if !r.AssessmentIP.isEmpty {Text("IP соединения с IP123   "+r.AssessmentIP)}
                        if let trust=r.Trust {Text("Доверие "+name+"   "+String(format:"%.1f",trust)+"/100 · выше лучше")}
                        if let risk=r.Risk {Text("Общий риск IP123   "+String(format:"%.1f",risk)+"/100 · ниже лучше")}
                        else if !r.RiskDetail.isEmpty {Text("Общий риск: "+r.RiskDetail)}
                        if !r.Network.isEmpty || !r.Country.isEmpty {Text("IPinfo для "+r.IP+"  ·  "+[r.Country,r.Network].filter{!$0.isEmpty}.joined(separator:" · "))}
                        if let tags=r.Signals,!tags.isEmpty {Text("IPinfo · признаки адреса   "+tags.joined(separator:", "))}
                        if !r.InfoDetail.isEmpty {Text("IPinfo: "+r.InfoDetail)}
                    }.font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
    }
}

private struct UpdateBanner:View {
    @ObservedObject var updater:AppUpdater
    var body:some View {
        HStack(spacing:10) {
            Image(systemName:"arrow.down.circle.fill").foregroundStyle(.blue).frame(width:20)
            VStack(alignment:.leading,spacing:2) {
                Text("Доступно обновление \(updater.latest)").font(.caption.weight(.semibold))
                Text("Загрузка с GitHub").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            Button(updater.busy ? "Загрузка…" : "Обновить"){ updater.install() }
                .buttonStyle(.borderedProminent).controlSize(.small).disabled(updater.busy)
        }.padding(10).background(Color.blue.opacity(0.10),in:RoundedRectangle(cornerRadius:10))
    }
}

private struct VectraConnectBanner:View {
    var body:some View {
        HStack(spacing:10) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.blue.opacity(0.16))
                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.blue.opacity(0.28), lineWidth: 1))
                Image(systemName:"bolt.shield.fill").font(.system(size: 13.5, weight: .medium)).foregroundStyle(.blue)
            }.frame(width:28, height:28)
            VStack(alignment:.leading,spacing:2) {
                Text("Vectra Connect").font(.subheadline.weight(.semibold))
                Text("Лучший VPN-сервис для быстрой и стабильной работы")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
            }
            Spacer(minLength:4)
            Button("Открыть") {
                if let url = URL(string:"https://pay.vectra-pro.net/store") {
                    NSWorkspace.shared.open(url)
                }
            }.controlSize(.small)
        }
        .padding(12)
        .background(
            LinearGradient(colors: [Color(red: 37/255, green: 99/255, blue: 235/255).opacity(0.20), Color(red: 24/255, green: 28/255, blue: 38/255)], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius:12, style: .continuous)
        )
        .overlay(RoundedRectangle(cornerRadius:12, style: .continuous).strokeBorder(Color.blue.opacity(0.26), lineWidth: 1))
    }
}

private struct AppUpdateRow:View {
    @ObservedObject var updater:AppUpdater
    var body:some View {
        HStack(alignment:.top,spacing:10) {
            Image(systemName:"arrow.down.app").frame(width:24).padding(.top,2)
            VStack(alignment:.leading,spacing:2) {
                Text("Обновления Guard")
                Text(updater.summary).font(.caption)
                    .foregroundStyle(updater.state=="error" ? Color.red : updater.hasUpdate ? Color.blue : Color.secondary)
                    .fixedSize(horizontal:false,vertical:true)
            }
            Spacer(minLength:4)
            if updater.hasUpdate {
                Button("Обновить"){ updater.install() }.buttonStyle(.borderedProminent).disabled(updater.busy)
            } else {
                Button("Проверить"){ updater.check() }.disabled(updater.busy)
            }
        }.padding(.vertical,6)
    }
}

private struct AntigravityPatchRow:View {
    @ObservedObject var patch:AntigravityPatch
    var body:some View {
        HStack(alignment:.top,spacing:10) {
            Image(systemName:"wrench.and.screwdriver").frame(width:24).padding(.top,2)
            VStack(alignment:.leading,spacing:2) {
                Text("Патч Antigravity")
                Label(patch.title,systemImage:patch.symbol)
                    .font(.caption).foregroundStyle(patch.tint)
                if !patch.subtitle.isEmpty {
                    Text(patch.subtitle).font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal:false,vertical:true)
                }
                if !patch.actionError.isEmpty {
                    Text(patch.actionError).font(.caption2).foregroundStyle(Color.red)
                        .fixedSize(horizontal:false,vertical:true)
                }
                if !patch.updateNote.isEmpty {
                    Text(patch.updateNote)
                        .font(.caption2)
                        .foregroundStyle(patch.update=="error" ? Color.red : Color.secondary)
                        .fixedSize(horizontal:false,vertical:true)
                }
                if patch.canInstallUpdate {
                    Button("Обновить патчер"){ patch.installUpdate() }
                        .buttonStyle(.link).font(.caption)
                }
            }
            Spacer(minLength:4)
            HStack(spacing:6) {
                Button { patch.checkUpdate() } label:{ Image(systemName:"arrow.triangle.2.circlepath") }
                    .buttonStyle(.borderless).disabled(patch.busy)
                    .accessibilityLabel("Проверить обновление патчера")
                Button { patch.refresh() } label:{ Image(systemName:"arrow.clockwise") }
                    .buttonStyle(.borderless).disabled(patch.busy)
                    .accessibilityLabel("Проверить состояние патча")
                if patch.canRestore {
                    Button("Восстановить"){ patch.restore() }.disabled(patch.busy)
                } else {
                    Button("Пропатчить"){ patch.apply() }
                        .buttonStyle(.borderedProminent).disabled(!patch.canPatch)
                }
            }
        }.padding(.vertical,6)
        .onAppear { patch.refresh() }
    }
}

private struct MainProxyCard:View {
    @ObservedObject var monitor:Monitor
    @ObservedObject var proxy:ProxyClient
    private var state:(String,Color,String) {
        if proxy.ready && proxy.plan?.CommonPaused==true{return ("Отдельные маршруты",.secondary,"network")}
        if proxy.busy {return ("Проверяем…",.secondary,"clock")}
        if proxy.paused {return ("На паузе",.secondary,"pause.circle")}
        if proxy.expected.isEmpty {return ("Выключен",.secondary,"circle")}
        if !proxy.ready || !monitor.online {return ("Нет соединения",.orange,"exclamationmark.circle.fill")}
        return ("Подключён",.secondary,"network")
    }
    var body:some View {
        let status=state
        VStack(alignment:.leading,spacing:10) {
            Button { monitor.proxySettings=true } label: {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color.blue.opacity(0.14))
                            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.blue.opacity(0.26), lineWidth: 1))
                        Image(systemName:"network").font(.system(size: 13, weight: .medium)).foregroundStyle(.blue)
                    }.frame(width: 28, height: 28)
                    Text("Прокси").font(.body.weight(.semibold))
                    Spacer()
                    let isConnected = proxy.ready && monitor.online && proxy.plan?.CommonPaused != true
                    Text(proxy.expected.isEmpty && !proxy.paused && !proxy.busy ? "Добавить прокси" : status.0)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(isConnected ? Color.green : status.1)
                        .padding(.horizontal, 8).padding(.vertical, 3.5)
                        .background((isConnected ? Color.green : Color.primary).opacity(isConnected ? 0.13 : 0.06), in: Capsule())
                        .overlay(Capsule().strokeBorder((isConnected ? Color.green : Color.primary).opacity(isConnected ? 0.26 : 0.10), lineWidth: 1))
                    Image(systemName:"chevron.right").font(.caption2).foregroundStyle(.secondary)
                }.contentShape(Rectangle())
            }.buttonStyle(.plain)
            if !proxy.routeWarning.isEmpty {
                Text(proxy.routeWarning).font(.caption).foregroundStyle(.orange)
            }
            if proxy.expected.isEmpty && !proxy.paused && !proxy.ready {
                Divider()
                ProxyFields(actionTitle: "Подключить", busy: proxy.busy, apply: proxy.connect)
                if !proxy.message.isEmpty {
                    Text(proxy.message).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                }
            } else if proxy.ready {
                Divider()
                HStack(spacing:12) {
                    VStack(alignment:.leading,spacing:3) {
                        Text("Защита по IP").font(.body.weight(.medium))
                        Text(proxy.proxyOnly ? "Guard только предупреждает о риске." : "При опасном IP Guard блокирует запросы к ИИ через прокси.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
                    }
                    Spacer(minLength:4)
                    Toggle("Защита по IP",isOn:Binding(get:{ !proxy.proxyOnly },set:{ monitor.setProxyOnly(!$0) }))
                        .labelsHidden().toggleStyle(.switch).controlSize(.small)
                }
            } else {
                Divider()
                HStack {
                    Text("Защита по IP").font(.body.weight(.medium))
                    Spacer()
                    Text(proxy.paused ? "На паузе" : "Неактивна").font(.caption).foregroundStyle(.secondary)
                }
                Text("Блокировка по оценке IP доступна при подключённом прокси.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
            }
        }.padding(12)
         .background(Color(red: 25/255, green: 27/255, blue: 33/255),in:RoundedRectangle(cornerRadius:12, style: .continuous))
         .overlay(RoundedRectangle(cornerRadius:12, style: .continuous).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))

    }
}

private final class ServiceProxyForm: ObservableObject { @Published var editing = false }

private struct ServiceProxyEditor:View {
    let service:String
    @ObservedObject var proxy:ProxyClient
    @StateObject private var form = ServiceProxyForm()
    var body:some View {
        VStack(alignment:.leading,spacing:8){
            if proxy.plan == nil {Text("На главном экране нажмите «Прокси» и подключите общий адрес.").font(.callout)}
            else {
                Picker("Маршрут",selection:Binding(get:{form.editing || proxy.plan?.Profiles[service] != nil},set:{individual in
                    if individual {form.editing=true}
                    else {form.editing=false;if proxy.plan?.Profiles[service] != nil {proxy.useCommon(service)}}
                })){
                    Text("Общий").tag(false);Text("Индивидуальный").tag(true)
                }.pickerStyle(.segmented).disabled(proxy.busy)
                if form.editing {
                    ProxyFields(endpoint: proxy.plan?.Profiles[service]?.Endpoint, actionTitle: "Проверить и применить", busy: proxy.busy) { line, scheme in
                        proxy.useIndividual(service, line: line, scheme: scheme)
                    }
                } else {
                    HStack{Text("IP выхода");Spacer();Text(proxy.expectedIP(service)).monospacedDigit()
                        if proxy.plan?.Profiles[service] != nil {Button("Изменить"){form.editing=true}}
                    }.font(.callout)
                }
                if !proxy.profileMessage.isEmpty {Text(proxy.profileMessage).font(.caption).foregroundStyle(.secondary)}
            }
        }.onAppear{proxy.profileMessage=""}.onReceive(proxy.$profileMessage){note in
            if note=="Маршрут сохранён." {form.editing=false}
        }
    }
}
