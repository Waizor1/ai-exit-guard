import SwiftUI

struct GuardPanel: View {
    @ObservedObject var model: Monitor
    private let services = ["Claude", "ChatGPT"]
    private func hosts(_ service:String) -> [String] {
        service == "Claude" ? Array(Monitor.hosts.prefix(2)) : Array(Monitor.hosts.suffix(2))
    }
    private var selectedHosts:[String] {model.selectedService.map(hosts) ?? Monitor.hosts}
    private var verdict:Recommendation {model.displayed(selectedHosts)}
    private var reason:String {
        if !model.online {return "Подключитесь к интернету. Проверка начнётся автоматически."}
        if !model.directProbeAllowed && !model.proxy.expected.isEmpty {return "Маршрут прокси не подтверждён. Проверьте подключение в настройках Guard."}
        if !model.directProbeAllowed {return "Системный прокси мешает проверить подключение. Отложите вход."}
        if !model.proxy.expected.isEmpty && !model.proxy.allowsTraffic() && verdict != .avoid {
            return "Доступ через Guard закрыт до полной проверки четырёх маршрутов."
        }
        let worst=selectedHosts.map {model.displayedFinding($0)}.max { $0.rawValue < $1.rawValue } ?? .waiting
        return worst.explanation
    }
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            HStack {
                if model.permissions || model.selectedService != nil || model.proxySettings || model.showConnections {
                    Button { if model.showConnections {model.showConnections=false} else if model.proxySettings {model.proxySettings=false} else if model.showHistory {model.showHistory=false} else if model.technical {model.technical=false} else {model.permissions=false;model.selectedService=nil} } label:{
                        Label("Назад",systemImage:"chevron.left")
                    }.buttonStyle(.plain)
                } else {
                    Image(systemName:"shield.checkered").foregroundStyle(.secondary)
                    Text("AI Exit Guard").fontWeight(.semibold)
                }
                Spacer()
                if !model.permissions && !model.showConnections && !model.proxySettings && model.selectedService == nil {
                    Button {model.permissions=true;model.readPermissions()} label:{Image(systemName:"gearshape").padding(4)}.buttonStyle(.plain).accessibilityLabel("Настройки")
                }
            }
            if model.showConnections {
                ConnectionsPanel(list:model.connections,proxy:model.proxy,height:model.connectionHeight)
            } else if model.proxySettings {
                ProxyEditor(proxy:model.proxy)
            } else if model.permissions {
                Text("Настройки").font(.system(size:24,weight:.bold))
                Text("Проверяется соединение AI Exit Guard с доменом. При отдельных правилах Happ для приложений выход может отличаться.").font(.callout).foregroundStyle(.secondary)
                Button("Прокси для Claude и ChatGPT"){model.proxySettings=true}.buttonStyle(.link)
                setting("bell","Уведомления",model.notificationState,model.notificationState=="Разрешены" ? "Тест" : model.notificationState=="Выключены" ? "Настройки" : "Разрешить",model.notifications)
                setting("power","Запуск при входе",model.loginState,model.loginState=="Выключен" ? "Включить" : "Настройки",model.login)
                Button("Инструкция"){ NSWorkspace.shared.open(Bundle.main.resourceURL!.appendingPathComponent("Инструкция.txt")) }
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
            } else {
                if model.selectedService==nil { MainProxyCard(monitor:model,proxy:model.proxy); KillSwitchCard(lock:model.killSwitch,proxy:model.proxy) }
                VStack(alignment:.leading,spacing:9){
                    Label((model.selectedService ?? "Claude и ChatGPT")+(!model.proxy.expected.isEmpty ? " · через Guard" : ""),systemImage:verdict.symbol)
                        .font(.subheadline.weight(.semibold)).foregroundStyle(Color(nsColor:verdict.color))
                    Text(verdict.title).font(.system(size:25,weight:.bold))
                    Text(reason).font(.body).fixedSize(horizontal:false,vertical:true)
                }.padding(16).frame(maxWidth:.infinity,alignment:.leading)
                 .background(Color(nsColor:verdict.color).opacity(0.10),in:RoundedRectangle(cornerRadius:14))
                if let service=model.selectedService {
                    let routes=hosts(service)
                    usage("В браузере",routes[0])
                    if service=="Claude" {
                        usage("Claude Code · напрямую",routes[1])
                    } else {
                        usage("Codex · вход через ChatGPT",routes[0])
                        usage("Codex · с ключом OpenAI",routes[1])
                    }
                    Text("Оценка по адресу сервиса. При отдельном прокси или другом провайдере маршрут командной строки может отличаться.").font(.caption).foregroundStyle(.secondary)
                    Button("История IP"){model.showHistory=true}.buttonStyle(.link)
                    Button("Технические сведения"){model.technical=true}.buttonStyle(.link)
                } else {
                    VStack(spacing:0){
                        serviceRow("Claude","sun.max.fill",.orange)
                        Divider()
                        serviceRow("ChatGPT","bubble.left.and.bubble.right.fill",.teal)
                    }.padding(.horizontal,10)
                }
                if !model.proxy.expected.isEmpty && model.guardOnly {
                    Text("VPN управляет другими приложениями. Открывайте ИИ отсюда.").font(.callout)
                    HStack {
                        Button("Открыть Claude"){model.proxy.openService("Claude")}
                        Button("Открыть ChatGPT"){model.proxy.openService("ChatGPT")}
                        Button("CLI"){model.proxySettings=true}
                    }.disabled(!model.proxy.ready)
                }
                if model.selectedService==nil {Button("Подключения приложений"){model.showConnections=true}.buttonStyle(.link)}
                Divider()
                HStack{
                    ZStack { if model.running { ProgressView().controlSize(.small).accessibilityLabel("Идёт проверка") } }.frame(width:16,height:16)
                    VStack(alignment:.leading,spacing:2){
                        Text(model.running ? "Обновляем последнюю оценку…" : model.fresh.compactMap{model.rows[$0]?.Checked}.max().map{"Проверено в "+String($0.dropFirst(11).prefix(5))} ?? "Ожидаем проверку").font(.caption)
                        Text(model.proxy.expected.isEmpty ? "Только наблюдение" : "Прокси для ИИ").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(action:model.check){Text("Проверить снова")}.buttonStyle(.borderedProminent).disabled(model.running || !model.online || !model.directProbeAllowed)
                }
            }
        }.padding(18).frame(width:model.showConnections ? 408 : 370).fixedSize(horizontal:false,vertical:true)
    }
    func usage(_ label:String,_ host:String)->some View {
        HStack {Text(label);Spacer();status(model.displayed([host]))}
    }
    func status(_ state:Recommendation)->some View {
        Label(state == .clear ? "Низкий риск" : state == .avoid ? "Не входить" : "Повремените",systemImage:state.symbol)
            .font(.caption.weight(.semibold)).foregroundStyle(Color(nsColor:state.color))
    }
    func serviceRow(_ name:String,_ symbol:String,_ tint:Color)->some View {
        let state=model.displayed(hosts(name))
        return Button{model.selectedService=name;model.technical=false} label:{
            HStack(spacing:9){
                Image(systemName:symbol).foregroundStyle(tint).frame(width:24)
                Text(name).font(.body.weight(.semibold));Spacer();status(state)
                Image(systemName:"chevron.right").font(.caption2).foregroundStyle(.secondary)
            }.padding(.vertical,10).contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityLabel(name+" · "+state.title)
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

private struct MainProxyCard:View {
    @ObservedObject var monitor:Monitor
    @ObservedObject var proxy:ProxyClient
    private var matches:Bool {
        monitor.online && monitor.fresh.count==Monitor.hosts.count &&
        Monitor.hosts.allSatisfy{monitor.rows[$0]?.IP==proxy.expected}
    }
    private var state:(String,Color,String) {
        if proxy.busy {return ("Проверяем…",.secondary,"clock")}
        if proxy.expected.isEmpty {return ("Выключен",.secondary,"circle")}
        if !proxy.ready || !monitor.online {return ("Нет соединения",.orange,"exclamationmark.circle.fill")}
        if monitor.displayed(Monitor.hosts) == .avoid {return ("Доступ закрыт",.red,"lock.fill")}
        if !proxy.allowsTraffic() {return ("Ждём проверки",.orange,"lock.fill")}
        if monitor.guardOnly {return ("Через Guard",.green,"checkmark.circle.fill")}
        if matches {return ("Прокси проверен",.green,"checkmark.circle.fill")}
        if let host=Monitor.hosts.first(where:{monitor.fresh.contains($0) && monitor.rows[$0]?.IP.isEmpty==false && monitor.rows[$0]?.IP != proxy.expected}) {
            let service=Monitor.hosts.prefix(2).contains(host) ? "Claude" : "ChatGPT"
            return (service+" видит другой IP",.red,"exclamationmark.octagon.fill")
        }
        return monitor.running ? ("Проверяем…",.secondary,"clock") : ("Нет ответа от сервиса",.orange,"exclamationmark.circle.fill")
    }
    var body:some View {
        let status=state
        VStack(alignment:.leading,spacing:9) {
            HStack{
                Label("Прокси",systemImage:"network").font(.headline)
                Spacer()
                Label(status.0,systemImage:status.2).font(.caption.weight(.semibold)).foregroundStyle(status.1)
            }
            if proxy.expected.isEmpty {
                HStack{
                    SecureField("логин:пароль@адрес:порт",text:$proxy.draft)
                        .textFieldStyle(.roundedBorder).accessibilityLabel("Строка прокси")
                    Button("Вставить"){proxy.draft=NSPasteboard.general.string(forType:.string) ?? ""}
                }
                HStack{
                    Picker("Тип",selection:$proxy.scheme){
                        Text("HTTP").tag("http");Text("HTTPS").tag("https");Text("SOCKS5").tag("socks5")
                    }.fixedSize()
                    Spacer();Button("Подключить"){proxy.connect(proxy.draft,proxy.scheme)}.buttonStyle(.borderedProminent).disabled(proxy.draft.isEmpty || proxy.busy)
                }
                if !proxy.message.isEmpty {Text(proxy.message).font(.caption).foregroundStyle(.secondary)}
            } else {
                HStack{
                    Text(proxy.expected).font(.system(.callout,design:.monospaced)).textSelection(.enabled)
                    Spacer()
                    Button("Отключить"){proxy.disconnect()}.controlSize(.small)

                }
                if monitor.guardOnly {
                    Button("Применить для Happ"){proxy.applyTunnelRoute(force:true)}.buttonStyle(.link)
                }
            }
        }.padding(12).background(.quaternary.opacity(0.45),in:RoundedRectangle(cornerRadius:11))
    }
}
