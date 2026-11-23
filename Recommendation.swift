import AppKit

enum Recommendation: Int, CaseIterable {
    case clear, caution, avoid

    var title: String {
        switch self {
        case .clear: return "Риска не обнаружено"
        case .caution: return "Есть замечания"
        case .avoid: return "Нельзя пользоваться"
        }
    }
    var symbol: String {
        switch self {
        case .clear: return "checkmark.circle.fill"
        case .caution: return "exclamationmark.triangle.fill"
        case .avoid: return "xmark.octagon.fill"
        }
    }
    var color: NSColor {
        switch self {
        case .clear: return .systemGreen
        case .caution: return .systemOrange
        case .avoid: return .systemRed
        }
    }
    var trayIcon:NSImage {
        let image=NSImage(size:NSSize(width:20,height:18),flipped:false){ _ in
            let shield=NSBezierPath()
            shield.move(to:NSPoint(x:10,y:17))
            shield.line(to:NSPoint(x:18,y:14))
            shield.line(to:NSPoint(x:17.5,y:8))
            shield.curve(to:NSPoint(x:10,y:1),controlPoint1:NSPoint(x:17,y:5),controlPoint2:NSPoint(x:13,y:2))
            shield.curve(to:NSPoint(x:2.5,y:8),controlPoint1:NSPoint(x:7,y:2),controlPoint2:NSPoint(x:3,y:5))
            shield.line(to:NSPoint(x:2,y:14));shield.close()
            self.color.setFill();shield.fill()
            let mark=NSBezierPath()
            mark.lineWidth=2;mark.lineCapStyle = .round;mark.lineJoinStyle = .round
            switch self {
            case .clear:
                mark.move(to:NSPoint(x:6.4,y:9));mark.line(to:NSPoint(x:9,y:6.5));mark.line(to:NSPoint(x:13.8,y:12))
            case .caution:
                mark.move(to:NSPoint(x:10,y:12.8));mark.line(to:NSPoint(x:10,y:9))
                mark.move(to:NSPoint(x:10,y:6));mark.line(to:NSPoint(x:10,y:5.9))
            case .avoid:
                mark.move(to:NSPoint(x:7.4,y:11.7));mark.line(to:NSPoint(x:12.6,y:6.5))
                mark.move(to:NSPoint(x:12.6,y:11.7));mark.line(to:NSPoint(x:7.4,y:6.5))
            }
            NSColor(white:0.09,alpha:1).setStroke();mark.stroke()
            return true
        }
        image.isTemplate=false
        return image
    }
    static func summarize(_ routes: [Self]) -> Self {
        routes.max { $0.rawValue < $1.rawValue } ?? .caution
    }
}

// Higher-priority evidence supplies the single explanation shown in the panel.
enum Finding: Int {
    case clear, reputationOnly, waiting, incomplete, changingIP, regionUncertain, policyExpired,
         trustUnavailable, infoUnavailable, riskUnavailable, regionUnknown, regionConflict, domainUnavailable, moderateIP, moderateAI,
         frequentSwitch, riskyIP, riskyAI, unsupportedCountry, differentExit

    var verdict: Recommendation {
        switch self {
        case .clear: return .clear
        case .frequentSwitch, .riskyIP, .riskyAI, .unsupportedCountry, .differentExit: return .avoid
        default: return .caution
        }
    }
    var explanation: String {
        switch self {
        case .clear: return "Можно входить. Страна поддерживается, у адреса хорошая репутация."
        case .reputationOnly: return "Страна и репутация адреса проверены. IP123 оценил другой выход для ИИ."
        case .waiting: return "Дождитесь окончания проверки."
        case .incomplete: return "Нет свежего результата. Повторите проверку перед входом."
        case .changingIP: return "Интернет-адрес изменился. Подождите: Guard сам проверит, стабилен ли он."
        case .regionUncertain: return "В стране есть региональные исключения. Уточните местоположение перед входом."
        case .policyExpired: return "Список доступных стран устарел. Сверьте страну со списком сервиса."
        case .trustUnavailable: return "IP123 не вернул оценку для ИИ. Повторите проверку перед входом."
        case .infoUnavailable: return "IPinfo не подтвердил сведения об адресе. Guard повторит проверку."
        case .riskUnavailable: return "Репутацию адреса проверить не удалось. Повторите проверку перед входом."
        case .regionConflict: return "Домен и IPinfo указывают разные страны для этого IP. Уточните выход перед входом."
        case .regionUnknown: return "Сервис не подтвердил страну выхода. Повторите проверку перед входом."
        case .domainUnavailable: return "Сервис пока не ответил на проверку. Перед входом нажмите «Проверить снова»."
        case .moderateIP: return "У адреса средний риск по IP123. Лучше сменить выход перед входом."
        case .moderateAI: return "У адреса средняя оценка доверия для ИИ. Лучше сменить выход."
        case .differentExit: return "Выход отличается от выбранного прокси. Переподключите прокси перед входом."
        case .frequentSwitch: return "Адрес менялся несколько раз за 15 минут. Вернитесь к разрешённому адресу из истории или отложите вход."
        case .riskyIP: return "IP123 отметил высокий риск адреса. Смените выход перед входом."
        case .riskyAI: return "IP123 дал красную оценку этому выходу для ИИ. Смените выход."
        case .unsupportedCountry: return "Сервис не поддерживает страну выхода. Не входите с этого адреса."
        }
    }
}

enum RegionPolicy {
    // Official lists checked 2026-11-22. Sources are included in the bundled guide.
    private static let claude = Set("AD AE AG AL AM AO AR AT AU AZ BA BB BD BE BF BG BH BI BJ BN BO BR BS BT BW BZ CA CD CF CG CH CI CL CM CO CR CV CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET FI FJ FM FR GA GB GD GE GH GM GN GQ GR GT GW GY HN HR HT HU ID IE IL IN IQ IS IT JM JO JP KE KG KH KI KM KN KR KW KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MG MH MK ML MN MR MT MU MV MW MX MY MZ NA NE NG NI NL NO NP NR NZ OM PA PE PG PH PK PL PS PT PW PY QA RO RS RW SA SB SC SD SE SG SI SK SL SM SN SO SR SS ST SV SZ TD TG TH TJ TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA VC VN VU WS ZA ZM ZW".split(separator:" ").map(String.init))
    private static let openAI = Set("AD AE AF AG AL AM AO AR AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BR BS BT BW BZ CA CD CF CG CH CI CL CM CO CR CV CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET FI FJ FM FO FR GA GB GD GE GF GH GL GM GN GP GQ GR GT GW GY HN HR HT HU ID IE IL IN IQ IS IT JM JO JP KE KG KH KI KM KN KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MQ MR MT MU MV MW MX MY MZ NA NC NE NG NI NL NO NP NR NZ OM PA PE PF PG PH PK PL PM PS PT PW PY QA RE RO RS RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SZ TD TF TG TH TJ TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA VC VN VU WF WS YE YT ZA ZM ZW".split(separator:" ").map(String.init))
    // Anthropic explicitly includes territories and dependencies of listed countries.
    private static let dependencies = Set("AI AS AW AX BL BM BQ BV CC CK CW CX FK FO GF GG GI GL GP GS GU HM IM IO JE KY MF MP MQ MS NC NF NU PF PM PN PR RE SH SJ SX TC TF TK UM VG VI WF YT".split(separator:" ").map(String.init))
    private static let known = Set(Locale.Region.isoRegions.map(\.identifier))
    static func isKnown(_ code:String) -> Bool {known.contains(code) && code != "ZZ"}
    static let reviewed = Date(timeIntervalSince1970: 1795305600) // 2026-11-22 UTC
    static func issue(host:String, country:String?, now:Date) -> Finding? {
        guard let country, isKnown(country) else {return .regionUnknown}
        guard (0..<90*86400).contains(now.timeIntervalSince(reviewed)) else {return .policyExpired}
        if country == "UA" {return .regionUncertain}
        if host == "claude.ai" || host == "api.anthropic.com" {
            return claude.contains(country) || dependencies.contains(country) ? nil : .unsupportedCountry
        }
        return openAI.contains(country) ? nil : .unsupportedCountry
    }
}
