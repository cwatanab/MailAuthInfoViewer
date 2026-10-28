// messagedisplay.js
// Mail Auth Info Viewer — メッセージ表示画面に認証情報ダッシュボードを構築
// Copyright (C) 2025 Shota (SHOWTIME)
// License: GPL-3.0

(async () => {
  try {
    // =========================================================
    // i18n ヘルパー: browser.i18n.getMessage のショートハンド
    // =========================================================
    const msg = (id) => browser.i18n.getMessage(id) || id;

    // =========================================================
    // HTML エスケープ: XSS防止のため、ユーザー由来文字列は必ず通す
    // =========================================================
    const escapeHTML = (str) => {
      if (!str) return "";
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };

    // =========================================================
    // 日時パース: Received ヘッダのタイムスタンプを Date オブジェクトに変換
    // =========================================================
    const parseReceivedDate = (line) => {
      const dateMatch = line.match(/;\s*(.+)$/);
      if (dateMatch) {
        const d = new Date(dateMatch[1].trim());
        if (!isNaN(d.getTime())) return d;
      }
      return null;
    };

    // =========================================================
    // IP アドレス判定ヘルパー群
    // =========================================================
    const isIPv4Like = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
    const isIPv6Like = (s) => /^[a-fA-F0-9:]+$/.test(s) && s.includes(':');

    // プライベートIPアドレス判定（内部/外部ネットワーク分類用）
    const isPrivateIP = (ip) => {
      if (!ip) return false;
      if (ip.includes(':')) {
        const lower = ip.toLowerCase();
        return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
      }
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4) return false;
      // 100.64.0.0/10 は RFC 6598 の共有アドレス空間（キャリアグレード NAT 等の内部用）で、
      // インターネットからは到達できない（例: xspmail の内部 LMTP ホップ "(100.120.25.83)"）。
      // 169.254.0.0/16 はリンクローカル
      return (parts[0] === 10) ||
             (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
             (parts[0] === 192 && parts[1] === 168) ||
             (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
             (parts[0] === 169 && parts[1] === 254) ||
             (parts[0] === 127);
    };

    // Received ヘッダの from 句からIPアドレスを抽出
    // includeParenIPv6=false の場合は角括弧なしの括弧内 IPv6 を対象外とする
    // （authserv 信頼ホストの境界検出で、従来の判定結果を変えないため）
    const extractIPFromReceived = (line, includeParenIPv6 = true) => {
      if (!line) return null;
      // 角括弧内のIPv4/IPv6 (例: [192.168.1.1])
      const bracketMatch = line.match(/\[([^\]]+)\]/);
      if (bracketMatch && (isIPv4Like(bracketMatch[1]) || isIPv6Like(bracketMatch[1]))) {
        return bracketMatch[1];
      }
      // 括弧内のIPv4 (例: (192.168.1.1))
      const parenMatch = line.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
      if (parenMatch) return parenMatch[1];
      // 括弧内のIPv6 (例: (2603:10a6:10:360::8))
      // Exchange Online / Exchange Server は角括弧を付けずに括弧内へ IPv6 を記録する。
      // "(Postfix)" 等のコメントや時刻表記との誤マッチを避けるため、
      // コロンを2つ以上含む IPv6 形式の文字列のみを対象とする。
      const parenV6Match = includeParenIPv6 && line.match(/\(([a-fA-F0-9:]+)\)/);
      if (parenV6Match && isIPv6Like(parenV6Match[1]) && (parenV6Match[1].match(/:/g) || []).length >= 2) {
        return parenV6Match[1];
      }
      return null;
    };

    // =========================================================
    // 国際化ドメイン名（IDN）の表記変換とホモグラフ判定ヘルパー群
    // =========================================================
    // ホモグラフ攻撃は、見た目がそっくりな別の文字（キリル文字の "а" とラテン文字の "a" 等）や
    // 紛らわしい文字列（"rn" と "m"、"1" と "l" 等）で、実在のドメインになりすます手口。
    // 攻撃者は偽ドメインを自分で取得して SPF/DKIM/DMARC を正しく設定できるため、
    // 認証がすべて pass しても安全とは言えない。ここではドメインの文字そのものを検査する。
    //
    // 表記の扱い:
    //   - 比較は常に ASCII 表記（Punycode、"xn--" 形式）にそろえて行う。
    //     URL の hostname はブラウザが ASCII 表記に変換するが、ヘッダ From 等は
    //     Unicode のまま渡ることがあり、そのまま比べると同一ドメインでも不一致になる。
    //   - 利用者への表示には Unicode 表記を併記し、実際の文字を確認できるようにする。

    // Punycode（RFC 3492）のデコード。"xn--" を除いた部分を受け取り Unicode 文字列を返す。
    // ブラウザには ASCII→Unicode 方向の標準 API が無いため、仕様どおりに実装する。
    const punycodeDecode = (input) => {
      const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
      const adapt = (delta, numPoints, firstTime) => {
        let k = 0;
        delta = firstTime ? Math.floor(delta / damp) : (delta >> 1);
        delta += Math.floor(delta / numPoints);
        for (; delta > ((base - tMin) * tMax) >> 1; k += base) {
          delta = Math.floor(delta / (base - tMin));
        }
        return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
      };
      const digitOf = (cp) => {
        if (cp >= 0x30 && cp <= 0x39) return cp - 0x16; // 0-9 → 26-35
        if (cp >= 0x41 && cp <= 0x5A) return cp - 0x41; // A-Z → 0-25
        if (cp >= 0x61 && cp <= 0x7A) return cp - 0x61; // a-z → 0-25
        return base;
      };
      const output = [];
      // 最後の "-" より前は基本文字（ASCII）がそのまま並ぶ
      const basicEnd = Math.max(input.lastIndexOf("-"), 0);
      for (let j = 0; j < basicEnd; j++) {
        if (input.charCodeAt(j) >= 0x80) throw new Error("invalid punycode");
        output.push(input.charCodeAt(j));
      }
      let n = 128, i = 0, bias = 72;
      for (let idx = basicEnd > 0 ? basicEnd + 1 : 0; idx < input.length; ) {
        const oldi = i;
        for (let w = 1, k = base; ; k += base) {
          if (idx >= input.length) throw new Error("invalid punycode");
          const d = digitOf(input.charCodeAt(idx++));
          if (d >= base) throw new Error("invalid punycode");
          i += d * w;
          const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
          if (d < t) break;
          w *= base - t;
        }
        const len = output.length + 1;
        bias = adapt(i - oldi, len, oldi === 0);
        n += Math.floor(i / len);
        i %= len;
        output.splice(i++, 0, n);
      }
      return String.fromCodePoint(...output);
    };

    // ドメインを ASCII 表記（Punycode）に正規化する。URL パーサの IDNA 処理に任せることで、
    // 大文字・全角英数字などの正規化も同時に行う。変換できない文字列は小文字化のみ。
    const domainToAscii = (domain) => {
      if (!domain) return "";
      try {
        return new URL(`http://${domain}/`).hostname.replace(/\.$/, "");
      } catch {
        return domain.toLowerCase();
      }
    };

    // ドメインを Unicode 表記に変換する（表示・文字種判定用）。デコードできないラベルはそのまま。
    const domainToUnicode = (domain) => {
      return domainToAscii(domain).split(".").map(label => {
        if (!label.startsWith("xn--")) return label;
        try { return punycodeDecode(label.slice(4)); } catch { return label; }
      }).join(".");
    };

    // ラテン文字と見分けにくい文字 → 見た目が同じラテン文字（またはそれに近い ASCII 表記）。
    // Unicode の confusables（UTS #39）のうち、ドメイン（小文字化済み）で
    // ラテン文字の偽装に使われるものに絞っている。"0"→"o" と "1"→"l" は ASCII 同士の紛らわしさ。
    const CONFUSABLE_TO_LATIN = {
      // キリル文字
      "а": "a", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
      "ӏ": "l", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s", "ѵ": "v", "ԝ": "w", "х": "x",
      "у": "y", "ү": "y",
      // ギリシャ文字
      "α": "a", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "υ": "u", "χ": "x",
      // アルメニア文字
      "ա": "w", "հ": "h", "ո": "n", "ս": "u", "ց": "g", "զ": "q", "օ": "o",
      // ラテン文字の拡張（ASCII の字と見分けにくいもの）
      "ı": "i", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ǀ": "l", "ȷ": "j",
      // ASCII 同士
      "0": "o", "1": "l"
    };
    // ラテン文字の拡張のうち、ASCII の字になりすますために使われるもの（文字種の混在が無くても警告）
    const LATIN_LOOKALIKES = new Set(["ı", "ɑ", "ɡ", "ɩ", "ǀ", "ȷ"]);

    // 文字種の判定。数字・ハイフン等の共通文字（Common / Inherited）は判定対象外として null を返す。
    const SCRIPT_TESTS = [
      "Latin", "Cyrillic", "Greek", "Armenian", "Georgian", "Hebrew", "Arabic", "Cherokee",
      "Han", "Hiragana", "Katakana", "Hangul", "Bopomofo", "Thai", "Devanagari", "Ethiopic"
    ].map(name => [name, new RegExp(`\\p{Script=${name}}`, "u")]);
    const scriptOf = (ch) => {
      if (/[\p{Script=Common}\p{Script=Inherited}]/u.test(ch)) return null;
      for (const [name, re] of SCRIPT_TESTS) {
        if (re.test(ch)) return name;
      }
      return "Other";
    };
    // 1つのラベル内で混在しても正当とみなす文字種の組み合わせ（UTS #39 "Highly Restrictive"）。
    // 日本語・中国語・韓国語の表記ではラテン文字・漢字・かな等の併用が日常的なため。
    const ALLOWED_SCRIPT_MIXES = [
      ["Latin", "Han", "Hiragana", "Katakana"],
      ["Latin", "Han", "Bopomofo"],
      ["Latin", "Han", "Hangul"]
    ];

    // ドメインの「骨格」: 紛らわしい文字を代表の字にそろえた比較用の文字列。
    // 骨格が同じで実際のドメインが異なれば、利用者には同じドメインに見える可能性が高い。
    // 例: "pаypal.com"（キリル文字の а）、"paypa1.com"、"rnicrosoft.com" はいずれも
    //     "paypal.com" / "microsoft.com" と同じ骨格になる。
    // 合成文字は分解してアクセント記号を除き（"é"→"e"）、"rn"→"m"、"vv"→"w" もそろえる。
    const domainSkeleton = (domain) => {
      const base = domainToUnicode(domain).toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "");
      return [...base].map(ch => CONFUSABLE_TO_LATIN[ch] || ch).join("")
        .replace(/rn/g, "m").replace(/vv/g, "w");
    };

    // ドメインの文字を検査し、ホモグラフ（見た目の偽装）の兆候を返す。
    //   mixed:   1つのラベル内で、正当な組み合わせ以外の文字種が混在している（例: ラテン＋キリル）
    //   whole:   ラベル全体がラテン文字以外の1文字種で、しかもラテン文字に見える字だけで
    //            できている（例: キリル文字だけの "аре"）。トップレベルドメインが同じ文字種
    //            （キリル文字のラベル＋".рф" 等）の場合は、その言語の正当な表記とみなす。
    //   latin:   ASCII の字になりすますためのラテン文字拡張（"ı" 等）を含む
    // 戻り値: { ascii, unicode, isIdn, reasons: [...], isDeceptive, chars: [{ch, script, code}] }
    const analyzeDomainHomograph = (domain) => {
      const ascii = domainToAscii(domain);
      const unicode = domainToUnicode(domain);
      const labels = unicode.split(".").filter(Boolean);
      const tld = labels[labels.length - 1] || "";
      const reasons = new Set();
      const chars = new Map();
      for (const label of labels) {
        const scripts = new Set();
        for (const ch of label) {
          const s = scriptOf(ch);
          if (s) scripts.add(s);
          // 利用者に提示するため、ASCII 以外の紛らわしい文字を記録する
          if (ch.codePointAt(0) > 0x7F && CONFUSABLE_TO_LATIN[ch] && !chars.has(ch)) {
            chars.set(ch, { ch, script: s || "", code: "U+" + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0") });
          }
          if (LATIN_LOOKALIKES.has(ch)) reasons.add("latin");
        }
        const scriptList = Array.from(scripts);
        if (scriptList.length > 1 && !ALLOWED_SCRIPT_MIXES.some(mix => scriptList.every(s => mix.includes(s)))) {
          reasons.add("mixed");
        }
        if (scriptList.length === 1 && scriptList[0] !== "Latin") {
          const script = scriptList[0];
          const allLookalike = [...label].every(ch => !scriptOf(ch) || CONFUSABLE_TO_LATIN[ch]);
          const tldSameScript = [...tld].some(ch => scriptOf(ch) === script);
          if (allLookalike && !tldSameScript) reasons.add("whole");
        }
      }
      return {
        ascii,
        unicode,
        isIdn: ascii !== unicode,
        reasons: Array.from(reasons),
        isDeceptive: reasons.size > 0,
        chars: Array.from(chars.values())
      };
    };

    // 参照ドメイン群（組織ドメイン、ASCII 表記）の骨格索引を作る。
    // 戻り値の Map は 骨格 → 参照ドメイン。
    const buildSkeletonIndex = (domains) => {
      const index = new Map();
      for (const d of domains) {
        if (!d) continue;
        const sk = domainSkeleton(d);
        if (!index.has(sk)) index.set(sk, d);
      }
      return index;
    };
    // orgDomain（ASCII 表記の組織ドメイン）が、参照ドメインのどれかに「似せた別ドメイン」なら
    // その参照ドメインを返す。同一ドメインは対象外。該当しなければ null。
    const findLookalikeTarget = (orgDomain, skeletonIndex) => {
      if (!orgDomain || !skeletonIndex) return null;
      const target = skeletonIndex.get(domainSkeleton(orgDomain));
      return (target && target !== orgDomain) ? target : null;
    };

    // =========================================================
    // 既知の電子メール匿名化・転送（リレー）サービスのドメイン
    // =========================================================
    // これらのサービスはユーザーの実アドレスを隠蔽するため、
    // 元送信者の身元を「表示名」に保持しつつ、別ドメインの匿名アドレスから配信する。
    // 例: From: "original@sender.com [via Relay]" <random@mozmail.com>
    // 表示名と実アドレスのドメインが意図的に異なるため、なりすまし検知の対象外とする。
    const EMAIL_RELAY_DOMAINS = new Set([
      "mozmail.com",              // Firefox Relay
      "relay.firefox.com",        // Firefox Relay (legacy)
      "duck.com",                 // DuckDuckGo Email Protection
      "privaterelay.appleid.com", // Apple Hide My Email
      "simplelogin.com",          // SimpleLogin
      "simplelogin.fr",
      "simplelogin.co",
      "slmail.me",
      "aleeas.com",
      "anonaddy.com",             // AnonAddy / addy.io
      "anonaddy.me",
      "addy.io",
      "forwardemail.net",         // Forward Email
      "33mail.com",               // 33Mail
      "spamgourmet.com",          // SpamGourmet
    ]);

    // =========================================================
    // 転送サービスが「元メールの認証結果」を記録する独自ヘッダ
    // =========================================================
    // エイリアス転送サービスは元メールを受信した時点で SPF/DKIM/DMARC を検証し、
    // その結果を独自ヘッダに記録したうえで、自身のドメインで再署名して転送する。
    // 外側の認証（転送サービス→受信者）が pass しても元送信者の正当性は保証されないため、
    // このヘッダがある場合は「元送信者の DMARC pass」をグリーンの追加条件として用いる。
    // ヘッダ自体は暗号学的に検証できない報告値であり、判定を緩める方向には使わない。
    const RELAY_ORIGINAL_AUTH_HEADERS = [
      "x-anonaddy-authentication-results", // addy.io (AnonAddy)
    ];

    // =========================================================
    // 汎用の authserv-id 照合が成立しない受信プロバイダの定義
    // =========================================================
    // 以下のプロバイダは、受信境界の後ろにグローバル IP で接続された内部ホップが多段に続き
    // （最終配送ホストは認証を実施したホストではない）、しかも付与する A-R の authserv-id が
    // ホスト名と対応しないため、境界ホスト名との照合では正規の A-R を特定できない。
    //   - Microsoft 365 / Exchange Online:
    //       受信境界は EOP（*.mail.protection.outlook.com）。内部ホップは *.prod.outlook.com /
    //       *.outlook.office365.com。A-R に authserv-id 自体が無い（RFC 8601 非準拠）。
    //         Authentication-Results: spf=pass (sender IP is ...) smtp.mailfrom=...; dkim=pass ...
    //   - mailbox.org:
    //       受信境界は mx*.mailbox.org。内部ホップは *.heinlein-hosting.de。
    //       authserv-id はホスト名ではない固定値 "incoming_mbo"。
    //   - Hostpoint:
    //       受信境界は mxin<番号>.mail.hostpoint.ch（Exim）。受信後は SpamAssassin による
    //       スキャンのため同一ホストへ自身で再投入し（from mailnull ... with local_*）、
    //       *.adm.hostpoint.ch / *.mail.hostpoint.internal の内部ホップへ LMTP で渡す。
    //       authserv-id は受信ホスト名ではないクラスタ名 "mxin-hosts.mail.hostpoint.ch"。
    // これらは parseAuthResults の detectProviderRoute で境界を特定し、生ヘッダ順序で
    // A-R の付与位置を検証したうえで採用する。各定義:
    //   orgDomains:         プロバイダ自身のホストの組織ドメイン
    //   ingress:            外部から受け取る受信境界ホスト（by）のパターン
    //   providerAuthServId: プロバイダが付与する A-R の authserv-id（null は authserv-id 無し）
    //   arPlacement:        プロバイダが A-R を付与する位置
    //                         "above": 受信境界の Received より上（EOP は受信後のヘッダとして積む）
    //                         "below": 受信境界の Received の直下（Postfix + milter 構成では、
    //                                  MTA 自身の Received の直後に milter のヘッダが挿入される）
    //   queueIdHeader:      "below" の位置は元メール先頭に置かれた偽 A-R と区別できないため、
    //                       受信時にプロバイダが付与するキュー ID ヘッダの値が受信境界の
    //                       Received の "id" と一致することを要求する（受信時に初めて決まる値で
    //                       送信者は予測できないため、プロバイダが実際に処理したことの証跡になる）
    //   localReinjection:   MTA が受信済みメールを同一ホストへ自身で再投入するホップ
    //                       （from <ローカルユーザー名> by <ホスト> with local*、IP なし）を、
    //                       同一サーバ内の処理として通過させるか
    //   detectInternal:     組織内で完結した配送を判定・注記する対象か
    const PROVIDER_INGRESS_RULES = [
      {
        name: "Microsoft 365",
        orgDomains: ["outlook.com", "office365.com"],
        ingress: /\.mail\.protection\.outlook\.com$/,
        providerAuthServId: null,
        arPlacement: "above",
        queueIdHeader: null,
        localReinjection: false,
        detectInternal: true
      },
      {
        name: "mailbox.org",
        orgDomains: ["mailbox.org", "heinlein-hosting.de"],
        ingress: /^mx\d*\.mailbox\.org$/,
        providerAuthServId: "incoming_mbo",
        arPlacement: "below",
        queueIdHeader: "x-rspamd-queue-id",
        localReinjection: false,
        detectInternal: false
      },
      {
        name: "Hostpoint",
        orgDomains: ["hostpoint.ch", "hostpoint.internal"],
        ingress: /^mxin\d+\.mail\.hostpoint\.ch$/,
        providerAuthServId: "mxin-hosts.mail.hostpoint.ch",
        // A-R はスパムスキャン後の再投入ホップと受信境界の Received の間に積まれる
        arPlacement: "above",
        queueIdHeader: null,
        localReinjection: true,
        detectInternal: false
      }
    ];

    // 受信ホスト名から該当するプロバイダ定義を返す（該当なしは undefined）
    const findProviderRule = (host) => {
      if (!host) return undefined;
      const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
      const org = getOrgDomain(host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, ""));
      return PROVIDER_INGRESS_RULES.find(r => r.orgDomains.includes(org));
    };

    // =========================================================
    // 1. parseEnvelope - エンベロープ情報・アドレスアライメント・メーリングリスト検知
    // =========================================================
    // trustedDomains: 利用者の信頼済みドメイン（送信者ドメインが、これらに似せた別ドメインかの判定に使う）
    const parseEnvelope = (fullMsg, headers, msgHeader, trustedDomains) => {
      // ■ エンベロープ情報の抽出
      // envelope.from、return-path、またはauthorを評価し、送信元アドレスを特定
      const envelopeFromRaw =
        fullMsg.envelope?.from ||
        headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
        fullMsg.author ||
        "Unknown";
      const envelopeFrom = envelopeFromRaw.replace(/^<|>$/g, "").trim();

      // delivered-to、envelope.to、またはrecipientsを評価し、宛先アドレスを特定
      const envelopeToRaw =
        (headers["delivered-to"] || []).join(", ") ||
        fullMsg.envelope?.to?.join(", ") ||
        (fullMsg.recipients || []).join(", ") ||
        "Unknown";
      const envelopeTo = envelopeToRaw.replace(/^<|>$/g, "").trim();

      // ■ ヘッダFrom（表示名とアドレス）の抽出
      // ※ rawヘッダのままだと文字化け(MIMEエンコードや生UTF-8)が発生するため、
      //   Thunderbirdがデコード済みの author 情報を優先する
      const headerFromRaw = msgHeader.author || headers["from"]?.[0] || "Unknown";
      let headerFromName = "";
      let headerFromAddress = "";

      // "Display Name <user@domain.com>" の形式をパース（末尾の <...> を採用）
      // 複数の角括弧がある場合は最後のものが正規アドレスと判断する
      const matches = Array.from(headerFromRaw.matchAll(/<([^>]+)>/g));
      if (matches.length > 0) {
        const lastMatch = matches[matches.length - 1];
        headerFromAddress = lastMatch[1].trim();
        headerFromName = headerFromRaw.substring(0, lastMatch.index).trim().replace(/"/g, '').trim();
      } else {
        headerFromAddress = headerFromRaw.replace(/^<|>$/g, "").trim();
      }

      // 比較用にドメイン部分を抽出し、ASCII 表記（Punycode）に正規化する
      // （Thunderbird の author は国際化ドメインを Unicode のまま返すことがあり、
      //   Authentication-Results やリンク先の ASCII 表記と比べると同一ドメインでも不一致になるため）
      const headerFromDomain = headerFromAddress.includes('@')
        ? domainToAscii(headerFromAddress.split('@')[1])
        : headerFromAddress.toLowerCase();
      const envelopeFromDomain = envelopeFrom.includes('@')
        ? domainToAscii(envelopeFrom.split('@')[1])
        : envelopeFrom.toLowerCase();

      // ■ 組織ドメイン (Organizational Domain) での比較 — RFC 7489 準拠
      // psl_data.js で定義された getOrganizationalDomain() を使用し、
      // Public Suffix List に基づいて正確な組織ドメインを抽出して比較する。
      // これにより aaa.bbb.google.com と ccc.google.com は共に google.com として一致する。
      const headerOrgDomain = window.getOrganizationalDomain
        ? window.getOrganizationalDomain(headerFromDomain)
        : headerFromDomain;
      const envelopeOrgDomain = window.getOrganizationalDomain
        ? window.getOrganizationalDomain(envelopeFromDomain)
        : envelopeFromDomain;

      const isDomainAligned = (headerOrgDomain === envelopeOrgDomain);

      // ■ メーリングリスト検知
      // List-Id または List-Unsubscribe ヘッダの存在でメーリングリスト経由と判断
      const isMailingList = !!(
        (headers["list-id"] && headers["list-id"].length > 0) ||
        (headers["list-unsubscribe"] && headers["list-unsubscribe"].length > 0)
      );

      // ■ メール匿名化/転送サービス経由かを判定
      // Firefox Relay 等のリレーサービスは、元送信者の身元を表示名に残しつつ、
      // 配信は別ドメインの匿名アドレスから行う。表示名と実アドレスの
      // ドメイン不一致が「正規の挙動」となるため、なりすまし検知を抑制する必要がある。
      const isEmailRelay = EMAIL_RELAY_DOMAINS.has(headerOrgDomain);

      // ■ 表示名なりすまし検知
      // 攻撃者が表示名にメールアドレスを埋め込み、受信者を欺く手口を検知する。
      // 例: From: "support@amazon.co.jp" <evil@attacker.com>
      // 表示名内のアドレスのドメインと実際のHeader Fromドメインを組織ドメインレベルで比較し、
      // 不一致の場合はなりすましの疑いとして警告フラグを立てる。
      // 実アドレスが既知のメールリレーサービスのドメインの場合は、転送パターンとして警告対象外。
      let isDisplayNameSpoofed = false;
      if (headerFromName && !isEmailRelay) {
        // 表示名から @ を含む文字列（メールアドレス候補）を抽出
        const emailInName = headerFromName.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
        if (emailInName) {
          const spoofedDomain = domainToAscii(emailInName[0].split('@')[1]);
          const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
          const spoofedOrgDomain = getOrgDomain(spoofedDomain);
          // 表示名内のドメインと実際のHeader Fromドメインが組織ドメインレベルで異なれば警告
          isDisplayNameSpoofed = (spoofedOrgDomain !== headerOrgDomain);
        }
      }

      // ■ Reply-To ドメイン不一致検知
      // Reply-To が Header From と異なる組織ドメインの場合、
      // フィッシングで返信先を攻撃者に誘導する手口の可能性がある
      // ※ メールリレーサービス経由の場合、Reply-To に元送信者を設定するのが通常のため除外
      let isReplyToMismatch = false;
      let replyToAddress = "";
      const replyToRaw = headers["reply-to"]?.[0] || "";
      if (replyToRaw && !isEmailRelay) {
        const replyToMatch = replyToRaw.match(/<([^>]+)>/);
        replyToAddress = replyToMatch ? replyToMatch[1].trim() : replyToRaw.replace(/^<|>$/g, "").trim();
        if (replyToAddress.includes('@')) {
          const replyToDomain = domainToAscii(replyToAddress.split('@')[1]);
          const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
          const replyToOrgDomain = getOrgDomain(replyToDomain);
          // Reply-To の組織ドメインが Header From と異なり、
          // かつ Reply-To アドレスが Header From アドレスと完全一致でもない場合に警告
          if (replyToOrgDomain !== headerOrgDomain && replyToAddress.toLowerCase() !== headerFromAddress.toLowerCase()) {
            isReplyToMismatch = true;
          }
        }
      }

      // ■ 送信者ドメインのホモグラフ（見た目の偽装）検知
      // 攻撃者は "аpple.com"（キリル文字の а）のような偽ドメインを自分で取得し、
      // SPF/DKIM/DMARC を正しく設定できる。認証・アライメントがすべて成立しても
      // 送信者を誤認させる手口であるため、ドメインの文字そのものを検査する。
      //   - 文字種の混在・全体の置き換え・紛らわしいラテン文字（analyzeDomainHomograph）
      //   - 利用者の信頼済みドメインに似せた別ドメイン（骨格の一致）
      // いずれかに該当すれば determineSecurityStatus でフィッシング判定とする。
      const getOrgDomainFn = window.getOrganizationalDomain || ((d) => d);
      const senderDomainInfo = headerFromAddress.includes('@')
        ? analyzeDomainHomograph(headerFromDomain)
        : { ascii: headerFromDomain, unicode: headerFromDomain, isIdn: false, reasons: [], isDeceptive: false, chars: [] };
      const trustedIndex = buildSkeletonIndex(Array.from(trustedDomains || []).map(d => getOrgDomainFn(domainToAscii(d))));
      const senderLookalikeOf = (headerFromAddress.includes('@') && !(trustedDomains && trustedDomains.has(headerOrgDomain)))
        ? findLookalikeTarget(headerOrgDomain, trustedIndex)
        : null;
      const senderHomograph = {
        ...senderDomainInfo,
        lookalikeOf: senderLookalikeOf,
        isHomograph: senderDomainInfo.isDeceptive || !!senderLookalikeOf
      };

      // ■ Reply-To ドメインのホモグラフ検知
      // 返信先に紛らわしい文字のドメインや、送信者ドメインに似せた別ドメインが
      // 指定されている場合は、返信を攻撃者に誘導する手口の可能性が高い。
      // リレーサービス経由でも返信先の偽装は正当化されないため、ここでは除外しない。
      let replyToHomograph = null;
      const replyToAddrForCheck = replyToAddress || (replyToRaw.match(/<([^>]+)>/)?.[1] || replyToRaw.replace(/^<|>$/g, "")).trim();
      if (replyToAddrForCheck.includes('@')) {
        const replyInfo = analyzeDomainHomograph(replyToAddrForCheck.split('@')[1]);
        const replyOrg = getOrgDomainFn(replyInfo.ascii);
        const replyLookalikeOf = findLookalikeTarget(replyOrg, buildSkeletonIndex([headerOrgDomain]));
        if (replyInfo.isDeceptive || replyLookalikeOf) {
          replyToHomograph = { ...replyInfo, address: replyToAddrForCheck, lookalikeOf: replyLookalikeOf };
        }
      }

      return {
        senderHomograph,
        replyToHomograph,
        envelopeFrom,
        envelopeTo,
        headerFromName,
        headerFromAddress,
        headerFromDomain,
        envelopeFromDomain,
        headerOrgDomain,
        envelopeOrgDomain,
        isDomainAligned,
        isMailingList,
        isDisplayNameSpoofed,
        isReplyToMismatch,
        replyToAddress
      };
    };

    // =========================================================
    // 2. parseAuthResults - メール認証結果の解析 (authserv-id フィルタリング付き)
    // =========================================================
    // rawHeaderOrder: 生ヘッダを上から順に並べた [{name, value}]（取得できない場合は null）
    const parseAuthResults = (headers, envelope, rawHeaderOrder) => {
      // ■ authserv-id による信頼フィルタリング
      // 最新の Received ヘッダの by ホスト名と Authentication-Results の authserv-id を比較し、
      // 信頼できるヘッダのみを採用する。攻撃者が注入した偽の認証結果を排除するため。
      // ARC-Authentication-Results は独自のチェイン検証機構を持つため、フィルタリング対象外。
      // 名前の照合だけでは偽物を排除できないため、受信境界（detectBoundary）と生ヘッダ上の
      // 位置（selectGenericAR）を併せて確かめ、受信サーバが付けたと言える A-R だけを採用する。

      // ■ コメント括弧を考慮したセミコロン分割ヘルパー
      // RFC 8601 では Authentication-Results 中の "(...)" はコメントであり、
      // 括弧内に含まれるセミコロンは構文上のセパレータではない。
      // 例: dkim=pass (2048-bit key; unprotected) header.d=example.com
      //   このようなコメント付き結果を素朴に ';' で分割すると、
      //   "dkim=pass (2048-bit key" と " unprotected) header.d=..." に
      //   分断され、header.d 等の属性が後続セグメントに紛れ込んで
      //   ドメイン抽出やアライメント評価が誤った結果になる。
      // そのため括弧の対応をネストで追いつつトップレベルのセミコロンだけで
      // 分割する専用関数を用いる。
      const splitOnTopLevelSemicolons = (str) => {
        if (!str) return [];
        const result = [];
        let depth = 0;
        let current = "";
        for (let i = 0; i < str.length; i++) {
          const ch = str[i];
          if (ch === '(') {
            depth++;
            current += ch;
          } else if (ch === ')') {
            if (depth > 0) depth--;
            current += ch;
          } else if (ch === ';' && depth === 0) {
            result.push(current);
            current = "";
          } else {
            current += ch;
          }
        }
        // 最後のセグメント（末尾セミコロンがない場合の残り）も含める
        result.push(current);
        return result;
      };

      // ■ 受信境界（境界 MTA）の特定
      // authserv-id 照合と A-R の位置検証に使う「信頼する受信ホスト」を求める。
      // 単純に received[0] の by を採るだけでは、受信プロバイダの構成によって
      // 「最終配送ホップ ≠ 認証（Authentication-Results 付与）ホスト」となり、
      // 正規の A-R が authserv-id 不一致で破棄されてしまう。代表的な2パターン:
      //   - Gmail / Google Workspace: 最上段に内部ハンドオフ
      //       Received: by 2002:<IPv6> with SMTP id ...
      //     を積む（by が IP リテラルで authserv-id になり得ない）。
      //   - Fastmail (messagingengine.com): Cyrus LMTP の内部ホスト
      //       Received: ... by slotpiXXmYY (Cyrus ...) with LMTPA
      //     が最終配送だが、認証は phl-mx-NN.messagingengine.com が実施し
      //     A-R を付与する。間に *.internal / localhost の内部ホップが挟まる。
      // 最上段から下へ、受信側の内部処理と言い切れるホップだけを読み飛ばし、
      // それ以外の最初のホップを境界とする。読み飛ばすのは次のものに限る:
      //   - from 句の無いホップ（Gmail の "Received: by 2002:..." 等の内部ハンドオフ）
      //   - プライベート IP・ループバックからの受信（*.internal / localhost の内部ホップ）
      //   - IP の記録が無いローカルの受け渡し（"from exim by ... with sa-scanned" のように、
      //     from がドットも角括弧も含まない単語だけのもの）
      // 境界の Received は受信側が書いたものであり、それより下は送信者が自由に書ける。
      // IP の読み取れない外部受信の行を読み飛ばすと、送信者が書いた偽の Received を
      // 境界と取り違え、送信者が自作した「境界」と A-R の組を信頼してしまう。
      // そのため境界の候補は「最初の読み飛ばせないホップ」1つに限り、それより下は見ない。
      // 括弧内 IPv6 も IP として扱う: Exchange 系の内部ホップは "(2001:db8::1)" の形で
      // 公開 IPv6 を記録するため、そこが境界になって A-R が照合されなくなるが、
      // 下へ潜って送信者の行を拾うよりは安全側である
      // （Microsoft 365 等は detectProviderRoute で別途ホスト名ベースに境界を特定する）。
      // 戻り値:
      //   host:  境界ホップの by（IP リテラル等で使えない場合は ""）
      //   index: 境界ホップの received 配列上の位置（全ホップが内部処理なら -1）
      const detectBoundary = () => {
        const received = headers["received"] || [];

        // by 句のホスト名は空白・セミコロンに加え "(" の手前で区切る。
        // RFC 5321 の Received 構文ではホスト名の直後に空白なしでコメントを続けられ、
        // 例: "by mfsmax.docomo.ne.jp(DOCOMO Mail Server Ver2.0)"
        // ここを区切らないとホスト名にコメントが混入し、authserv-id 照合に失敗して
        // 受信サーバー自身の正規の Authentication-Results まで信頼対象から外れてしまう。
        const extractBy = (line) => {
          const m = line.match(/\bby\s+([^\s;()]+)/i);
          return m ? m[1].toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "") : "";
        };
        const isIpLiteral = (h) => isIPv4Like(h) || isIPv6Like(h);

        for (let i = 0; i < received.length; i++) {
          const line = received[i];
          const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
          if (!fromMatch) continue;
          const fromPart = fromMatch[1].trim();
          const fromIP = extractIPFromReceived(fromPart, true);
          if (fromIP && isPrivateIP(fromIP)) continue;
          const fromHost = fromPart.split(/[\s(]+/)[0];
          // IP の記録が無く、from がドットも角括弧も含まない単語だけのもの（"from exim" /
          // "from mailnull" 等）は、MTA が自身へ渡し直したローカルの受け渡し。
          // 外部からの SMTP 受信では MTA が接続元 IP を必ず記録するため、この形は境界になり得ない。
          // ホスト名だけで IP の無い行（"from mail.example.com by ..."）は、送信者が HELO で
          // 受信側と同じドメインを名乗れるため内部とはみなさず、境界として扱う
          if (!fromIP && !fromPart.includes("[") && /^[A-Za-z][A-Za-z0-9_-]*$/.test(fromHost)) continue;
          const by = extractBy(line);
          return { host: by && !isIpLiteral(by) ? by : "", index: i };
        }
        return { host: "", index: -1 };
      };

      // ■ 汎用経路での A-R の採用（受信プロバイダ固有ルールに該当しない場合）
      // A-R は誰でもメールに書けるため、authserv-id の名前だけでは受信サーバが付けたものと
      // 区別できない。受信サーバが除去するのは自身の authserv-id を名乗る A-R だけで、
      // A-R を付けないサーバや、別の名前を名乗る偽物はそのまま届く。そこで生のヘッダ順序
      // （rawHeaderOrder）で位置を確かめ、受信サーバが付けたと言える A-R だけを信頼する。
      //   名前: authserv-id は境界ホスト名との完全一致のみ（大文字小文字・末尾のドットは無視）。
      //         親ドメインやサブドメインを許すと "com" や "ne.jp" を名乗るだけの偽物が通る。
      //   位置: 境界の Received より上にある、名前の一致する A-R はすべて候補にする。
      //         受信サーバが 1 回の検証結果を複数の A-R に分けて書くことがあるため
      //         （Fastmail は x-ptr / bimi / arc / dkim・dmarc・spf 等を別々の A-R にする）、
      //         1 本に絞ると DKIM や DMARC の結果を取りこぼす。
      //         境界より上に無い場合は、境界の直下（次の Received の手前）で名前の一致する
      //         最初の 1 本だけを候補にする。元メールに埋もれた A-R は使わない。
      //   証拠: 境界より上の A-R は受信後に付与されたもので、送信者は書き込めないため信頼する。
      //         境界の直下は元メール先頭に置かれた偽物とも重なる位置（Gmail 等はここに付与する）
      //         のため、境界より上に同じ authserv-id の ARC-Authentication-Results がある場合
      //         （受信サーバが実際に処理した証跡）に限って信頼する。直下で 2 本目以降を採らないのは、
      //         受信サーバの A-R のすぐ後ろに送信者の偽物が続いていても区別できないため。
      //   内部経路のみ（境界が無い。自己送信等）: 最上段の Received より上にある最初の A-R だけを
      //         信頼する。最上段より上は最終配送側が書いた位置で、送信者は書き込めない。
      // 生ヘッダが取得できない、または getFull と Received の本数が一致しない場合は信頼しない。
      // 戻り値は getFull 側の該当ヘッダ値の配列（境界より上の場合は複数本になりうる）。
      const selectGenericAR = (boundary, regularAuth) => {
        if (!Array.isArray(rawHeaderOrder) || regularAuth.length === 0) return [];
        const squash = (s) => (s || "").replace(/\s+/g, " ").trim();
        const normalizeId = (s) => (s || "").toLowerCase().replace(/\.$/, "");
        const idOf = (v) => normalizeId(splitOnTopLevelSemicolons(v)[0].trim());
        const receivedRaw = [];
        rawHeaderOrder.forEach((h, i) => { if (h.name === "received") receivedRaw.push(i); });
        if (receivedRaw.length === 0 || receivedRaw.length !== (headers["received"] || []).length) return [];
        const toFullValue = (rawValue) => regularAuth.find(h => squash(h) === squash(rawValue));
        const isAR = (h) => h.name === "authentication-results";

        if (boundary.index < 0) {
          const k = rawHeaderOrder.findIndex((h, i) => i < receivedRaw[0] && isAR(h));
          const full = k >= 0 ? toFullValue(rawHeaderOrder[k].value) : undefined;
          return full ? [full] : [];
        }
        if (!boundary.host) return [];
        const boundaryRaw = receivedRaw[boundary.index];
        const isBoundaryAR = (h) => isAR(h) && idOf(h.value) === boundary.host;

        // 境界より上: 名前の一致するものをすべて採用する。
        // getFull 側に対応するヘッダが見つからないものが 1 本でもあれば、生ヘッダとの対応が
        // 取れていないため全体を信頼しない（安全側）
        const above = rawHeaderOrder.filter((h, i) => i < boundaryRaw && isBoundaryAR(h)).map(h => toFullValue(h.value));
        if (above.length > 0) return above.every(Boolean) ? above : [];

        // 境界の直下: 最初の 1 本だけを、境界より上に同名の ARC-AR がある場合に限って採用する
        const zoneEnd = boundary.index + 1 < receivedRaw.length ? receivedRaw[boundary.index + 1] : rawHeaderOrder.length;
        const k = rawHeaderOrder.findIndex((h, i) => i > boundaryRaw && i < zoneEnd && isBoundaryAR(h));
        if (k < 0) return [];
        const arcAbove = rawHeaderOrder.some((h, i) => i < boundaryRaw && h.name === "arc-authentication-results" &&
          idOf(h.value.replace(/^\s*i\s*=\s*\d+\s*;\s*/i, "")) === boundary.host);
        if (!arcAbove) return [];
        const full = toFullValue(rawHeaderOrder[k].value);
        return full ? [full] : [];
      };

      // authserv-id を持たない A-R か（先頭セグメントが "method=result" の形をしている）
      const lacksAuthServId = (h) => /^\s*[a-z][a-z0-9-]*\s*=/i.test(splitOnTopLevelSemicolons(h)[0]);

      // プロバイダが付与した形式の A-R か（PROVIDER_INGRESS_RULES の providerAuthServId で判定）
      const isProviderAR = (rule, h) => rule.providerAuthServId === null
        ? lacksAuthServId(h)
        : splitOnTopLevelSemicolons(h)[0].trim().toLowerCase() === rule.providerAuthServId;

      // ■ プロバイダ受信経路の判定
      // 「最上段から連続するプロバイダ内部ホップをたどり、外部から受信境界に入ったホップに
      // 到達できた場合のみ」そのホストを受信境界として特定する。
      //   - 最上段 Received は実際の受信側が書くため外部から偽造できない。
      //   - 前段の from と次段の by が同一サーバ（先頭ラベル一致）である連続性を要求し、
      //     攻撃者が下段に積んだ偽の Received へ走査が乗り移らないようにする。
      //     （EOP は from に *.prod.outlook.com、by に *.mail.protection.outlook.com という
      //       別名を用いるため、FQDN 全体ではなくサーバ名である先頭ラベルで比較する）
      // 戻り値:
      //   rule:         最上段がこのプロバイダだった場合の定義（該当なしは null）
      //   ingressHost:  外部→受信境界のホップの by（見つからなければ ""）
      //   ingressIndex: そのホップの received 配列上の位置（見つからなければ -1）
      //   internalOnly: 全経路がプロバイダ内部で完結（組織内配送）していれば true
      const detectProviderRoute = () => {
        const result = { rule: null, ingressHost: "", ingressIndex: -1, internalOnly: false };
        const received = headers["received"] || [];
        if (received.length === 0) return result;

        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
        const firstLabel = (h) => (h || "").split(".")[0];
        const normalize = (h) => h.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
        const hops = received.map(line => {
          // ホスト名の直後に空白なしで続くコメント "host(...)" を含めないよう "(" でも区切る
          const byMatch = line.match(/\bby\s+([^\s;()]+)/i);
          const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
          const fromHost = fromMatch ? fromMatch[1].trim().split(/[\s(]+/)[0] : "";
          return {
            by: byMatch ? normalize(byMatch[1]) : "",
            fromHost: normalize(fromHost),
            // 同一ホストへの自己再投入（Exim がスパムスキャン後に記録する
            //   "from mailnull by mxin016.mail.hostpoint.ch with local_accounts_spamscanned"）。
            // from がドットを含まないローカルユーザー名で、IP の記録が無く、プロトコルが local* のもの
            localHandoff: !!fromHost && !fromHost.includes(".") &&
                          !extractIPFromReceived(line) && /\bwith\s+local\w*/i.test(line)
          };
        });

        // 最上段の受信ホストからプロバイダを特定する
        const rule = findProviderRule(hops[0].by);
        if (!rule) return result;
        result.rule = rule;
        const isProviderHost = (h) => !!h && rule.orgDomains.includes(getOrgDomain(h));

        for (let i = 0; i < hops.length; i++) {
          const hop = hops[i];
          // 受信ホストがプロバイダでなくなった時点でプロバイダの受信経路ではない
          if (!isProviderHost(hop.by)) return result;
          // 前段の送信元と、このホップの受信ホストが同一サーバでなければ連続性が途切れている
          if (i > 0 && firstLabel(hops[i - 1].fromHost) !== firstLabel(hop.by)) return result;
          // 自己再投入ホップは、同じサーバが受信済みのメールを自身へ渡し直したもの。
          // 送信元を自分自身とみなして走査を続け、次段にも同じサーバの Received を求める。
          // 最上段から連続した走査でしか到達しないため、送信者が下段に積んだヘッダは対象にならない
          if (rule.localReinjection && hop.localHandoff) {
            hop.fromHost = hop.by;
            continue;
          }
          // 同一サーバが自身から受け取ったホップ（from X by X）は組織内での送信受付の起点。
          // これより下段はクライアントが送信時に含めた任意のヘッダであり信頼できないため、
          // ここで走査を打ち切り、組織内で発生した配送として扱う。
          // （内部の送信者が偽の受信境界ホップを下段に積んで境界を詐称することを防ぐ）
          if (firstLabel(hop.fromHost) === firstLabel(hop.by)) {
            result.internalOnly = true;
            return result;
          }
          if (!isProviderHost(hop.fromHost)) {
            // プロバイダ外から受信したホップ。受信境界ホストであれば境界として採用する。
            // それ以外（SMTP AUTH による送信受付等）は境界として扱わない。
            if (rule.ingress.test(hop.by)) {
              result.ingressHost = hop.by;
              result.ingressIndex = i;
            }
            return result;
          }
        }
        // 外部から入ったホップが一つも無く、全経路がプロバイダ内部で連続している
        result.internalOnly = true;
        return result;
      };

      // ■ 生ヘッダ順序による A-R 付与位置の検証
      // getFull のヘッダはヘッダ名ごとにまとめられ、異なるヘッダ間の前後関係が失われる。
      // そこで生のヘッダ順（rawHeaderOrder: [{name, value}]、上から順）を用いて、
      // 採用候補の A-R がプロバイダの付与位置（rule.arPlacement）にあることを確かめる。
      //   "above": 受信境界の Received より上。受信境界より上のヘッダは受信後に
      //            プロバイダが付与したものであり、元メールに注入された偽の A-R は
      //            必ず受信境界より下に位置するため、プロバイダが A-R の付与や偽 A-R の
      //            除去を行わなかった場合でも偽物を採用しない。
      //   "below": 受信境界の Received の直下（次の Received より前）。この位置は元メール
      //            先頭に置かれた偽 A-R とも重なるため、キュー ID の一致（rule.queueIdHeader）
      //            でプロバイダが実際に処理したことを併せて確かめる。プロバイダの milter は
      //            自身の A-R を元メールのヘッダより上に挿入するため、処理済みであれば
      //            直下で最初に現れる A-R がプロバイダのものになる。
      // 生ヘッダが得られない・内容が getFull と一致しない場合は信頼しない（安全側）。
      const isProviderARPlaced = (rule, candidateAR, ingressIndex) => {
        if (!Array.isArray(rawHeaderOrder) || ingressIndex < 0) return false;
        const squash = (s) => (s || "").replace(/\s+/g, " ").trim();

        if (rule.queueIdHeader) {
          // キュー ID ヘッダはちょうど1本で、受信境界の Received の "id" と一致すること
          // （送信者が同名ヘッダを含めていれば2本以上になり、不一致として扱う）
          const queueIds = headers[rule.queueIdHeader] || [];
          const ingressId = ((headers["received"] || [])[ingressIndex] || "").match(/\bid\s+([A-Za-z0-9]+)/i);
          if (queueIds.length !== 1 || !ingressId || squash(queueIds[0]) !== ingressId[1]) return false;
        }

        let receivedSeen = 0;
        let pastIngress = false;
        for (const h of rawHeaderOrder) {
          if (h.name === "received") {
            // "below": 受信境界の直下で A-R が現れないまま次の Received に達した
            if (pastIngress) return false;
            if (receivedSeen === ingressIndex) {
              // "above": 受信境界の Received に到達するまでに A-R が現れなかった
              if (rule.arPlacement === "above") return false;
              pastIngress = true;
            }
            receivedSeen++;
            continue;
          }
          if (h.name === "authentication-results") {
            // 付与位置で最初に現れた A-R が候補と同一であること
            if (rule.arPlacement === "above" || pastIngress) return squash(h.value) === squash(candidateAR);
            // "below" で受信境界より上に A-R がある場合、最上段の候補は境界直下のものではない
            return false;
          }
        }
        return false;
      };

      const providerRoute = detectProviderRoute();
      const boundary = providerRoute.ingressHost ? null : detectBoundary();
      const lastReceivedBy = providerRoute.ingressHost || boundary.host;
      const regularAuth = headers["authentication-results"] || [];

      // 通常の Authentication-Results のみ authserv-id でフィルタリング
      // ARC-Authentication-Results は暗号学的検証なしでは偽造可能なため、
      // 本判定からは除外し、ARC カード表示（parseArcChain）のみで利用する
      // （汎用経路で境界より上にある ARC-AR を「受信サーバが処理した証跡」として参照するのみ）。
      // プロバイダの受信経路が特定できた場合は、authserv-id による照合を行わない。
      // これらのプロバイダの authserv-id は受信境界のホスト名と異なるため、境界のホスト名を
      // authserv-id に名乗る A-R はプロバイダが付与したものではなく、送信者が元メールに
      // 仕込んだ偽物でしかありえない（プロバイダは自身の authserv-id を名乗る A-R しか
      // 除去しないため、偽物はそのまま届く）。下の位置検証を経た A-R だけを信頼する。
      // それ以外は selectGenericAR で、名前の完全一致と生ヘッダ上の位置を確かめた 1 本だけを信頼する。
      let trustedRegular = providerRoute.ingressHost ? [] : selectGenericAR(boundary, regularAuth);
      let authHeaders = trustedRegular;

      // ■ プロバイダが付与した A-R の採用
      // 受信境界が特定でき、最上段の A-R がそのプロバイダの形式であり、
      // かつ生ヘッダ上でプロバイダの付与位置にある（isProviderARPlaced）場合に限り、
      // その1本だけをプロバイダが付与したものとして信頼する。
      // 下段にある A-R（元メールに含まれていたもの）は対象にしない。
      // authserv-id を持たない形式（Microsoft 365）は、既存パーサが先頭セグメントを
      // authserv-id として読み飛ばすため、境界ホスト名を authserv-id として補って渡す。
      if (providerRoute.ingressHost && regularAuth.length > 0 &&
          isProviderAR(providerRoute.rule, regularAuth[0]) &&
          isProviderARPlaced(providerRoute.rule, regularAuth[0], providerRoute.ingressIndex)) {
        trustedRegular = [regularAuth[0]];
        authHeaders = lacksAuthServId(regularAuth[0])
          ? [`${providerRoute.ingressHost}; ${regularAuth[0]}`]
          : [regularAuth[0]];
      }

      // セミコロンで区切ってメソッド単位に分割し、認証タイプのステータスを抽出
      // 分割は splitOnTopLevelSemicolons を用い、コメント括弧内のセミコロンを保護する。
      // 任意のヘッダ群を対象に取れるよう汎用化し、信頼済み A-R 以外
      // （authserv-id 不一致で除外したものや ARC-AR）の報告値抽出にも再利用する。
      const statusFromHeaderList = (headerList, type) => {
        const regex = new RegExp(`\\b${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
        for (const h of headerList) {
          const methods = splitOnTopLevelSemicolons(h).slice(1);
          for (const m of methods) {
            const match = m.match(regex);
            if (match) return match[1].toLowerCase();
          }
        }
        return "none";
      };
      const parseAuthStatus = (type) => statusFromHeaderList(authHeaders, type);

      // ■ 複数 DKIM 署名への対応
      // メールによっては複数の DKIM 署名があり、一部は pass・一部は fail のことがある。
      // 全結果を個別に収集し、集約ステータスと署名ごとの結果リストの両方を返す。
      const parseDkimResults = () => {
        const results = [];
        // 重複排除用: "status|domain" の組み合わせを記録
        const seen = new Set();
        // pass した署名の (domain, selector) を重複排除前の状態で保持する。
        // 同一ドメインでセレクタ違いの署名を区別する必要がある署名範囲（h=）の評価に用いる
        const passed = [];

        for (const h of authHeaders) {
          // コメント括弧 "(2048-bit key; unprotected)" 等に含まれるセミコロンを
          // 境界として扱わないため splitOnTopLevelSemicolons を使う。
          // これにより header.d= 等の属性がセグメントから漏れない。
          const methods = splitOnTopLevelSemicolons(h).slice(1);
          for (const m of methods) {
            const statusMatch = m.match(/\bdkim\s*=\s*([a-zA-Z0-9]+)/i);
            if (statusMatch) {
              // 各DKIM署名の d= ドメインを抽出。なければ i= から取得
              const dMatch = m.match(/header\.d=([^;\s()]+)/i);
              let domain = dMatch ? dMatch[1].replace(/^[@"']|["']$/g, '') : "";
              if (!domain) {
                // header.i=@domain or header.i=user@domain からドメイン部分を取得
                const iMatch = m.match(/header\.i=([^;\s()]+)/i);
                if (iMatch) {
                  let ival = iMatch[1].replace(/["']/g, '');
                  domain = ival.includes('@') ? ival.split('@').pop() : ival;
                }
              }
              // DKIM セレクター (header.s=) を抽出: デバッグやDNS確認時に有用
              const sMatch = m.match(/header\.s=([^;\s()]+)/i);
              const selector = sMatch ? sMatch[1].replace(/["']/g, '') : "";
              const status = statusMatch[1].toLowerCase();
              if (status === "pass" && domain) passed.push({ domain, selector });

              // Authentication-Results と ARC-Authentication-Results に
              // 同じ署名結果が記録されることがあるため、status+domain で重複排除
              // セレクタも鍵に含め、同一ドメインでセレクタの異なる署名は別々に表示する
              // （1 つにまとめると、署名ごとの警告がどの署名のものか分からなくなるため）
              const key = `${status}|${domain.toLowerCase()}|${selector.toLowerCase()}`;
              if (seen.has(key)) continue;
              seen.add(key);

              results.push({
                status: status,
                domain: domain,
                selector: selector,
                segment: m
              });
            }
          }
        }

        // 集約: 1つでも pass なら pass
        let aggregated = "none";
        if (results.length > 0) {
          if (results.some(r => r.status === "pass")) aggregated = "pass";
          else if (results.some(r => r.status === "fail")) aggregated = "fail";
          else aggregated = results[0].status;
        }

        return { aggregated, results, passed };
      };

      // 認証タイプに関連する詳細情報(ドメイン, IP等)を構造化データとして抽出する
      const extractDetail = (type) => {
        if (type === 'spf') {
          let domain = "";
          let ip = "";
          let rawSegment = "";

          for (const h of authHeaders) {
            const methods = splitOnTopLevelSemicolons(h).slice(1);
            for (const m of methods) {
              if (!/\bspf\s*=/i.test(m)) continue;
              rawSegment = m.trim();

              // smtp.mailfrom
              const mailfromMatch = m.match(/smtp\.mailfrom=([^;\s()]+)/i);
              if (mailfromMatch) {
                const fromStr = mailfromMatch[1].replace(/^["'<]|["'>]$/g, '');
                domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
              } else {
                const domainOfMatch = m.match(/domain of ([^;\s()]+)/i);
                if (domainOfMatch) {
                  const fromStr = domainOfMatch[1].replace(/^["'<]|["'>]$/g, '');
                  domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
                }
              }

              // IP
              // "sender IP is x.x.x.x" は Exchange Online のコメント表記
              const ipMatch = m.match(/designates\s+([a-fA-F0-9.:]+)\s+as\s+permitted\s+sender/i) ||
                              m.match(/client-ip=([a-fA-F0-9.:]+)/i) ||
                              m.match(/smtp\.remote-ip=([a-fA-F0-9.:]+)/i) ||
                              m.match(/sender\s+IP\s+is\s+([a-fA-F0-9.:]+)/i);
              if (ipMatch) ip = ipMatch[1];

              if (domain || ip) return { domain, ip, rawSegment };
            }
          }
          return { domain, ip, rawSegment };
        }

        if (type === 'dkim') {
          const domains = new Set();

          for (const h of authHeaders) {
            const methods = splitOnTopLevelSemicolons(h).slice(1);
            for (const m of methods) {
              if (!/\bdkim\s*=/i.test(m)) continue;

              const domainRegex = /header\.(?:d|i)=([^;\s()]+)/ig;
              let match;
              while ((match = domainRegex.exec(m)) !== null) {
                let dkimDomain = match[1].replace(/["']/g, '');
                if (dkimDomain.includes('@')) dkimDomain = dkimDomain.split('@')[1];
                if (dkimDomain) domains.add(dkimDomain);
              }
            }
          }

          return { domains: Array.from(domains) };
        }

        if (type === 'dmarc') {
          let domain = "";
          let policy = "";
          let rawSegment = "";

          for (const h of authHeaders) {
            const methods = splitOnTopLevelSemicolons(h).slice(1);
            for (const m of methods) {
              if (!/\bdmarc\s*=/i.test(m)) continue;
              rawSegment = m.trim();

              const domainMatch = m.match(/header\.from=([^;\s()]+)/i);
              if (domainMatch) domain = domainMatch[1].replace(/["']/g, '');

              // p= (ポリシー) - sp= / pct= との誤マッチ防止
              const policyMatch = m.match(/(?:^|[\s(])p=([a-zA-Z]+)/i);
              if (policyMatch) policy = policyMatch[1].toLowerCase();
            }
          }
          return { domain, policy, rawSegment };
        }

        return {};
      };

      // ■ SPF/DKIM アライメントの個別評価
      // DMARCはSPFアライメントとDKIMアライメントを別々に評価する（RFC 7489）。
      // SPFドメイン(smtp.mailfrom)とDKIM署名ドメイン(header.d)を
      // それぞれヘッダFromの組織ドメインと比較する。
      const evaluateAlignment = (spfDetail, dkimSignatures, headerOrgDomain, spfStatus, dkimStatus) => {
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);

        // SPF アライメント: smtp.mailfrom のドメインと Header From の組織ドメインを比較
        // SPF が pass でない場合、ドメインが一致していてもアライメント成立とはみなさない
        let spfAligned = false;
        if (spfStatus === "pass" && spfDetail.domain) {
          // ヘッダ From 側と同じく ASCII 表記（Punycode）にそろえて比較する
          const spfOrgDomain = getOrgDomain(domainToAscii(spfDetail.domain));
          spfAligned = (spfOrgDomain === headerOrgDomain);
        }

        // DKIM アライメント: pass した署名のドメインのみを対象に評価する。
        // fail した署名のドメインが Header From と一致していてもアライメント成立とはみなさない。
        // （例: pass=trusted.com, fail=attacker.com の場合、attacker.com は無視する）
        let dkimAligned = false;
        if (dkimStatus === "pass") {
          const passedDomains = (dkimSignatures || [])
            .filter(sig => sig.status === "pass" && sig.domain)
            .map(sig => sig.domain);
          for (const d of passedDomains) {
            const dkimOrgDomain = getOrgDomain(domainToAscii(d));
            if (dkimOrgDomain === headerOrgDomain) {
              dkimAligned = true;
              break;
            }
          }
        }

        return { spfAligned, dkimAligned };
      };

      let spfStatus = parseAuthStatus("spf");
      const dkimResult = parseDkimResults();
      const dmarcStatus = parseAuthStatus("dmarc");

      let spfDetail = extractDetail("spf");
      const dkimDetail = extractDetail("dkim");
      const dmarcDetail = extractDetail("dmarc");

      // ■ Received-SPF フォールバック
      // Authentication-Results に SPF 結果がない場合（古いMTAなど）、
      // Received-SPF ヘッダから SPF ステータスとドメイン・IPを取得する
      // Received-SPF も送信者が自由に書けるため、受信側が書いたと言える位置のものだけを使う。
      // 受信境界の Received より上（内部経路のみの場合は最上段の Received より上）にある
      // 最初の Received-SPF に限る。生ヘッダが取得できない場合は補完しない（安全側）。
      const pickReceivedSpf = () => {
        if (!Array.isArray(rawHeaderOrder)) return "";
        const receivedRaw = [];
        rawHeaderOrder.forEach((h, i) => { if (h.name === "received") receivedRaw.push(i); });
        if (receivedRaw.length === 0 || receivedRaw.length !== (headers["received"] || []).length) return "";
        const recvIndex = providerRoute.ingressHost ? providerRoute.ingressIndex : Math.max(boundary.index, 0);
        const k = rawHeaderOrder.findIndex((h, i) => i < receivedRaw[recvIndex] && h.name === "received-spf");
        return k >= 0 ? rawHeaderOrder[k].value : "";
      };
      if (spfStatus === "none") {
        const spfLine = pickReceivedSpf();
        if (spfLine) {
          // ステータス: ヘッダの先頭単語 (例: "pass identity=mailfrom;")
          const statusMatch = spfLine.match(/^\s*(pass|fail|softfail|neutral|temperror|permerror|none)/i);
          if (statusMatch) {
            spfStatus = statusMatch[1].toLowerCase();
            // ドメイン: envelope-from="user@domain.com" から抽出
            const envFromMatch = spfLine.match(/envelope-from=["']?([^"';\s]+)/i);
            let domain = "";
            if (envFromMatch) {
              const fromStr = envFromMatch[1].replace(/["'>]/g, '');
              domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
            }
            // IP: client-ip=x.x.x.x から抽出
            const ipMatch = spfLine.match(/client-ip=([a-fA-F0-9.:]+)/i);
            const ip = ipMatch ? ipMatch[1] : spfDetail.ip;
            spfDetail = { domain: domain || spfDetail.domain, ip: ip };
          }
        }
      }

      // SPF/DKIM アライメントの個別評価結果（pass した署名のドメインのみで判定）
      const alignment = evaluateAlignment(spfDetail, dkimResult.results, envelope.headerOrgDomain, spfStatus, dkimResult.aggregated);

      // ■ DKIM 署名範囲（h= タグ）の評価
      // DKIM 署名が保証するのは本文と h= に列挙されたヘッダだけで、署名対象外のヘッダは
      // 署名を壊さずに誰でも差し替え・追加できる。正規の署名付きメールを入手した第三者が
      // 件名や Content-Type（本文の MIME 構造をどう解釈するか）だけを書き換えて別の宛先へ
      // 再送する「DKIM リプレイ」では、From と署名ドメインが一致したまま DMARC も pass するため、
      // 認証結果だけでは正規メールと区別できない。
      // RFC 6376 が署名を必須とするのは From のみだが、5.4.1 は Subject・Reply-To 等の
      // 署名を推奨し、MIME ヘッダの署名も強く勧めている。
      // From とアラインして pass した署名を対象に、改ざんされると受信者に実害が出るヘッダを調べる。
      //   blocking:     Subject。署名付きメールを 1 通入手するだけで、前提条件なしに件名を
      //                 差し替えて再送できる。判定（グリーン阻害）に用いる。
      //   always:       Subject / Content-Type。受信者が目にする件名と本文の解釈を決めるヘッダ。
      //                 メールに存在しない場合でも署名対象（オーバーサイン）に含まれていなければ
      //                 第三者が後から追加できるため、存在の有無に関わらず署名を求める。
      //                 Content-Type の差し替えで本文を別の内容として表示させるには、本文中に
      //                 攻撃者が入力した文字列（フォーム入力の転記等）が含まれている必要があり、
      //                 その前提はヘッダから判断できない。また Gmail 等の大手サービスも署名しない
      //                 ことが多く、判定に用いると正規メールの大半がグリーンを失うため、
      //                 DKIM カード内の管理者向け警告に留める。
      //   when present: Reply-To。返信先を攻撃者へ誘導できるヘッダで、メールに存在するのに
      //                 署名対象外の場合のみ報告する（存在しない Reply-To のオーバーサインまでは
      //                 正規の送信基盤でもほとんど行われていないため問わない）。
      // Date・To・Cc・MIME-Version 等の未署名は、差し替えても受信者の判断を直接誤らせないため報告しない。
      const SIGNED_HEADER_LABELS = {
        "subject": "Subject",
        "content-type": "Content-Type",
        "reply-to": "Reply-To"
      };
      const BLOCKING_SIGNED_HEADERS = ["subject"];
      const ALWAYS_SIGNED_HEADERS = ["subject", "content-type"];
      const SIGNED_WHEN_PRESENT_HEADERS = ["reply-to"];

      const evaluateSignedHeaderCoverage = () => {
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
        const normalizeDomain = (d) => domainToAscii((d || "").replace(/\.$/, "")).toLowerCase();

        // DKIM-Signature をタグ単位に分解する。h= の値は折り返し（FWS）を含みうるため、
        // 空白をすべて除去してからコロンで分割する。
        // b= の値（Base64）はセミコロンを含まないため、単純な ';' 分割で問題ない
        const parseSigTags = (sigHeader) => {
          const tags = {};
          for (const part of sigHeader.split(";")) {
            const eq = part.indexOf("=");
            if (eq < 0) continue;
            const name = part.slice(0, eq).trim().toLowerCase();
            if (name && !(name in tags)) tags[name] = part.slice(eq + 1).replace(/\s+/g, "");
          }
          return tags;
        };
        const signatures = (headers["dkim-signature"] || []).map(h => {
          const t = parseSigTags(h);
          return {
            domain: normalizeDomain(t.d),
            selector: (t.s || "").toLowerCase(),
            signed: new Set((t.h || "").toLowerCase().split(":").filter(Boolean))
          };
        });

        const warnings = [];
        let alignedPassCount = 0;
        let coveredPassCount = 0;
        const seenSig = new Set();

        for (const p of dkimResult.passed) {
          const passDomain = normalizeDomain(p.domain);
          if (getOrgDomain(passDomain) !== envelope.headerOrgDomain) continue;
          const passSelector = (p.selector || "").toLowerCase();

          // A-R の header.s があればセレクタまで一致する署名に絞る。
          // 記録が無い場合は同一ドメインの全署名が候補となり、どれが pass したか
          // 特定できないため、全候補が blocking ヘッダを覆っている場合のみ「覆われている」とみなす
          const matches = signatures.filter(sig =>
            sig.domain === passDomain && (!passSelector || sig.selector === passSelector));
          // DKIM-Signature ヘッダが見当たらない（経路上で除去された等）場合は判断材料が無いため評価しない
          if (matches.length === 0) continue;
          alignedPassCount++;

          let allCovered = true;
          for (const sig of matches) {
            const blocking = BLOCKING_SIGNED_HEADERS.some(name => !sig.signed.has(name));
            if (blocking) allCovered = false;

            const sigKey = `${sig.domain}|${sig.selector}`;
            if (seenSig.has(sigKey)) continue;
            seenSig.add(sigKey);
            const missing = ALWAYS_SIGNED_HEADERS.filter(name => !sig.signed.has(name))
              .concat(SIGNED_WHEN_PRESENT_HEADERS.filter(name =>
                !sig.signed.has(name) && (headers[name] || []).length > 0));
            if (missing.length > 0) {
              warnings.push({
                type: "unsigned_headers",
                domain: sig.domain,
                // 同一ドメインに複数の署名がある場合に、どの署名についての警告か示すため保持する
                selector: sig.selector,
                value: missing.map(name => SIGNED_HEADER_LABELS[name]).join(", ")
              });
            }
          }
          if (allCovered) coveredPassCount++;
        }

        // アラインした pass 署名が評価でき、そのいずれも Subject を覆っていない場合に
        // 「受信者が目にする件名をドメイン所有者が保証していない」とみなす
        return {
          warnings,
          subjectUncovered: alignedPassCount > 0 && coveredPassCount === 0
        };
      };
      const dkimCoverage = evaluateSignedHeaderCoverage();

      // ■ 認証強度の弱さ検出
      // 認証が pass していても、送信側の努力で解決できる設定上の弱さがあれば
      // 警告対象とする（設計思想: グリーン＝何もしなくて安全）。
      // ただしバッジ判定には影響させず、各カード内の警告表示のみに使う
      // （DMARC p=none の赤色表示と同じ位置づけ）。
      const detectStrengthWarnings = () => {
        const dkimWarnings = [];
        const dmarcWarnings = [];

        // --- DKIM-Signature ヘッダの署名タグ検査 ---
        // a=rsa-sha1: 衝突攻撃が現実的な非推奨アルゴリズム（RFC 8301 で禁止）
        // l= タグ:    本文の先頭 N バイトのみ署名するため、署名検証を保ったまま
        //             本文末尾へのコンテンツ追記を許してしまう既知の弱点
        const dkimSigHeaders = headers["dkim-signature"] || [];
        const seenWeakAlgo = new Set();
        const seenLimitedScope = new Set();
        for (const sigHeader of dkimSigHeaders) {
          const dMatch = sigHeader.match(/(?:^|[;\s])d=([^;\s]+)/i);
          const sigDomain = dMatch ? dMatch[1].trim() : "";

          const aMatch = sigHeader.match(/(?:^|[;\s])a=([a-zA-Z0-9-]+)/i);
          if (aMatch && aMatch[1].toLowerCase() === "rsa-sha1" && !seenWeakAlgo.has(sigDomain)) {
            seenWeakAlgo.add(sigDomain);
            dkimWarnings.push({ type: "weak_algorithm", domain: sigDomain, value: "rsa-sha1" });
          }

          const lMatch = sigHeader.match(/(?:^|[;\s])l=(\d+)/i);
          if (lMatch && !seenLimitedScope.has(sigDomain)) {
            seenLimitedScope.add(sigDomain);
            dkimWarnings.push({ type: "limited_scope", domain: sigDomain, value: `l=${lMatch[1]}` });
          }
        }

        // --- 署名対象ヘッダの不足（h= タグ） ---
        // 評価は evaluateSignedHeaderCoverage() で済ませてあり、ここでは警告一覧に合流させる
        for (const w of dkimCoverage.warnings) dkimWarnings.push(w);

        // --- DKIM 鍵長検査 ---
        // 鍵長は DKIM-Signature には現れないが、受信側 MTA が
        // Authentication-Results のコメントに "(1024-bit key; ...)" の形で
        // 記録することがある（Gmail 等）。記録がある場合のみ判定する。
        // 注意: Ed25519 署名（RFC 8463）は 256 ビットでも安全なため、
        // 512 ビット未満の表記や ed25519 の言及がある場合は RSA とみなさず警告しない
        const seenWeakKey = new Set();
        for (const sig of dkimResult.results) {
          const segment = sig.segment || "";
          if (/ed25519/i.test(segment)) continue;
          const bitsMatch = segment.match(/(\d{3,5})-bit/i);
          if (bitsMatch) {
            const bits = parseInt(bitsMatch[1], 10);
            if (bits >= 512 && bits < 2048 && !seenWeakKey.has(sig.domain)) {
              seenWeakKey.add(sig.domain);
              dkimWarnings.push({ type: "weak_key", domain: sig.domain, value: `${bits}-bit` });
            }
          }
        }

        // --- DMARC ポリシーパラメータ検査 ---
        // sp= / pct= は DNS 由来の値だが、受信側 MTA が A-R のコメントに
        // "(p=REJECT sp=NONE dis=NONE)" の形で記録した場合のみ判定可能。
        const dmarcSegment = dmarcDetail.rawSegment || "";
        // sp=none: 本ドメインのポリシーが強くてもサブドメインが無防備になる穴。
        // p=none の場合は既存のポリシー赤色表示が同じ問題を示すため重複警告しない
        const spMatch = dmarcSegment.match(/\bsp=([a-zA-Z]+)/i);
        if (spMatch && spMatch[1].toLowerCase() === "none" && dmarcDetail.policy && dmarcDetail.policy !== "none") {
          dmarcWarnings.push({ type: "weak_sp", value: "sp=none" });
        }
        // pct<100: ポリシーが一部のメールにしか適用されない部分施行状態
        const pctMatch = dmarcSegment.match(/\bpct=(\d+)/i);
        if (pctMatch && parseInt(pctMatch[1], 10) < 100) {
          dmarcWarnings.push({ type: "limited_pct", value: `pct=${pctMatch[1]}` });
        }

        return { dkim: dkimWarnings, dmarc: dmarcWarnings };
      };
      const strength = detectStrengthWarnings();

      // ■ 信頼できないソースからの報告値（判定には一切用いない・断り書き表示用）
      // ある方式の信頼済み判定が none のとき、次の「信頼しないソース」に結果が
      // あれば、それを「受信サーバの報告値（未検証）」として控えめに surface する。
      //   ① authserv-id 不一致で除外した標準 Authentication-Results
      //   ② ARC-Authentication-Results（暗号検証不能・偽造可能なため判定外）
      // 設計思想（グリーン昇格は保守的に）を守るため、これらはバッジ・カード判定に
      // 影響させず、ヘッダのピル＋ツールチップで情報提供するに留める。
      const buildReportedUnverified = () => {
        const result = { spf: null, dkim: null, dmarc: null, fromUnmatchedAR: false, fromArc: false, any: false };
        // authserv-id 不一致で信頼対象から外れた標準 A-R
        const untrustedRegular = regularAuth.filter(h => !trustedRegular.includes(h));
        const arcAuthHeaders = headers["arc-authentication-results"] || [];
        const trustedStatus = { spf: spfStatus, dkim: dkimResult.aggregated, dmarc: dmarcStatus };
        for (const type of ["spf", "dkim", "dmarc"]) {
          // 信頼済み判定で結果が出ている方式は報告不要（重複・矛盾の糊塗を避ける）
          if (trustedStatus[type] && trustedStatus[type] !== "none") continue;
          // ①不一致だった標準 A-R を優先、無ければ②ARC-AR
          let status = statusFromHeaderList(untrustedRegular, type);
          let viaAR = status !== "none";
          if (!viaAR) status = statusFromHeaderList(arcAuthHeaders, type);
          if (status === "none") continue;
          result[type] = status;
          if (viaAR) result.fromUnmatchedAR = true; else result.fromArc = true;
          result.any = true;
        }
        return result;
      };
      const reportedUnverified = buildReportedUnverified();

      // ■ 転送サービスが記録した元メールの認証結果（RELAY_ORIGINAL_AUTH_HEADERS）
      // 外側の認証とは別に、転送サービスが元メール受信時に検証した結果を抽出する。
      // 元送信者の DMARC は、全インスタンスが pass の場合のみ pass とみなす
      // （同名ヘッダが複数ある場合に、都合のよい1本だけを採用しないため）。
      const parseRelayOriginalAuth = () => {
        for (const name of RELAY_ORIGINAL_AUTH_HEADERS) {
          const list = headers[name] || [];
          if (list.length === 0) continue;
          const fromMatch = list[0].match(/header\.from=([^;\s()]+)/i);
          return {
            present: true,
            header: name,
            spf: statusFromHeaderList([list[0]], "spf"),
            dkim: statusFromHeaderList([list[0]], "dkim"),
            dmarc: statusFromHeaderList([list[0]], "dmarc"),
            fromDomain: fromMatch ? fromMatch[1].replace(/["']/g, '').toLowerCase() : "",
            dmarcPass: list.every(h => statusFromHeaderList([h], "dmarc") === "pass")
          };
        }
        return { present: false };
      };
      const relayOriginal = parseRelayOriginalAuth();

      // ■ 受信サーバが検証結果を記録していない DKIM 署名
      // 信頼済み A-R に DKIM の結果が無いのに DKIM-Signature ヘッダがある場合、
      // 「署名なし」ではなく「署名はあるが受信サーバが検証していない」状態として区別して示す。
      // 検証結果を Authentication-Results に書かず、SpamAssassin の X-Spam-Status 等にだけ
      // 記録する受信サーバで生じる。X-Spam-* は送信者が自由に付与でき、付与した MTA も
      // 特定できないため、認証結果の代わりには用いない。
      // DKIM-Signature ヘッダ自体も送信者が偽造できるため、署名の存在は安全の根拠にならない。
      // 判定（DKIM: none）は変えず、DKIM カードの表示を補う情報としてのみ使う。
      const collectUnverifiedSignatures = () => {
        if (dkimResult.aggregated !== "none") return [];
        const list = [];
        const seen = new Set();
        for (const sigHeader of (headers["dkim-signature"] || [])) {
          const dMatch = sigHeader.match(/(?:^|[;\s])d=([^;\s]+)/i);
          const sMatch = sigHeader.match(/(?:^|[;\s])s=([^;\s]+)/i);
          const domain = dMatch ? dMatch[1].trim() : "";
          const selector = sMatch ? sMatch[1].trim() : "";
          const key = `${domain.toLowerCase()}|${selector.toLowerCase()}`;
          if (seen.has(key)) continue;
          seen.add(key);
          list.push({ domain, selector });
        }
        return list;
      };
      const unverifiedSignatures = collectUnverifiedSignatures();

      return {
        // 信頼した A-R の authserv-id（Microsoft 365 の場合は補った EOP ホスト名）
        authServId: authHeaders.length > 0
          ? splitOnTopLevelSemicolons(authHeaders[0])[0].trim()
          : lastReceivedBy,
        spf: { status: spfStatus, detail: spfDetail },
        // unverifiedSignatures: 受信サーバが検証結果を記録していない署名の {domain, selector}（表示専用）
        dkim: { status: dkimResult.aggregated, detail: dkimDetail, signatures: dkimResult.results, unverifiedSignatures },
        dmarc: { status: dmarcStatus, detail: dmarcDetail },
        alignment,
        strength,
        // アラインした pass 署名が Subject を署名対象に含んでいないか
        // （DKIM リプレイで件名を差し替えうる状態か）
        dkimSubjectUnsigned: dkimCoverage.subjectUncovered,
        reportedUnverified,
        // Microsoft 365 組織内で完結した配送か（注記表示用。判定には影響させない）
        // 外部から EOP を経由したメールには必ず A-R が付与されるため、A-R が1本でも
        // 存在する場合は組織内配送とはみなさない（外部メールへの誤った注記を防ぐ）。
        m365Internal: !!providerRoute.rule && providerRoute.rule.detectInternal &&
                      providerRoute.internalOnly && regularAuth.length === 0,
        relayOriginal
      };
    };

    // =========================================================
    // 3. parseRoute - 送達経路 (Receivedヘッダ) の解析
    // =========================================================
    const parseRoute = (headers) => {
      // Receivedヘッダは「新しい順(受信側→送信元)」で記録されるため、
      // reverse()を用いて「時系列順(送信元→受信側)」に並び替えて処理する
      const rawReceived = headers["received"] || [];

      // ■ ホップごとの TLS / 暗号化状態の抽出
      // Received ヘッダの記載は受信側 MTA が書くため改ざんは可能だが、
      // 送達経路自体と同じ信頼レベルの参考情報として可視化する。
      // 対応フォーマット例:
      //   Gmail / Microsoft: "(version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 ...)"
      //   Postfix:           "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 ...)"
      //   プロトコル名:       "with ESMTPS" / "with ESMTPSA"（TLSあり）、
      //                      "with SMTP" / "with ESMTP"（TLSの記録なし）
      const parseTlsInfo = (line) => {
        // バージョン表記の正規化: "TLS1_3" / "TLSv1.3" / "TLS 1.3" → "TLS 1.3"
        const normalizeVersion = (v) => {
          const m = v.match(/(\d+)[._](\d+)/);
          return m ? `TLS ${m[1]}.${m[2]}` : `TLS ${v}`;
        };

        let version = "";
        const versionMatch = line.match(/\bversion=TLS[v_ ]?([\d._]+)/i) ||
                             line.match(/\busing\s+TLSv?([\d.]+)/i) ||
                             line.match(/\bTLSv?(1[._][0-3])\b/);
        if (versionMatch) version = normalizeVersion(versionMatch[1]);

        let cipher = "";
        const cipherMatch = line.match(/\bcipher[= ]([A-Za-z0-9_-]+)/i);
        if (cipherMatch) cipher = cipherMatch[1];

        // with 句のプロトコル名から暗号化有無を推定
        const withMatch = line.match(/\bwith\s+([A-Za-z]+)/);
        const proto = withMatch ? withMatch[1].toUpperCase() : "";
        const tlsProto = /^(ESMTPS|ESMTPSA|SMTPS|UTF8SMTPS|UTF8SMTPSA)$/.test(proto);
        const plainProto = /^(SMTP|ESMTP|ESMTPA|UTF8SMTP|UTF8SMTPA)$/.test(proto);

        // encrypted: true=TLS記録あり / false=平文プロトコル表記でTLS記録なし /
        //            null=判定材料なし（内部配送・with句なし等）
        let encrypted = null;
        if (version || tlsProto) encrypted = true;
        else if (plainProto) encrypted = false;

        return { encrypted, version, cipher };
      };

      return rawReceived.slice().reverse().map(line => {
        const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
        // 受信ホスト名の直後に空白なしで続くコメント "host(...)" は表示に含めない
        const byMatch = line.match(/\bby\s+([^\s;()]+)/i);
        const date = parseReceivedDate(line);

        // from 句からIPアドレスを抽出し、内部/外部ネットワークを判定
        const fromClause = fromMatch ? fromMatch[1] : "";
        const ip = extractIPFromReceived(fromClause);
        const isInternal = isPrivateIP(ip);

        return {
          from: fromMatch ? fromMatch[1].trim() : null,
          by: byMatch ? byMatch[1] : null,
          date: date,
          ip: ip,
          isInternal: isInternal,
          tls: parseTlsInfo(line),
          raw: line
        };
      }).filter(hop => hop.from || hop.by);
    };

    // =========================================================
    // 4. parseArcChain - ARC (Authenticated Received Chain) の解析
    // =========================================================
    // メールが転送される際に付与される ARC ヘッダセットを解析し、
    // チェーン番号ごとの検証状態・署名ドメイン・認証サマリーを抽出する。
    // ARC は転送先のMTAがオリジナルの認証結果を保証するための仕組み (RFC 8617)。
    const parseArcChain = (headers) => {
      const arcSeals = headers["arc-seal"] || [];
      const arcAuthResults = headers["arc-authentication-results"] || [];

      if (arcSeals.length === 0 && arcAuthResults.length === 0) return [];

      // ARC-Seal から各チェーンの情報を抽出
      const chains = new Map();
      for (const seal of arcSeals) {
        // チェーン番号 (i=1, i=2, ...)
        const iMatch = seal.match(/\bi=(\d+)/);
        // チェーン検証状態 (cv=none / cv=pass / cv=fail)
        const cvMatch = seal.match(/\bcv=(\w+)/i);
        // 署名ドメイン (d=example.com)
        const dMatch = seal.match(/\bd=([^\s;]+)/i);

        if (iMatch) {
          const chainNum = parseInt(iMatch[1], 10);
          chains.set(chainNum, {
            i: chainNum,
            cv: cvMatch ? cvMatch[1].toLowerCase() : "unknown",
            domain: dMatch ? dMatch[1] : "",
            authSummary: ""
          });
        }
      }

      // ARC-Authentication-Results から各チェーンの認証サマリーを抽出
      for (const aar of arcAuthResults) {
        const iMatch = aar.match(/\bi=(\d+)/);
        if (!iMatch) continue;
        const chainNum = parseInt(iMatch[1], 10);

        // SPF/DKIM/DMARC の結果をコンパクトにまとめる
        const summaryParts = [];
        const spfMatch = aar.match(/\bspf=(\w+)/i);
        const dkimMatch = aar.match(/\bdkim=(\w+)/i);
        const dmarcMatch = aar.match(/\bdmarc=(\w+)/i);
        if (spfMatch) summaryParts.push(`spf=${spfMatch[1].toLowerCase()}`);
        if (dkimMatch) summaryParts.push(`dkim=${dkimMatch[1].toLowerCase()}`);
        if (dmarcMatch) summaryParts.push(`dmarc=${dmarcMatch[1].toLowerCase()}`);

        if (chains.has(chainNum)) {
          chains.get(chainNum).authSummary = summaryParts.join(" ");
        } else {
          // ARC-Seal がなくても ARC-Authentication-Results だけある場合
          chains.set(chainNum, {
            i: chainNum,
            cv: "unknown",
            domain: "",
            authSummary: summaryParts.join(" ")
          });
        }
      }

      // チェーン番号順にソートして返す
      return Array.from(chains.values()).sort((a, b) => a.i - b.i);
    };

    // =========================================================
    // 5. parseMessageBody - MIME構造を走査してHTML本文を取得
    // =========================================================
    // fullMessage.parts のツリーを再帰的に走査し、text/html パーツを優先的に取得する。
    // HTML が見つからない場合は text/plain にフォールバックする。
    const parseMessageBody = (fullMsg) => {
      let htmlBody = "";
      let textBody = "";

      const walkParts = (parts) => {
        if (!parts) return;
        for (const part of parts) {
          const ct = (part.contentType || "").toLowerCase();
          if (ct === "text/html" && part.body && !htmlBody) {
            htmlBody = part.body;
          } else if (ct === "text/plain" && part.body && !textBody) {
            textBody = part.body;
          }
          // multipart/* の子パーツを再帰走査
          if (part.parts) walkParts(part.parts);
        }
      };

      walkParts(fullMsg.parts);
      return htmlBody || textBody || "";
    };

    // =========================================================
    // 6. analyzeLinkSafety - メール本文のリンク安全性分析
    // =========================================================
    // メール本文のHTML/テキストを解析し、フィッシングの特徴や未信頼ドメイン、
    // プライバシー上の注意点を検出する。
    // findings の level は深刻度と解決手段で4段階に分類される:
    //   [critical]  リンクテキスト偽装、javascript:/data: URI、HTMLフォーム埋め込み
    //               → 明確なフィッシングの兆候。ホワイトリスト対象外。
    //   [suspicious] IPアドレスリンク、IDNホモグラフ、URLショートナー
    //               → リンク先そのものが怪しい書式。ホワイトリスト対象外。
    //   [untrusted]  全リンク外部ドメイン、最大CTAが外部ドメイン
    //               → ドメインが未知なだけ。信頼リスト追加で解消する。
    //   [privacy]    トラッキングピクセル
    //               → プライバシー上の注意喚起。フィッシングではない。
    //   [info]       リンクドメイン一覧、リソースドメイン一覧
    const analyzeLinkSafety = (bodyContent, headerOrgDomain, trustedDomains) => {
      const findings = [];   // { level: "critical"|"suspicious"|"untrusted"|"privacy"|"info", type, detail }
      const linkDomains = new Map(); // domain → { count, matchesFrom }
      const resourceDomains = new Map(); // domain → { count, matchesFrom } (画像等の外部リソース)
      const deceptiveDomains = new Set(); // リンクテキスト偽装の実際のリンク先組織ドメイン
      // untrusted レベルの findings から参照される、未信頼かつ Header From と不一致の外部リンクドメイン集合
      // findings 行からワンクリック信頼を行う際の対象ドメイン解決に使用する
      const externalLinkDomains = new Set();

      // フィッシングで多用される URL ショートナーサービスのドメインリスト
      const URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bl.ink", "rb.gy", "cutt.ly", "shorturl.at",
        "tiny.cc", "lnkd.in", "surl.li", "rebrand.ly", "v.gd", "qr.ae",
        "bc.vc", "yourls.org"
      ];

      if (!bodyContent) return { findings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains: new Set(), externalLinkDomains };

      // DOMParser で本文HTMLをパースし、リンク・フォーム・画像を解析する
      const parser = new DOMParser();
      const doc = parser.parseFromString(bodyContent, "text/html");
      const getOrgDomain = window.getOrganizationalDomain || ((d) => d);

      // ■ ホモグラフ検査の参照ドメイン: 送信者ドメインと信頼済みドメイン（いずれも組織ドメイン）
      // リンク先がこれらに「似せた別ドメイン」（骨格が一致するが実体は異なる）であれば、
      // 正規の送信者が使うことはまず無い偽装リンクとして critical 扱いにする。
      const lookalikeIndex = buildSkeletonIndex([
        headerOrgDomain,
        ...Array.from(trustedDomains || []).map(d => getOrgDomain(domainToAscii(d)))
      ]);
      const lookalikeLinks = new Set();   // "偽装ドメイン ≈ 本物" の表示用文字列
      // 国際化ドメインのリンク先を表示用の "Unicode (ASCII)" 形式で記録する
      const idnLabel = (info) => `${info.unicode} (${info.ascii})`;
      // リンク先ホストのホモグラフ検査（<a> と本文中の URL の両方で使う）
      //   - 紛らわしい文字を含む国際化ドメイン → idnHomographLinks（suspicious）
      //   - 紛らわしい兆候の無い国際化ドメイン → idnLinks（suspicious。表示で区別する）
      //   - 参照ドメインに似せた別ドメイン     → lookalikeLinks（critical）
      const inspectHostHomograph = (host, orgDomain) => {
        const info = analyzeDomainHomograph(host);
        if (info.isIdn) {
          if (info.isDeceptive) idnHomographLinks.add(idnLabel(info));
          else idnLinks.add(idnLabel(info));
        }
        const target = (trustedDomains && trustedDomains.has(orgDomain)) ? null : findLookalikeTarget(orgDomain, lookalikeIndex);
        if (target) {
          lookalikeLinks.add(`${domainToUnicode(orgDomain)} ≈ ${target}`);
          deceptiveDomains.add(orgDomain);
        }
      };

      // ■ フォーム検知 (項目3): メール内の <form> 要素は極めて異常
      const forms = doc.querySelectorAll("form");
      if (forms.length > 0) {
        findings.push({
          level: "critical",
          type: "embedded_form",
          detail: msg("linkEmbeddedForm")
        });
      }

      // ■ リンク解析: 全 <a href="..."> を走査
      // 各リンクの推定表示面積も記録し、最大CTAの判定に使う
      const anchors = doc.querySelectorAll("a[href]");
      const linkInfos = []; // { orgDomain, matchesFrom, estimatedArea }

      // 重複の集約用: 同じ type のドメイン/IPを集めてから1つの finding にまとめる
      // これにより同種の警告が大量に並ぶ肥大化を防ぐ
      const ipAddressLinks = new Set();
      const idnHomographLinks = new Set();
      const idnLinks = new Set();
      const urlShortenerLinks = new Set();

      for (const a of anchors) {
        const href = (a.getAttribute("href") || "").trim();
        if (!href || href.startsWith("#") || href.startsWith("mailto:")) continue;

        // --- 項目2: javascript: / data: URI 検知 ---
        const hrefLower = href.toLowerCase().replace(/\s/g, '');
        if (hrefLower.startsWith("javascript:") || hrefLower.startsWith("data:")) {
          findings.push({
            level: "critical",
            type: "dangerous_scheme",
            detail: msg("linkDangerousScheme") + ` (${escapeHTML(href.substring(0, 30))}...)`
          });
          continue;
        }

        // URL からホスト名を抽出
        let linkHost = "";
        try {
          const url = new URL(href, "http://dummy.invalid");
          linkHost = url.hostname.toLowerCase();
        } catch {
          continue;
        }

        if (!linkHost || linkHost === "dummy.invalid") continue;

        // --- 項目1: リンクテキスト偽装検知 ---
        const linkText = (a.textContent || "").trim();
        const urlInText = linkText.match(/^https?:\/\/([^\/\s?#]+)/i);
        if (urlInText) {
          // 表示テキストのホスト名も、実リンク先（URL パーサが ASCII 表記に変換済み）と同じく
          // ASCII 表記にそろえてから比べる。そろえないと、テキストもリンク先も同じ正規の
          // 国際化ドメイン（例: https://例え.jp/）が、表記の違いだけで偽装と誤判定される。
          const displayHost = domainToAscii(urlInText[1].replace(/:\d+$/, ""));
          const displayOrgDomain = getOrgDomain(displayHost);
          const hrefOrgDomain = getOrgDomain(linkHost);
          if (displayOrgDomain !== hrefOrgDomain) {
            // リンクテキスト偽装（critical）は信頼リスト対象外
            // ドメイン信頼性とは無関係に、表示テキストと実リンク先が異なる場合は必ず警告
            findings.push({
              level: "critical",
              type: "deceptive_text",
              detail: msg("linkDeceptiveText"),
              targetDomain: hrefOrgDomain
            });
            deceptiveDomains.add(hrefOrgDomain);
          }
        }

        // --- 項目4: IPアドレス直指定リンク検知 ---
        // 同一ホストの重複は集約する
        if (isIPv4Like(linkHost) || isIPv6Like(linkHost) || linkHost.startsWith("[")) {
          ipAddressLinks.add(linkHost);
        }

        // --- 項目5: IDNホモグラフ攻撃検知・類似ドメイン検知 ---
        const linkOrgDomain = getOrgDomain(linkHost);
        inspectHostHomograph(linkHost, linkOrgDomain);

        // --- 項目6: URLショートナー検知 ---
        if (URL_SHORTENERS.some(s => linkHost === s || linkHost.endsWith("." + s))) {
          urlShortenerLinks.add(linkHost);
        }

        // --- 項目7: リンクドメイン一覧収集 ---
        const matchesFrom = (linkOrgDomain === headerOrgDomain);
        if (linkDomains.has(linkOrgDomain)) {
          linkDomains.get(linkOrgDomain).count++;
        } else {
          linkDomains.set(linkOrgDomain, { count: 1, matchesFrom });
        }

        // --- CTA推定面積の計算 ---
        // <a> 内に <img> がある場合はその画像サイズ、なければテキスト長で推定
        let estimatedArea = linkText.length * 16; // テキストリンクのデフォルト推定
        const innerImg = a.querySelector("img");
        if (innerImg) {
          const w = parseInt(innerImg.getAttribute("width")) || 0;
          const h = parseInt(innerImg.getAttribute("height")) || 0;
          if (w > 0 && h > 0) estimatedArea = w * h;
          else estimatedArea = 10000; // サイズ不明の画像リンクは大きめに推定
        }
        // ボタン風スタイルの検出: padding や display:block があれば面積を加算
        const style = a.getAttribute("style") || "";
        if (/padding/i.test(style) || /display\s*:\s*block/i.test(style)) {
          estimatedArea = Math.max(estimatedArea, 5000);
        }

        linkInfos.push({ orgDomain: linkOrgDomain, matchesFrom, estimatedArea });
      }

      // 重複集約された ip/idn/shortener の findings を生成
      // 同種が複数ある場合は detail 末尾に "(host1, host2, +N more)" 形式で集約表示する
      // 表示上の最大件数は 3 までとし、超過分は "+N more" でまとめる
      const formatAggregated = (set) => {
        const arr = Array.from(set);
        if (arr.length === 0) return "";
        const shown = arr.slice(0, 3).map(escapeHTML).join(", ");
        const extra = arr.length > 3 ? `, +${arr.length - 3} more` : "";
        return `(${shown}${extra})`;
      };
      if (ipAddressLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "ip_address_link",
          detail: msg("linkIpAddress") + " " + formatAggregated(ipAddressLinks)
        });
      }
      if (urlShortenerLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "url_shortener",
          detail: msg("linkShortener") + " " + formatAggregated(urlShortenerLinks)
        });
      }

      // ■ テキスト状態のURL検出
      const textContent = doc.body ? doc.body.textContent : "";
      const textUrlRegex = /https?:\/\/([^\s"'<>)\]]+)/gi;
      const textUrls = []; // テキスト中のURL一覧（唯一のURL判定に使用）
      let textUrlMatch;
      while ((textUrlMatch = textUrlRegex.exec(textContent)) !== null) {
        try {
          const url = new URL(textUrlMatch[0]);
          const host = url.hostname.toLowerCase();
          if (!host) continue;
          const orgDomain = getOrgDomain(host);
          const matchesFrom = (orgDomain === headerOrgDomain);
          textUrls.push({ orgDomain, matchesFrom });
          if (!linkDomains.has(orgDomain)) {
            linkDomains.set(orgDomain, { count: 1, matchesFrom });
          }
          // 本文中の URL もクリックされ得るため、リンクと同じくホモグラフを検査する
          inspectHostHomograph(host, orgDomain);
        } catch {
          // パース不能なURLはスキップ
        }
      }

      // ■ ホモグラフ関連の findings（<a> と本文中の URL の検査結果をまとめて生成）
      // 参照ドメインに似せた別ドメインは、リンクテキスト偽装と同じく信頼リスト対象外の critical。
      if (lookalikeLinks.size > 0) {
        findings.push({
          level: "critical",
          type: "lookalike_domain",
          detail: msg("linkLookalikeDomain") + " " + formatAggregated(lookalikeLinks)
        });
      }
      // 紛らわしい文字を含む国際化ドメインと、兆候の無い国際化ドメインは、いずれも suspicious。
      // 後者は「国際化ドメインであること」自体を知らせるもので、文言で前者と区別する。
      if (idnHomographLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "idn_homograph",
          detail: msg("linkIdnHomograph") + " " + formatAggregated(idnHomographLinks)
        });
      }
      if (idnLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "idn_domain",
          detail: msg("linkIdnDomain") + " " + formatAggregated(idnLinks)
        });
      }

      // ■ すべてのリンクが外部ドメイン → 未信頼レベル
      // HTMLメール: 全 <a> リンクのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      // テキストメール: 全URLのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      // untrusted レベルはユーザーが信頼リストに追加すれば解消するため、
      // 攻撃の兆候を示す "suspicious" とは区別して扱う。
      const isHtml = /<[a-z][\s\S]*>/i.test(bodyContent);
      const isSafeLink = (l) => l.matchesFrom || (trustedDomains && trustedDomains.has(l.orgDomain));
      let hasAllExternalWarning = false;
      if (isHtml && linkInfos.length > 0 && !linkInfos.some(isSafeLink)) {
        findings.push({ level: "untrusted", type: "all_links_external", detail: msg("linkAllExternalUntrusted") });
        hasAllExternalWarning = true;
        // 対象の外部ドメインを externalLinkDomains に収集
        for (const l of linkInfos) {
          if (!l.matchesFrom && !(trustedDomains && trustedDomains.has(l.orgDomain))) {
            externalLinkDomains.add(l.orgDomain);
          }
        }
      } else if (!isHtml && textUrls.length > 0 && !textUrls.some(isSafeLink)) {
        findings.push({ level: "untrusted", type: "all_links_external", detail: msg("linkAllExternalUntrusted") });
        hasAllExternalWarning = true;
        for (const l of textUrls) {
          if (!l.matchesFrom && !(trustedDomains && trustedDomains.has(l.orgDomain))) {
            externalLinkDomains.add(l.orgDomain);
          }
        }
      }

      // ■ 最大CTAリンクが外部ドメイン → 未信頼レベル
      // メール内で最も目立つクリック領域（推定面積最大）のリンク先が送信者ドメインと異なる場合
      // 全リンク外部警告が出ている場合は冗長なので省略
      if (!hasAllExternalWarning && linkInfos.length > 0) {
        const largestCta = linkInfos.reduce((max, cur) => cur.estimatedArea > max.estimatedArea ? cur : max);
        if (!isSafeLink(largestCta)) {
          findings.push({ level: "untrusted", type: "cta_external", detail: msg("linkCtaExternalUntrusted") });
          externalLinkDomains.add(largestCta.orgDomain);
        }
      }

      // ■ 画像・外部リソース解析
      const images = doc.querySelectorAll("img[src]");
      let trackingPixelCount = 0;
      const trackingPixelDomains = new Set(); // トラッキングピクセルの配信元ドメイン
      for (const img of images) {
        const src = (img.getAttribute("src") || "").trim();
        if (!src || src.startsWith("data:") || src.startsWith("cid:")) continue;

        let imgHost = "";
        try {
          const url = new URL(src, "http://dummy.invalid");
          imgHost = url.hostname.toLowerCase();
        } catch {
          continue;
        }
        if (!imgHost || imgHost === "dummy.invalid") continue;

        const imgOrgDomain = getOrgDomain(imgHost);
        const matchesFrom = (imgOrgDomain === headerOrgDomain);

        // トラッキングピクセル検知: 1x1 や 0x0 の非表示画像
        const w = parseInt(img.getAttribute("width")) || -1;
        const h = parseInt(img.getAttribute("height")) || -1;
        const style = img.getAttribute("style") || "";
        const isPixel = (w >= 0 && w <= 2 && h >= 0 && h <= 2) ||
                        /width\s*:\s*[01]px/i.test(style) ||
                        /height\s*:\s*[01]px/i.test(style) ||
                        /display\s*:\s*none/i.test(style) ||
                        /visibility\s*:\s*hidden/i.test(style);
        if (isPixel) {
          trackingPixelCount++;
          trackingPixelDomains.add(imgOrgDomain);
        }

        // リソースドメイン一覧に追加（トラッキングピクセルも含める）
        if (resourceDomains.has(imgOrgDomain)) {
          resourceDomains.get(imgOrgDomain).count++;
        } else {
          resourceDomains.set(imgOrgDomain, { count: 1, matchesFrom });
        }
      }

      // トラッキングピクセルが検出された場合は privacy レベルとして情報提供
      // プライバシー上の注意喚起であり、フィッシング指標ではない。グリーン判定は阻害しない。
      if (trackingPixelCount > 0) {
        findings.push({
          level: "privacy",
          type: "tracking_pixel",
          detail: msg("linkTrackingPixel") + ` (×${trackingPixelCount})`
        });
      }

      // findings の重複排除（同じ type + detail は1回だけ）
      const uniqueFindings = [];
      const seenFindings = new Set();
      for (const f of findings) {
        const key = `${f.type}|${f.detail}`;
        if (!seenFindings.has(key)) {
          seenFindings.add(key);
          uniqueFindings.push(f);
        }
      }

      return { findings: uniqueFindings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains, externalLinkDomains };
    };

    // =========================================================
    // 7. determineSecurityStatus - 総合的なセキュリティ判定
    // =========================================================
    // 認証結果・アライメント・フィッシング指標を総合し、バッジ色と判定理由を決定する。
    // グリーン条件:
    //   SPF pass, DKIM pass, DMARC pass (policy ≠ none),
    //   DMARCアライメント成立, 表示名なりすましなし,
    //   critical/suspicious/untrusted のいずれのリンク指標もなし
    // エンベロープドメイン不一致: DMARC pass かつアライメント成立時はグリーンを阻害しない
    // senderHomograph:  parseEnvelope が返す送信者ドメインのホモグラフ検査結果
    // replyToHomograph: parseEnvelope が返す Reply-To ドメインのホモグラフ検査結果（該当なしは null）
    const determineSecurityStatus = (authResults, isDomainAligned, envelopeFrom, isDisplayNameSpoofed, linkSafety, senderHomograph, replyToHomograph) => {
      const isSpfOk = authResults.spf.status === "pass";
      const isDkimOk = authResults.dkim.status === "pass";
      // DMARC は pass のみを合格とする。
      // status=none（DMARCレコード未設定）は管理者がレコードを追加すれば解決できるため、
      // 「設定不備」として警告対象にする。
      const isDmarcOk = authResults.dmarc.status === "pass";

      // ■ DMARCポリシーの情報表示
      // p=none は「DMARCレコードはあるが認証失敗でも何もしない」という設定。
      // DMARCカード内でポリシーを赤色表示して管理者に改善を促すが、
      // 認証自体は成功しているためグリーン判定は阻害しない。
      // （一般ユーザーにはp=noneで自動展開しないことで情報過多を防ぐ）

      // ■ DMARCアライメント判定 (RFC 7489)
      // SPFドメイン(smtp.mailfrom)またはDKIM署名ドメイン(header.d)の
      // 少なくとも一方がHeader Fromの組織ドメインと一致する必要がある。
      // 両方とも不一致の場合、認証が通っていても信頼性が低い。
      const al = authResults.alignment || {};
      const isDmarcAligned = !!(al.spfAligned || al.dkimAligned);

      // ■ リンク系指標の集約 (4レベル)
      // critical:   確度の高いフィッシング指標。専用バッジへ昇格。
      // suspicious: ドメインや書式そのものが怪しいが、ホワイトリスト対象外のため
      //             警告として扱う（グリーン阻害）。
      // untrusted:  未信頼外部ドメインなだけで、信頼リスト追加で解消する。
      //             思想に従いユーザーが信頼表明するまでグリーンにはしない（阻害あり）。
      // privacy:    トラッキングピクセル等のプライバシー注意。グリーン阻害なし。
      const hasCriticalPhishing = linkSafety?.findings?.some(f => f.level === "critical") || false;
      const hasSuspiciousLink = linkSafety?.findings?.some(f => f.level === "suspicious") || false;
      const hasUntrustedLink = linkSafety?.findings?.some(f => f.level === "untrusted") || false;
      // privacy レベル（トラッキングピクセル等）は判定に影響しない

      // ■ 判定理由の収集: グリーンでない全理由を記録
      // 認証系は実ステータスを含め、アライメントはpassかつ不成立の場合のみ記録
      const verdictReasons = [];

      // ■ 総合判定
      // DMARCがpassかつアライメント成立していれば、エンベロープドメイン不一致はグリーンを阻害しない
      // （SendGrid等の正当な外部配信サービス利用パターンに対応）
      const domainCheckOk = isDmarcOk && isDmarcAligned ? true : isDomainAligned;

      // ■ 転送サービス経由メールの元送信者認証
      // 外側の認証が示すのは「転送サービスが自ドメインで送った」ことまでで、
      // 元送信者の正当性は転送サービスが記録した元メールの認証結果にしか現れない。
      // その報告値が存在し DMARC pass でない場合は、外側がすべて pass でもグリーンにしない。
      // 報告値は検証不能なため、ヘッダが無いメールの判定を緩める方向には使わない。
      const relayOriginal = authResults.relayOriginal || { present: false };
      const isRelayOriginalUnverified = relayOriginal.present && !relayOriginal.dmarcPass;

      // ■ 送信者ドメインのホモグラフ（見た目の偽装）
      // 偽ドメインを取得した攻撃者は認証を正しく通せるため、認証結果とは独立に判定する。
      // 「別のドメインになりすますための文字が使われている」こと自体が確度の高い攻撃の兆候であり、
      // リンク偽装と同じくフィッシング判定（最も重いバッジ）に昇格させる。
      const isSenderHomograph = !!(senderHomograph && senderHomograph.isHomograph);

      // ■ Reply-To ドメインのホモグラフ
      // 返信先が偽装ドメインなら、返信を攻撃者へ誘導する手口の可能性が高い。
      // 送信者ドメイン自体は正当でありうるためフィッシング判定までは上げないが、
      // 受信者が注意すべき事柄が残る以上グリーンにはしない（警告付きの判定に留める）。
      const isReplyToHomograph = !!replyToHomograph;

      // ■ DKIM リプレイの余地（件名が署名で守られていない）
      // DMARC が DKIM アライメントだけで pass している（SPF はアラインしていない）場合、
      // 「正規の送信基盤から直接届いた」保証は無く、ドメイン所有者が保証するのは署名範囲だけになる。
      // その署名が Subject を含まなければ、正規の署名付きメールを入手した第三者が
      // 件名を差し替えて再送しても DMARC pass のまま届く。
      // （Content-Type の未署名は悪用に本文側の前提条件が要り、大手サービスでも一般的なため
      //   判定には用いず、DKIM カード内の警告に留める。evaluateSignedHeaderCoverage 参照）
      // 署名範囲は送信側（署名を行う送信基盤）が広げれば解消できる不備のためグリーンにはしないが、
      // 認証自体は成功しており偽装と断定はできないため、警告付きの判定に留める。
      // SPF もアラインしている場合は第三者による再送が成立しないため、DKIM カード内の警告のみとする。
      const isDkimReplayRisk = isDmarcOk && !!al.dkimAligned && !al.spfAligned &&
                               !!authResults.dkimSubjectUnsigned;

      const isSecure = isSpfOk && isDkimOk && isDmarcOk &&
                       domainCheckOk && isDmarcAligned &&
                       !isDisplayNameSpoofed && !hasCriticalPhishing &&
                       !hasSuspiciousLink && !hasUntrustedLink &&
                       !isRelayOriginalUnverified && !isSenderHomograph && !isReplyToHomograph &&
                       !isDkimReplayRisk;

      // 認証系: pass 以外なら実際のステータスを記録 (例: "SPF: softfail")
      if (!isSpfOk) verdictReasons.push(`SPF: ${authResults.spf.status}`);
      if (!isDkimOk) verdictReasons.push(`DKIM: ${authResults.dkim.status}`);
      if (!isDmarcOk) verdictReasons.push(`DMARC: ${authResults.dmarc.status}`);
      // アライメント: 認証が pass しているのにアライメント不成立の場合のみ表示
      // ただし DMARC pass かつ DMARC アライメント成立（SPF/DKIMの片方が成立）の場合は、
      // もう片方の個別アライメント失敗は DMARC 上問題ないため非表示にする。
      // 例: Sailthru等のバルク配信で d=service.com、SPF が brand.com で aligned のケース。
      const dmarcOverallOk = isDmarcOk && isDmarcAligned;
      if (!dmarcOverallOk && isSpfOk && !al.spfAligned) verdictReasons.push("spf_align_fail");
      if (!dmarcOverallOk && isDkimOk && !al.dkimAligned) verdictReasons.push("dkim_align_fail");
      if (!domainCheckOk) verdictReasons.push("domain_not_aligned");
      if (isDisplayNameSpoofed) verdictReasons.push("display_name_spoofed");
      if (isRelayOriginalUnverified) verdictReasons.push("relay_original_unverified");
      if (isDkimReplayRisk) verdictReasons.push("dkim_replay_risk");
      // 送信者ドメインの偽装は、リンク起因のフィッシングと区別できるよう判定理由として明示する
      if (isSenderHomograph) verdictReasons.push("sender_homograph");
      if (isReplyToHomograph) verdictReasons.push("reply_to_homograph");
      // phishing_critical はバッジ自体が「💀 フィッシング検出」になるため判定理由には含めない
      // privacy（トラッキングピクセル）は判定理由タグに出さず、リンク安全性カード内で情報提供
      if (hasSuspiciousLink) verdictReasons.push("phishing_suspicious");
      if (hasUntrustedLink) verdictReasons.push("link_untrusted");

      let badgeClass = "warning";
      let badgeText = msg("badgeUnverified");

      if (isSenderHomograph) {
        // 送信者ドメインの偽装: リンクの有無に関わらずフィッシング判定。
        // バッジ文言は「リンク先相違」ではなく「なりすましドメイン」とし、原因を取り違えさせない。
        badgeClass = "phishing";
        badgeText = msg("badgeHomograph");
      } else if (hasCriticalPhishing) {
        // フィッシング確定: リンク偽装等の確度が極めて高い指標 → 専用バッジ（レッドより重い）
        badgeClass = "phishing";
        badgeText = msg("badgePhishing");
      } else if (isSecure) {
        badgeClass = "secure";
        badgeText = msg("badgeAuthPass");
      } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
        badgeClass = "danger";
        badgeText = msg("badgeAuthFailed");
      } else if ((isSpfOk || isDkimOk) && isDmarcOk) {
        // SPF/DKIM・DMARC全て通っているが他の条件（アライメント・なりすまし等）で不合格
        // DMARC が検証するのはヘッダ From であり、エンベロープ送信者が空（Return-Path: <>）や
        // 取得できない場合でも DMARC pass の事実は変わらないため、ここでは envelopeFrom を問わない。
        // （空の送信者は配送エラー通知・自動応答のほか、SPF を HELO で評価させる手口にも使われる）
        badgeClass = "warning";
        badgeText = msg("badgeAuthPassWarning");
      } else if ((isSpfOk || isDkimOk) && envelopeFrom !== "Unknown") {
        // SPF/DKIMの一部は通っているがDMARCがpassでない → 「認証成功」とは言わない
        badgeClass = "warning";
        badgeText = msg("badgeAuthPartial");
      }

      return {
        isSecure,
        isSpfOk,
        isDkimOk,
        isDmarcOk,
        isDmarcAligned,
        hasCriticalPhishing,
        hasSuspiciousLink,
        hasUntrustedLink,
        isSenderHomograph,
        verdictReasons,
        badgeClass,
        badgeText,
        shouldAutoExpand: false
      };
    };

    // =========================================================
    // 8. buildUI - UI構築 (HTML/CSS) — Shadow DOM・i18n・ダークモード完全対応
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains, compactMode) => {

      // --- Bootstrap Icons (SVG インライン定義) ---
      const BI = {
        checkCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0m-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>',
        xCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0M5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293z"/></svg>',
        exclamationTriangleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5m.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2"/></svg>',
        exclamationOctagonFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M11.46.146A.5.5 0 0 0 11.107 0H4.893a.5.5 0 0 0-.353.146L.146 4.54A.5.5 0 0 0 0 4.893v6.214a.5.5 0 0 0 .146.353l4.394 4.394a.5.5 0 0 0 .353.146h6.214a.5.5 0 0 0 .353-.146l4.394-4.394a.5.5 0 0 0 .146-.353V4.893a.5.5 0 0 0-.146-.353zm-3.46 4.85a.905.905 0 0 1 .9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5m.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2"/></svg>',
        envelopeFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M.05 3.555A2 2 0 0 1 2 2h12a2 2 0 0 1 1.95 1.555L8 8.414zM0 4.697v7.104l5.803-3.558zM6.761 8.83l-6.57 4.027A2 2 0 0 0 2 14h12a2 2 0 0 0 1.808-1.144l-6.57-4.027L8 9.586zm5.436-.575L18 11.801V4.697z"/></svg>',
        infoCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16m.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2"/></svg>',
        lockFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2m3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2"/></svg>',
        unlockFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M11 1a2 2 0 0 0-2 2v4a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h5V3a3 3 0 0 1 6 0v4a.5.5 0 0 1-1 0V3a2 2 0 0 0-2-2"/></svg>',
        clipboard: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>',
        arrowUpRightCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m5.854 2.146a.5.5 0 1 0 .708.708L9.243 8.17H7.5A.5.5 0 0 1 7 7.67V6.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H9.33a.5.5 0 0 1-.5-.5V7.828z"/></svg>',
        arrowDownLeftCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0m-5.854-2.146a.5.5 0 1 0-.708-.708L6.757 7.83h1.743a.5.5 0 0 1 .5.5v1.17a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-3a.5.5 0 0 1 .5-.5h1.17a.5.5 0 0 1 .5.5v1.072z"/></svg>',
        shieldFillCheck: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99 1.614 2.111 3.596 3.197 4.09 3.456a1.54 1.54 0 0 0 1.348 0c.494-.259 2.476-1.345 4.09-3.456 1.678-2.195 3.061-5.513 2.466-9.99a1.54 1.54 0 0 0-1.044-1.263 55 55 0 0 0-2.887-.87C9.843.266 8.69 0 8 0m2.146 5.146a.5.5 0 0 1 .708.708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7.5 7.793z"/></svg>',
        eyeSlashFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="m10.79 12.912-1.614-1.615a3.5 3.5 0 0 1-4.474-4.474L3.086 5.21C1.89 6.268 1 7.55 1 8c0 1.61 3.52 7 7 7a7 7 0 0 0 2.79-.088M5.21 3.086A7 7 0 0 1 8 3c3.48 0 7 5.39 7 7a7 7 0 0 1-.088 2.79l-2.062-2.063C13.48 9.308 14 8.543 14 8c0-1.61-3.52-7-7-7a7 7 0 0 0-1.17.1zm2.11 2.11a2.5 2.5 0 0 1 3.475 3.475l-3.475-3.475z"/><path d="M13.477 14.89 1.113 2.525a.5.5 0 1 1 .707-.707l12.366 12.365a.5.5 0 1 1-.707.708"/></svg>',
        dash: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M4 8a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7A.5.5 0 0 1 4 8"/></svg>',
        dashCircleFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0M4.5 7.5a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1z"/></svg>',
        rocketTakeoffFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M12.052.148a.76.76 0 0 0-.583-.146L7.155 1.111l-.813.813c-.114.114-.15.285-.093.436l.72 1.916-2.52 2.52-1.921-.718a.38.38 0 0 0-.438.093l-.813.813L3.12 9.155a.76.76 0 0 0 .146.583l2.83 2.83a.76.76 0 0 0 .583.146l2.171-1.832.813-.813a.38.38 0 0 0 .093-.438l-.718-1.921 2.52-2.52 1.916.72a.38.38 0 0 0 .436-.093l.813-.813L12.2 4.893a.76.76 0 0 0-.148-.583zm-1.87 7.746a.75.75 0 1 1-1.06-1.06.75.75 0 0 1 1.06 1.06z"/></svg>',
        houseFill: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M8.707 1.5a1 1 0 0 0-1.414 0L.646 8.146a.5.5 0 0 0 .708.708L8 2.207l6.646 6.647a.5.5 0 0 0 .708-.708L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293z"/><path d="m8 3.293 6 6V13.5a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 2 13.5V9.293z"/></svg>',
        globe: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m7.5-6.923c-.67.204-1.335.82-1.887 1.855A8 8 0 0 0 5.145 4H7.5zM4.09 4a9.2 9.2 0 0 1 .64-1.539 6.7 6.7 0 0 1 .597-.933A7.03 7.03 0 0 0 2.255 4zm-.582 1H1.053a7 7 0 0 0 0 2h2.222zm-.222 3H1.053a7 7 0 0 0 0 2h2.222zm.222 3H1.053a7 7 0 0 0 0 2h2.222zm.582 1h2.835a8 8 0 0 0 .47-1H4.09zm3.41 0h1c.67-.204 1.335-.82 1.887-1.855A8 8 0 0 0 10.855 12H7.5zm3.41 0a9.2 9.2 0 0 1-.64 1.539 6.7 6.7 0 0 1-.597.933A7.03 7.03 0 0 0 13.745 12zM12 11h2.222a7 7 0 0 0 0-2H12zm2.222-3a7 7 0 0 0 0-2H12zM12 5h2.222a7 7 0 0 0 0-2H12zm-1.145-1A8 8 0 0 0 10.855 3c-.552-1.035-1.217-1.651-1.887-1.855V4zM8.5 4h2.355a9.2 9.2 0 0 0-.46-1c-.538-1.01-1.2-1.613-1.895-1.815V4zM7.5 5v2H4.02a10 10 0 0 0 .08 2H7.5v2h2.46c-.05.67-.19 1.32-.42 1.93L7.5 11V5z"/></svg>',
        chevronDown: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708"/></svg>'
      };

      // --- スタイル定義 (CSS変数によるダークモード完全対応) ---
      const style = document.createElement('style');
      style.textContent = `

        /* === Shadow DOM host reset (upstream email CSS isolation) === */
        /* テキストメールで body に padding があってもバー周囲に隙間が出ないよう
           マージン・パディングは常に 0。幅はホスト側インラインで body padding を相殺する。 */
        :host {
          all: initial;
          display: block;
          margin: 0 !important;
          padding: 0 !important;
          border: 0 !important;
          color-scheme: light dark;
        }
        *, *::before, *::after { box-sizing: border-box; }

        /* === Design tokens (DESIGN.md Apple system + security semantics) === */
        .maiv-container {
          /* surfaces */
          --maiv-bg: #f5f5f7;                 /* canvas-parchment */
          --maiv-bg-elevated: #ffffff;        /* canvas */
          --maiv-border: #e0e0e0;             /* hairline */
          --maiv-border-subtle: #f0f0f0;      /* divider-soft */
          /* text */
          --maiv-text: #1d1d1f;               /* ink / body */
          --maiv-text-secondary: #333333;     /* ink-muted-80 */
          --maiv-text-muted: #7a7a7a;         /* ink-muted-48 */
          --maiv-text-faint: #7a7a7a;
          --maiv-text-strong: #1d1d1f;
          --maiv-text-strongest: #1d1d1f;
          /* interactive: single Action Blue */
          --maiv-primary: #0066cc;
          --maiv-primary-focus: #0071e3;
          --maiv-primary-on-dark: #2997ff;
          --maiv-on-primary: #ffffff;
          /* cards */
          --maiv-card-bg: #ffffff;
          --maiv-card-border: #e0e0e0;
          --maiv-card-title-color: #7a7a7a;
          --maiv-card-title-border: #f0f0f0;
          --maiv-highlight-bg: #fafafc;       /* surface-pearl */
          --maiv-highlight-border: #e0e0e0;
          --maiv-route-border: #f0f0f0;
          --maiv-route-origin-bg: #f5f5f7;
          --maiv-shadow: transparent;         /* chrome に影なし */
          /* security semantics (domain-specific; not brand accents) */
          --maiv-pass: #248a3d;
          --maiv-fail: #d70015;
          --maiv-none: #7a7a7a;
          --maiv-delay-normal: #7a7a7a;
          --maiv-delay-warning: #b25000;
          --maiv-delay-danger: #d70015;
          --maiv-align-ok-text: #248a3d;
          --maiv-align-warn-bg: #fff8ef;
          --maiv-align-warn-text: #b25000;
          --maiv-align-ng-bg: #fff2f2;
          --maiv-align-ng-text: #d70015;
          --maiv-policy-reject-bg: #eef5ff;
          --maiv-policy-reject-text: #0066cc;
          --maiv-policy-quarantine-bg: #fff8ef;
          --maiv-policy-quarantine-text: #b25000;
          --maiv-policy-none-bg: #fff2f2;
          --maiv-policy-none-text: #d70015;
          --maiv-mismatch-color: #b25000;
          --maiv-mailing-list-bg: #eef5ff;
          --maiv-mailing-list-text: #0066cc;
          --maiv-untrusted-bg: #fff8ef;
          --maiv-untrusted-text: #b25000;
          --maiv-privacy-bg: #f5f5f7;
          --maiv-privacy-text: #333333;
          --maiv-accent-secure: #248a3d;
          --maiv-accent-warning: #c93400;
          --maiv-accent-danger: #d70015;
          --maiv-accent-phishing: #d70015;
          --maiv-accent: var(--maiv-accent-warning);
          --maiv-mini-pass-bg: #eaf6ed;
          --maiv-mini-pass-border: #a8d5b5;
          --maiv-mini-fail-bg: #fff2f2;
          --maiv-mini-fail-border: #f5b5b8;
          --maiv-mini-soft-bg: #fff8ef;
          --maiv-mini-soft-border: #f0c9a0;

          /* typography: SF Pro Display & Text stacks (DESIGN.md) */
          --maiv-font-sans: "SF Pro Text", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          --maiv-font-display: "SF Pro Display", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          --maiv-font-mono: ui-monospace, "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;

          /* Typography Profiles from DESIGN.md */
          --maiv-fs-domain: 14px;
          --maiv-lh-domain: 1.29;
          --maiv-ls-domain: -0.224px;

          --maiv-fs-body: 17px;
          --maiv-lh-body: 1.47;
          --maiv-ls-body: -0.374px;

          --maiv-fs-body-strong: 17px;
          --maiv-lh-body-strong: 1.24;
          --maiv-ls-body-strong: -0.374px;

          --maiv-fs-tagline: 21px;
          --maiv-lh-tagline: 1.19;
          --maiv-ls-tagline: 0.231px;

          --maiv-fs-caption: 14px;
          --maiv-lh-caption: 1.43;
          --maiv-ls-caption: -0.224px;

          --maiv-fs-caption-strong: 14px;
          --maiv-lh-caption-strong: 1.29;
          --maiv-ls-caption-strong: -0.224px;

          --maiv-fs-btn-ut: 14px;
          --maiv-lh-btn-ut: 1.29;
          --maiv-ls-btn-ut: -0.224px;

          --maiv-fs-fine: 12px;
          --maiv-lh-fine: 1.0;
          --maiv-ls-fine: -0.12px;

          /* Spacing Scale (DESIGN.md) */
          --maiv-space-xxs: 4px;
          --maiv-space-xs: 8px;
          --maiv-space-sm: 12px;
          --maiv-space-md: 17px;
          --maiv-space-lg: 24px;
          --maiv-space-xl: 32px;
          --maiv-space-xxl: 48px;

          /* Border Radius Scale (DESIGN.md) */
          --maiv-radius-none: 0px;
          --maiv-radius-xs: 5px;
          --maiv-radius-sm: 8px;
          --maiv-radius-md: 11px;
          --maiv-radius-lg: 18px;
          --maiv-radius-pill: 9999px;
          --maiv-radius: var(--maiv-radius-sm);

          --maiv-bar-pad-y: 3px;
          --maiv-bar-pad-x: var(--maiv-space-xs);
          --maiv-gap: 6px;
        }

        @media (prefers-color-scheme: dark) {
          .maiv-container {
            --maiv-bg: #272729;              /* surface-tile-1 */
            --maiv-bg-elevated: #2a2a2c;     /* surface-tile-2 */
            --maiv-border: #3a3a3c;
            --maiv-border-subtle: #333335;
            --maiv-text: #ffffff;
            --maiv-text-secondary: #cccccc;  /* body-muted */
            --maiv-text-muted: #a1a1a6;
            --maiv-text-faint: #86868b;
            --maiv-text-strong: #ffffff;
            --maiv-text-strongest: #ffffff;
            --maiv-primary: #2997ff;         /* primary-on-dark */
            --maiv-primary-focus: #2997ff;
            --maiv-card-bg: #2a2a2c;
            --maiv-card-border: #3a3a3c;
            --maiv-card-title-color: #a1a1a6;
            --maiv-card-title-border: #333335;
            --maiv-highlight-bg: #252527;
            --maiv-highlight-border: #3a3a3c;
            --maiv-route-border: #333335;
            --maiv-route-origin-bg: #252527;
            --maiv-pass: #30d158;
            --maiv-fail: #ff453a;
            --maiv-none: #a1a1a6;
            --maiv-delay-normal: #a1a1a6;
            --maiv-delay-warning: #ff9f0a;
            --maiv-delay-danger: #ff453a;
            --maiv-align-ok-text: #30d158;
            --maiv-align-warn-bg: #3a2a12;
            --maiv-align-warn-text: #ffd60a;
            --maiv-align-ng-bg: #3a1515;
            --maiv-align-ng-text: #ff6961;
            --maiv-policy-reject-bg: #0a2540;
            --maiv-policy-reject-text: #2997ff;
            --maiv-policy-quarantine-bg: #3a2a12;
            --maiv-policy-quarantine-text: #ffd60a;
            --maiv-policy-none-bg: #3a1515;
            --maiv-policy-none-text: #ff6961;
            --maiv-mismatch-color: #ff9f0a;
            --maiv-mailing-list-bg: #0a2540;
            --maiv-mailing-list-text: #2997ff;
            --maiv-untrusted-bg: #3a2a12;
            --maiv-untrusted-text: #ffd60a;
            --maiv-privacy-bg: #252527;
            --maiv-privacy-text: #cccccc;
            --maiv-accent-secure: #30d158;
            --maiv-accent-warning: #ff9f0a;
            --maiv-accent-danger: #ff453a;
            --maiv-accent-phishing: #ff453a;
            --maiv-mini-pass-bg: #0f2a18;
            --maiv-mini-pass-border: #1f6b3a;
            --maiv-mini-fail-bg: #3a1515;
            --maiv-mini-fail-border: #7a2a28;
            --maiv-mini-soft-bg: #3a2a12;
            --maiv-mini-soft-border: #7a5a1e;
          }
          .maiv-badge.phishing {
            background-color: #1a0000;
            color: #ff453a;
            border-color: #ff453a;
          }
          @keyframes maiv-phishing-pulse {
            0%, 100% { background-color: #1a0000; color: #ff453a; }
            50% { background-color: #ff453a; color: #1a0000; }
          }
        }

        .maiv-container.maiv-sev-secure { --maiv-accent: var(--maiv-accent-secure); }
        .maiv-container.maiv-sev-warning { --maiv-accent: var(--maiv-accent-warning); }
        .maiv-container.maiv-sev-danger { --maiv-accent: var(--maiv-accent-danger); }
        .maiv-container.maiv-sev-phishing { --maiv-accent: var(--maiv-accent-phishing); }

        /* === Shell (floating-sticky-bar / parchment bar feel) === */
        .maiv-container {
          font-family: var(--maiv-font-sans);
          background: var(--maiv-bg);
          color: var(--maiv-text);
          font-size: var(--maiv-fs-caption);
          font-weight: 400;
          line-height: var(--maiv-lh-caption);
          letter-spacing: var(--maiv-ls-caption);
          border-bottom: 1px solid var(--maiv-border);
          border-left: 3px solid var(--maiv-accent);
          padding: var(--maiv-bar-pad-y) var(--maiv-bar-pad-x);
          margin: 0;
          box-shadow: none;                  /* chrome に影なし */
        }

        /* === Header bar (always visible) === */
        .maiv-header {
          display: flex;
          align-items: center;
          flex-wrap: nowrap;
          gap: var(--maiv-gap);
          cursor: pointer;
          user-select: none;
          min-height: 26px;
          padding: 0;
          overflow: hidden;
        }
        .maiv-header:hover { opacity: 0.92; }

        /* 判定バッジ: アイコンのみ（全文は title） */
        .maiv-badge {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 22px;
          height: 22px;
          padding: 0;
          border-radius: var(--maiv-radius-xs);
          color: #fff;
          font-family: var(--maiv-font-display);
          line-height: 1;
          flex-shrink: 0;
          cursor: help;
        }
        .maiv-badge svg {
          display: inline-block;
          vertical-align: middle;
          width: 13px;
          height: 13px;
          fill: currentColor;
          flex-shrink: 0;
        }
        .maiv-badge.secure { background: var(--maiv-accent-secure); }
        .maiv-badge.warning { background: var(--maiv-accent-warning); color: #fff; }
        .maiv-badge.danger,
        .maiv-badge.phishing {
          background: var(--maiv-accent-danger);
          color: #fff;
        }

        /* ドメイン名は SF Pro Display で Apple Tight を再現 (13.5px) */
        .maiv-header-domain {
          font-size: 13.5px;
          font-weight: 600;
          color: var(--maiv-text-strong);
          font-family: var(--maiv-font-display);
          letter-spacing: -0.25px;
          line-height: 1.2;
          min-width: 0;
          max-width: 38ch;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          flex-shrink: 1;
        }

        /* Mini SPF / DKIM / DMARC indicators */
        .maiv-auth-minis {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          flex-shrink: 0;
        }
        /* ラベル省略なし: SPF / DKIM / DMARC + ステータスアイコン */
        .maiv-auth-mini {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 3px;
          height: 20px;
          min-width: 0;
          padding: 0 6px;
          border-radius: var(--maiv-radius-pill);
          font-family: var(--maiv-font-sans);
          font-size: 10.5px;
          font-weight: 600;
          letter-spacing: 0.02em;
          line-height: 1;
          border: 1px solid transparent;
          cursor: help;
          white-space: nowrap;
          transition: background-color 0.15s ease, border-color 0.15s ease;
        }
        .maiv-auth-mini-icon {
          font-size: 11px;
          line-height: 1;
          flex-shrink: 0;
          display: inline-flex;
          align-items: center;
        }
        .maiv-auth-mini-icon svg {
          width: 11px;
          height: 11px;
        }
        .maiv-auth-mini-label {
          font-family: var(--maiv-font-mono);
          font-size: 10.5px;
          letter-spacing: 0.02em;
        }
        .maiv-auth-mini.pass {
          color: var(--maiv-pass);
          background: var(--maiv-mini-pass-bg);
          border-color: var(--maiv-mini-pass-border);
        }
        .maiv-auth-mini.fail {
          color: var(--maiv-fail);
          background: var(--maiv-mini-fail-bg);
          border-color: var(--maiv-mini-fail-border);
        }
        .maiv-auth-mini.soft {
          color: var(--maiv-delay-warning);
          background: var(--maiv-mini-soft-bg);
          border-color: var(--maiv-mini-soft-border);
        }
        .maiv-auth-mini.none {
          color: var(--maiv-text-faint);
          background: transparent;
          border-color: var(--maiv-border);
        }

        /* ヘッダ用アイコンチップ（ML / 理由件数 / 報告値） */
        .maiv-chip {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 2px;
          height: 20px;
          min-width: 20px;
          padding: 0 6px;
          border-radius: var(--maiv-radius-pill);
          font-family: var(--maiv-font-sans);
          font-size: 10.5px;
          font-weight: 600;
          line-height: 1;
          letter-spacing: 0.02em;
          flex-shrink: 0;
          cursor: help;
          white-space: nowrap;
        }
        .maiv-chip-ml {
          background: var(--maiv-mailing-list-bg);
          color: var(--maiv-mailing-list-text);
        }
        .maiv-chip-issue {
          background: var(--maiv-align-warn-bg);
          color: var(--maiv-align-warn-text);
        }
        .maiv-chip-issue.danger {
          background: var(--maiv-align-ng-bg);
          color: var(--maiv-align-ng-text);
        }
        .maiv-chip-issue .maiv-chip-count {
          font-family: var(--maiv-font-mono);
          font-size: inherit;
        }
        .maiv-chip-info {
          background: var(--maiv-privacy-bg);
          color: var(--maiv-privacy-text);
        }

        .maiv-spacer { flex-grow: 1; min-width: 4px; }

        /* utility icon buttons — rounded.xs, hairline, Action Blue focus */
        .maiv-copy-btn,
        .maiv-toggle-icon {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 22px;
          height: 22px;
          min-width: 22px;
          min-height: 22px;
          margin: 0;
          padding: 0;
          font-size: 11px;
          line-height: 1;
          flex-shrink: 0;
          border-radius: var(--maiv-radius-xs);
          background: var(--maiv-highlight-bg);
          border: 1px solid var(--maiv-border);
          color: var(--maiv-text);
          cursor: pointer;
          box-sizing: border-box;
          transition: transform 0.1s ease, background 0.15s, border-color 0.15s, color 0.15s;
        }
        .maiv-copy-btn svg,
        .maiv-toggle-icon svg {
          width: 12px;
          height: 12px;
        }
        .maiv-copy-btn:hover,
        .maiv-toggle-icon:hover {
          background: var(--maiv-bg-elevated);
          color: var(--maiv-primary);
          border-color: var(--maiv-primary);
        }
        .maiv-copy-btn:active,
        .maiv-toggle-icon:active { transform: scale(0.92); }
        .maiv-copy-btn:focus-visible,
        .maiv-toggle-icon:focus-visible {
          outline: 2px solid var(--maiv-primary-focus);
          outline-offset: 1px;
        }
        .maiv-toggle-icon {
          transition: transform 0.25s ease, background 0.15s, border-color 0.15s, color 0.15s;
        }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }
        .maiv-toggle-icon.expanded:active { transform: rotate(180deg) scale(0.92); }

        /* Compact: 余白のみ圧縮（フォント比率は維持） */
        .maiv-container.maiv-compact {
          --maiv-bar-pad-y: 1px;
          --maiv-bar-pad-x: 5px;
          margin: 0;
        }
        .maiv-container.maiv-compact .maiv-header { min-height: 22px; gap: 4px; }
        .maiv-container.maiv-compact .maiv-badge {
          width: 18px;
          height: 18px;
          border-radius: 4px;
        }
        .maiv-container.maiv-compact .maiv-badge svg {
          width: 11px;
          height: 11px;
        }
        .maiv-container.maiv-compact .maiv-header-domain {
          font-size: 12.5px;
        }
        .maiv-container.maiv-compact .maiv-auth-mini,
        .maiv-container.maiv-compact .maiv-chip {
          height: 18px;
          min-width: 18px;
          padding: 0 5px;
          font-size: 9.5px;
        }
        .maiv-container.maiv-compact .maiv-auth-mini-icon svg {
          width: 9.5px;
          height: 9.5px;
        }
        .maiv-container.maiv-compact .maiv-copy-btn,
        .maiv-container.maiv-compact .maiv-toggle-icon {
          width: 18px;
          height: 18px;
          min-width: 18px;
          min-height: 18px;
        }
        .maiv-container.maiv-compact .maiv-copy-btn svg,
        .maiv-container.maiv-compact .maiv-toggle-icon svg {
          width: 10px;
          height: 10px;
        }

        /* === Expanded body === */
        .maiv-body-wrapper {
          max-height: 0;
          overflow: hidden;
          transition: max-height 0.28s ease-out;
        }
        .maiv-body-wrapper.expanded {
          max-height: 4000px;
          transition: max-height 0.45s ease-in;
        }
        .maiv-body-inner { padding-top: 6px; }
        .maiv-body-content { display: flex; flex-direction: column; gap: 6px; }

        /* 詳細パネルは 2 カラムで統一（均等幅ストレッチ） */
        .maiv-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 6px;
          align-items: stretch;
        }
        @media (max-width: 560px) {
          .maiv-grid { grid-template-columns: minmax(0, 1fr); }
        }

        .maiv-empty-state {
          color: var(--maiv-text-faint);
          font-size: var(--maiv-fs-fine);
          font-style: italic;
          padding: var(--maiv-space-xxs) 0;
          margin: 0;
        }

        /* ========== 全パネル共通シェル ========== */
        .maiv-card {
          display: flex;
          flex-direction: column;
          gap: 6px;
          background: var(--maiv-card-bg);
          border: 1px solid var(--maiv-card-border);
          border-radius: var(--maiv-radius-sm);
          padding: 8px 10px;
          min-width: 0;
          height: 100%;
          font-size: var(--maiv-fs-caption);
          font-weight: 400;
          line-height: var(--maiv-lh-caption);
          letter-spacing: var(--maiv-ls-caption);
          box-shadow: none;
          transition: border-color 0.15s ease;
        }
        .maiv-card:hover {
          border-color: rgba(0, 0, 0, 0.16);
        }
        @media (prefers-color-scheme: dark) {
          .maiv-card:hover {
            border-color: rgba(255, 255, 255, 0.22);
          }
        }
        .maiv-card-title {
          flex-shrink: 0;
          margin: 0;
          padding: 0 0 3px 0;
          font-family: var(--maiv-font-display);
          font-size: var(--maiv-fs-fine);
          font-weight: 600;
          color: var(--maiv-card-title-color);
          text-transform: uppercase;
          letter-spacing: var(--maiv-ls-fine);
          line-height: var(--maiv-lh-fine);
          border-bottom: 1px solid var(--maiv-card-title-border);
        }
        .maiv-card-title.maiv-collapsible {
          cursor: pointer;
          user-select: none;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .maiv-card-title.maiv-collapsible:hover { color: var(--maiv-primary); }
        .maiv-card-title.maiv-collapsible::before {
          content: "";
          width: 5px;
          height: 5px;
          border-right: 1.5px solid currentColor;
          border-bottom: 1.5px solid currentColor;
          transform: rotate(-45deg);
          display: inline-block;
          flex-shrink: 0;
          margin-right: 3px;
          transition: transform 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
        }
        .maiv-card-title.maiv-collapsible.maiv-expanded::before {
          transform: rotate(45deg);
        }
        .maiv-collapsible-body {
          max-height: 0;
          overflow: hidden;
          transition: max-height 0.28s ease;
        }
        .maiv-collapsible-body.maiv-expanded { max-height: 2400px; }

        /* カード本文の縦リズム: 直下要素の独自マージンを無効化 */
        .maiv-card > * { margin-top: 0; margin-bottom: 0; }
        .maiv-auth-card { min-height: 0; }

        /* ステータス行（SPF/DKIM/DMARC 共通） */
        .maiv-status-row {
          display: flex;
          align-items: center;
          flex-wrap: wrap;
          gap: 4px var(--maiv-space-xxs);
          font-size: var(--maiv-fs-caption);
          font-weight: 600;
        }
        .maiv-status-icon { font-size: var(--maiv-fs-caption); line-height: 1; }
        .maiv-authserv {
          color: var(--maiv-text-faint);
          font-size: var(--maiv-fs-fine);
          font-family: var(--maiv-font-mono);
          font-weight: 400;
          letter-spacing: var(--maiv-ls-fine);
          line-height: var(--maiv-lh-fine);
        }
        .status-pass, .status-fail, .status-none { font-weight: 600; color: var(--maiv-text); }
        .maiv-status-icon.status-pass, .maiv-icon.status-pass { color: var(--maiv-pass) !important; }
        .maiv-status-icon.status-fail, .maiv-icon.status-fail { color: var(--maiv-fail) !important; }
        .maiv-status-icon.status-none, .maiv-icon.status-none { color: var(--maiv-none) !important; }

        /* 共通 kv 行（アドレス・詳細・プロパティ） */
        .maiv-kv-row,
        .address-row,
        .maiv-prop-row {
          display: flex;
          align-items: baseline;
          gap: var(--maiv-space-xs);
          min-width: 0;
        }
        .maiv-kv-key,
        .address-label,
        .maiv-prop-key {
          flex: 0 0 84px;
          width: 84px;
          color: var(--maiv-text-muted);
          font-size: var(--maiv-fs-fine);
          font-weight: 600;
          font-family: var(--maiv-font-sans);
          text-transform: uppercase;
          letter-spacing: var(--maiv-ls-fine);
          line-height: 1.35;
        }
        .maiv-kv-val,
        .address-highlight,
        .maiv-prop-val {
          flex: 1 1 auto;
          min-width: 0;
          font-size: var(--maiv-fs-caption);
          font-weight: 400;
          font-family: var(--maiv-font-mono);
          color: var(--maiv-text-strong);
          word-break: break-all;
          line-height: 1.35;
        }
        .address-highlight {
          background: var(--maiv-highlight-bg);
          padding: 2px 6px;
          border-radius: var(--maiv-radius-sm);
          border: 1px solid var(--maiv-highlight-border);
          direction: ltr;
          unicode-bidi: embed;
        }
        .maiv-prop-val { color: var(--maiv-text-secondary); }

        /* 詳細ブロック（認証カード本文） */
        .maiv-detail-text {
          display: flex;
          flex-direction: column;
          gap: 4px;
          font-size: var(--maiv-fs-caption);
          color: var(--maiv-text-muted);
          font-family: var(--maiv-font-mono);
        }
        .maiv-detail-stack {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .maiv-expanded-detail {
          display: flex;
          flex-direction: column;
          gap: var(--maiv-space-xxs);
          font-size: var(--maiv-fs-fine);
          color: var(--maiv-text-muted);
          padding-top: var(--maiv-space-xxs);
          border-top: 1px solid var(--maiv-card-title-border);
        }
        .maiv-align-item {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: var(--maiv-fs-fine);
          font-family: var(--maiv-font-sans);
        }
        .maiv-align-pass, .maiv-align-fail { font-weight: 600; color: var(--maiv-text); }
        .maiv-icon.maiv-align-pass { color: var(--maiv-pass) !important; }
        .maiv-icon.maiv-align-fail { color: var(--maiv-fail) !important; }
        .maiv-sig-heading {
          font-weight: 600;
          font-size: var(--maiv-fs-fine);
          font-family: var(--maiv-font-mono);
          color: var(--maiv-text-strong);
          margin: 0;
        }
        .maiv-sig-sep {
          border-top: 1px solid var(--maiv-card-title-border);
          margin: 0;
        }
        .maiv-policy-tag {
          display: inline-flex;
          align-items: center;
          font-size: var(--maiv-fs-fine);
          font-weight: 600;
          padding: 2px 8px;
          border-radius: var(--maiv-radius-pill);
          font-family: var(--maiv-font-mono);
          width: fit-content;
        }
        .maiv-policy-reject { background: var(--maiv-policy-reject-bg); color: var(--maiv-policy-reject-text); }
        .maiv-policy-quarantine { background: var(--maiv-policy-quarantine-bg); color: var(--maiv-policy-quarantine-text); }
        .maiv-policy-none { background: var(--maiv-policy-none-bg); color: var(--maiv-policy-none-text); }
        .maiv-icon {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          line-height: 1;
          flex-shrink: 0;
          vertical-align: middle;
        }
        /* アイコン類に明示的な color を強制し、外部からの白/黒等の予期しない color 継承を防ぐ */
        .maiv-copy-btn,
        .maiv-toggle-icon {
          color: var(--maiv-text-secondary) !important;
        }
        .maiv-copy-btn:hover,
        .maiv-toggle-icon:hover {
          color: var(--maiv-primary) !important;
        }
        .maiv-tls-secure {
          color: var(--maiv-pass) !important;
        }
        .maiv-tls-warn {
          color: var(--maiv-delay-warning) !important;
        }
        .maiv-tls-danger {
          color: var(--maiv-fail) !important;
        }
        .maiv-ip-tag {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          color: var(--maiv-text-muted) !important;
          vertical-align: middle;
        }
        .maiv-delay-origin {
          color: var(--maiv-primary) !important;
        }

        .maiv-icon svg,
        .maiv-status-icon svg,
        .maiv-auth-mini-icon svg,
        .maiv-tls-tag svg,
        .maiv-copy-btn svg,
        .maiv-toggle-icon svg {
          display: inline-block;
          vertical-align: middle;
          width: 1em;
          height: 1em;
          fill: currentColor;
        }

        .maiv-strength-warn {
          display: flex;
          align-items: center;
          gap: 6px;
          color: var(--maiv-delay-warning);
          font-size: var(--maiv-fs-fine);
          font-family: var(--maiv-font-sans);
          margin: 0;
        }

        /* 共通コールアウト（align / findings） */
        .align-ok,
        .align-ng,
        .align-warn,
        .align-info,
        .maiv-finding-critical,
        .maiv-finding-suspicious,
        .maiv-finding-untrusted,
        .maiv-finding-privacy {
          display: flex;
          align-items: center;
          gap: 6px;
          margin: 0;
          padding: 4px 8px;
          border-radius: var(--maiv-radius-sm);
          font-size: var(--maiv-fs-caption);
          font-weight: 600;
          line-height: 1.35;
          border-left: 3px solid currentColor;
        }
        .align-ok {
          color: var(--maiv-align-ok-text);
          background: var(--maiv-mini-pass-bg);
        }
        .align-ng,
        .maiv-finding-critical {
          background: var(--maiv-align-ng-bg);
          color: var(--maiv-align-ng-text);
        }
        .align-warn,
        .maiv-finding-suspicious {
          background: var(--maiv-align-warn-bg);
          color: var(--maiv-align-warn-text);
        }
        .align-info,
        .maiv-finding-privacy {
          background: var(--maiv-privacy-bg);
          color: var(--maiv-privacy-text);
          font-weight: 400;
        }
        .maiv-finding-untrusted {
          background: var(--maiv-untrusted-bg);
          color: var(--maiv-untrusted-text);
          display: flex;
          align-items: center;
          flex-wrap: wrap;
          gap: 6px;
        }

        /* 共通テーブル（route / ARC） */
        .maiv-route-table,
        .maiv-arc-table {
          width: 100%;
          border-collapse: collapse;
          font-size: var(--maiv-fs-caption);
          margin: 0;
        }
        .maiv-route-table td,
        .maiv-arc-table td {
          padding: 2px var(--maiv-space-xxs);
          border-bottom: 1px solid var(--maiv-route-border);
          vertical-align: middle;
          line-height: 1.35;
        }
        .maiv-route-table tr:last-child td,
        .maiv-arc-table tr:last-child td { border-bottom: none; }
        .maiv-route-origin {
          background: var(--maiv-route-origin-bg);
          font-weight: 600;
          color: var(--maiv-text-strongest);
          border-left: 3px solid var(--maiv-primary);
        }
        .maiv-route-hop { color: var(--maiv-text-secondary); }
        .maiv-route-by {
          color: var(--maiv-text-faint);
          font-weight: 400;
          font-family: var(--maiv-font-mono);
          font-size: var(--maiv-fs-fine);
        }
        .maiv-route-time,
        .maiv-route-delay,
        .maiv-tls-tag,
        .maiv-arc-summary {
          font-family: var(--maiv-font-mono);
          font-size: var(--maiv-fs-fine);
          color: var(--maiv-text-faint);
          white-space: nowrap;
        }
        .maiv-route-time { text-align: right; }
        .maiv-route-delay {
          width: 48px;
          text-align: right;
          font-weight: 600;
          color: inherit;
        }
        .maiv-route-tls { text-align: right; padding-left: 6px; }
        .maiv-delay-none { color: var(--maiv-text-faint); }
        .maiv-delay-origin { color: var(--maiv-text-strongest); }
        .maiv-delay-normal { color: var(--maiv-delay-normal); }
        .maiv-delay-warning { color: var(--maiv-delay-warning); }
        .maiv-delay-danger { color: var(--maiv-delay-danger); }
        .maiv-arc-chain-num {
          font-weight: 600;
          color: var(--maiv-text-strong);
          width: 36px;
          text-align: center;
          font-family: var(--maiv-font-mono);
          font-size: var(--maiv-fs-fine);
        }
        .maiv-arc-domain {
          color: var(--maiv-text-secondary);
          font-family: var(--maiv-font-mono);
          font-size: var(--maiv-fs-caption);
        }
        .maiv-ip-tag { font-size: var(--maiv-fs-fine); margin-left: 4px; }
        /* 受信サーバが検証していない DKIM 署名の注記（警告ではなく補足説明） */
        .maiv-dkim-unverified-note { color: var(--maiv-text-faint); font-size: var(--maiv-fs-fine); margin-top: 4px; }
        .maiv-tls-secure { color: var(--maiv-pass); }
        .maiv-tls-warn { color: var(--maiv-delay-warning); font-weight: 600; }
        .maiv-tls-danger { color: var(--maiv-fail); font-weight: 600; }
        .maiv-tls-unknown { color: var(--maiv-text-faint); }

        /* リンク安全性: リストも同一リズム */
        .maiv-findings-stack,
        .maiv-link-domain-list {
          display: flex;
          flex-direction: column;
          gap: 4px;
          margin: 0;
        }
        .maiv-link-domain-list { font-size: var(--maiv-fs-caption); }
        .maiv-link-domain-list-title {
          font-weight: 600;
          margin: 0;
          color: var(--maiv-card-title-color);
          font-size: var(--maiv-fs-fine);
          font-family: var(--maiv-font-sans);
          text-transform: uppercase;
          letter-spacing: var(--maiv-ls-fine);
        }
        .maiv-link-domain-item {
          display: flex;
          align-items: center;
          flex-wrap: wrap;
          gap: 6px;
          padding: 2px 0;
          font-family: var(--maiv-font-mono);
          font-size: var(--maiv-fs-caption);
          line-height: 1.35;
        }
        .maiv-link-domain-count { color: var(--maiv-text-faint); font-size: var(--maiv-fs-fine); }
        .maiv-link-domain-match,
        .maiv-link-domain-mismatch,
        .maiv-link-domain-trusted {
          color: var(--maiv-text);
        }
        .maiv-link-domain-danger {
          color: var(--maiv-text);
          font-weight: 600;
        }
        .maiv-icon.maiv-link-domain-match { color: var(--maiv-pass) !important; }
        .maiv-icon.maiv-link-domain-mismatch { color: var(--maiv-align-warn-text) !important; }
        .maiv-icon.maiv-link-domain-trusted { color: var(--maiv-primary) !important; }
        .maiv-icon.maiv-link-domain-danger { color: var(--maiv-fail) !important; }

        .maiv-trust-btn {
          font-size: var(--maiv-fs-fine);
          padding: 6px 12px;
          margin-left: 6px;
          border: 1px solid var(--maiv-primary);
          border-radius: var(--maiv-radius-pill);
          background: transparent;
          color: var(--maiv-primary);
          cursor: pointer;
          font-weight: 400;
          vertical-align: middle;
          transition: transform 0.1s ease, background 0.15s;
        }
        .maiv-trust-btn:hover { background: var(--maiv-mailing-list-bg); }
        .maiv-trust-btn:active { transform: scale(0.95); }
        .maiv-trust-btn:disabled { opacity: 0.5; cursor: default; }

        .maiv-confirm-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.5);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .maiv-confirm-box {
          background: var(--maiv-card-bg);
          border: 1px solid var(--maiv-card-border);
          border-radius: var(--maiv-radius-md);
          padding: 24px;
          max-width: 380px;
          width: 90%;
          box-shadow: 0 12px 36px rgba(0, 0, 0, 0.22);
        }
        .maiv-confirm-text {
          font-size: var(--maiv-fs-caption);
          color: var(--maiv-text-strongest);
          margin-bottom: 16px;
          line-height: 1.47;
        }
        .maiv-confirm-domain { font-weight: 600; color: var(--maiv-primary); }
        .maiv-confirm-buttons { display: flex; gap: 8px; justify-content: flex-end; }
        .maiv-confirm-buttons button {
          padding: 8px 16px;
          border-radius: var(--maiv-radius-pill);
          font-size: var(--maiv-fs-caption);
          cursor: pointer;
          border: 1px solid var(--maiv-card-border);
          transition: transform 0.1s ease;
        }
        .maiv-confirm-buttons button:active { transform: scale(0.95); }
        .maiv-confirm-cancel {
          background: transparent;
          color: var(--maiv-primary);
          border-color: var(--maiv-primary);
        }
        .maiv-confirm-ok {
          background: var(--maiv-primary);
          color: var(--maiv-on-primary);
          border-color: var(--maiv-primary);
        }

      `;

      // --- レポートテキスト生成補助関数 ---
      // 画面に表示している解析結果を、チケットシステムやメールに貼り付けやすい
      // プレーンテキストレポートへ整形する。クリップボード経由で外部ツールに
      // 渡ることを想定し、記号は ASCII 主体（警告マークは [!]）とする。
      const generateReportText = () => {
        const lines = [];

        lines.push("=== Mail Auth Info Viewer Report ===");
        lines.push("");

        // 総合判定: バッジ文言と判定理由タグ
        lines.push(`VERDICT: ${security.badgeText}`);
        if (security.verdictReasons.length > 0) {
          lines.push(`Reasons: ${security.verdictReasons.join(", ")}`);
        }
        lines.push("");

        // 認証結果セクション
        lines.push("AUTHENTICATION RESULTS");
        lines.push("----------------------");
        const spfDomain = authResults.spf.detail.domain || "-";
        const spfIp = authResults.spf.detail.ip ? `, ip: ${authResults.spf.detail.ip}` : "";
        lines.push(`SPF:   ${authResults.spf.status.toUpperCase()} (domain: ${spfDomain}${spfIp})`);

        // DKIM: 複数署名がある場合は署名ごとに「ドメイン=結果 (s=セレクタ)」で列挙
        const sigs = authResults.dkim.signatures || [];
        const dkimSummary = sigs.length > 0
          ? sigs.map(sig => `${sig.domain || "?"}=${sig.status}${sig.selector ? ` (s=${sig.selector})` : ""}`).join(", ")
          : "-";
        lines.push(`DKIM:  ${authResults.dkim.status.toUpperCase()} (${dkimSummary})`);
        // 受信サーバが検証結果を記録していない署名（判定には算入しない）
        const unverifiedSigs = authResults.dkim.unverifiedSignatures || [];
        if (authResults.dkim.status === "none" && unverifiedSigs.length > 0) {
          const list = unverifiedSigs.map(sig => `${sig.domain || "?"}${sig.selector ? ` (s=${sig.selector})` : ""}`).join(", ");
          lines.push(`DKIM signature present, not verified by receiving server: ${list}`);
        }

        const dmarcPolicy = authResults.dmarc.detail.policy || "-";
        lines.push(`DMARC: ${authResults.dmarc.status.toUpperCase()} (policy: ${dmarcPolicy})`);
        if (authResults.authServId) {
          lines.push(`Authserv-Id: ${authResults.authServId}`);
        }
        // 信頼できないソース（authserv-id 不一致の標準 A-R / ARC-AR）からの報告値。
        // 判定には算入していない旨を明記して情報提供する。
        const ru = authResults.reportedUnverified;
        if (ru && ru.any) {
          const parts = [];
          if (ru.spf) parts.push(`SPF:${ru.spf}`);
          if (ru.dkim) parts.push(`DKIM:${ru.dkim}`);
          if (ru.dmarc) parts.push(`DMARC:${ru.dmarc}`);
          lines.push(`Reported (unverified, not counted): ${parts.join(" ")}`);
        }
        // 転送サービスが記録した元送信者の認証結果（DMARC pass でなければグリーンを阻害）
        const ro = authResults.relayOriginal;
        if (ro && ro.present) {
          const roDomain = ro.fromDomain ? ` (${ro.fromDomain})` : "";
          lines.push(`Original sender (reported by forwarding service, unverified): SPF:${ro.spf} DKIM:${ro.dkim} DMARC:${ro.dmarc}${roDomain}`);
        }
        if (authResults.m365Internal) {
          lines.push("Note: Microsoft 365 internal delivery (SPF/DKIM/DMARC not applied)");
        }
        lines.push("");

        // アライメントセクション
        lines.push("ALIGNMENT");
        lines.push("---------");
        const al = authResults.alignment || {};
        lines.push(`SPF aligned:  ${al.spfAligned ? "yes" : "no"}`);
        lines.push(`DKIM aligned: ${al.dkimAligned ? "yes" : "no"}`);
        lines.push("");

        // 認証強度の弱さ（検出時のみセクションを出力）
        const strength = authResults.strength || { dkim: [], dmarc: [] };
        if (strength.dkim.length > 0 || strength.dmarc.length > 0) {
          lines.push("STRENGTH WARNINGS");
          lines.push("-----------------");
          for (const w of strength.dkim) {
            lines.push(`[!] DKIM ${w.type}: ${w.value}${w.domain ? ` (${w.domain}${w.selector ? `, s=${w.selector}` : ""})` : ""}`);
          }
          for (const w of strength.dmarc) {
            lines.push(`[!] DMARC ${w.type}: ${w.value}`);
          }
          lines.push("");
        }

        // 送信者情報セクション
        lines.push("SENDER IDENTITY");
        lines.push("---------------");
        if (envelope.headerFromName) {
          lines.push(`Display Name:  ${envelope.headerFromName}`);
        }
        lines.push(`Header From:   ${envelope.headerFromAddress}`);
        lines.push(`Envelope From: ${envelope.envelopeFrom}`);
        if (envelope.isDisplayNameSpoofed) {
          lines.push("[!] Display name contains an email address from a different domain");
        }
        // 国際化ドメインは Unicode 表記と ASCII 表記（Punycode）を併記し、偽装の根拠も記す
        const reportHomograph = (info) => {
          const reasonText = { mixed: "mixed scripts", whole: "look-alike characters of another script only", latin: "look-alike Latin characters" };
          const parts = (info.reasons || []).map(r => reasonText[r] || r);
          if (info.lookalikeOf) parts.push(`resembles ${info.lookalikeOf}`);
          const chars = (info.chars || []).map(c => `${c.ch} ${c.code}${c.script ? " " + c.script : ""}`).join(", ");
          const name = info.isIdn ? `${info.unicode} (${info.ascii})` : info.ascii;
          return `${name}${parts.length ? " - " + parts.join("; ") : ""}${chars ? " [" + chars + "]" : ""}`;
        };
        const sh = envelope.senderHomograph;
        if (sh && sh.isHomograph) {
          lines.push(`[!] Look-alike sender domain: ${reportHomograph(sh)}`);
        } else if (sh && sh.isIdn) {
          lines.push(`IDN sender domain: ${sh.unicode} (${sh.ascii})`);
        }
        if (envelope.isReplyToMismatch) {
          lines.push(`[!] Reply-To differs from sender: ${envelope.replyToAddress}`);
        }
        if (envelope.replyToHomograph) {
          lines.push(`[!] Look-alike Reply-To domain: ${reportHomograph(envelope.replyToHomograph)}`);
        }
        lines.push("");

        // 送達経路セクション（hop 構造: {from, by, date, ip, isInternal, tls}）
        lines.push("DELIVERY ROUTE");
        lines.push("--------------");
        if (routeHops.length > 0) {
          for (let i = 0; i < routeHops.length; i++) {
            const hop = routeHops[i];
            const label = (i === 0) ? "ORIGIN" : `HOP ${i + 1}`;
            const host = hop.from || hop.by || "(unknown)";
            const ipInfo = hop.ip ? ` [${hop.ip}]` : "";
            lines.push(`${label}: ${host}${ipInfo}`);
            if (hop.by && hop.from) lines.push(`  by:   ${hop.by}`);
            if (hop.date) lines.push(`  time: ${hop.date.toISOString()}`);
            if (hop.tls) {
              if (hop.tls.version) {
                lines.push(`  tls:  ${hop.tls.version}${hop.tls.cipher ? ` (${hop.tls.cipher})` : ""}`);
              } else if (hop.tls.encrypted === true) {
                lines.push("  tls:  encrypted (version unknown)");
              } else if (hop.tls.encrypted === false) {
                lines.push("  tls:  not recorded (plaintext protocol)");
              }
            }
          }
        } else {
          lines.push("(no route information)");
        }
        lines.push("");

        // リンク安全性セクション（findings 構造: {level, type, detail, targetDomain?}）
        lines.push("LINK SAFETY");
        lines.push("-----------");
        const lsFindings = (linkSafety && linkSafety.findings) || [];
        if (lsFindings.length > 0) {
          for (const f of lsFindings) {
            const domainInfo = f.targetDomain ? ` -> ${f.targetDomain}` : "";
            lines.push(`[${f.level.toUpperCase()}] ${f.detail}${domainInfo}`);
          }
        } else {
          lines.push("(no link findings)");
        }
        lines.push("");

        // 生成日時（ISO 8601 — タイムゾーン差異による誤読を防ぐ）
        lines.push(`Generated: ${new Date().toISOString()}`);

        return lines.join("\n");
      };

      // --- クリップボード書き込みヘルパー ---
      // メッセージ表示ペインの文書は mailbox:// / imap:// 等の非セキュアコンテキストで
      // 表示されるため、セキュアコンテキスト限定の navigator.clipboard が存在しない。
      // 利用可能ならそちらを使い、不可なら一時 textarea + document.execCommand("copy") に
      // フォールバックする（クリックというユーザー操作起点のため execCommand が許可される）。
      const writeToClipboard = async (text) => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(text);
            return true;
          } catch { /* 権限拒否などの場合はフォールバックへ */ }
        }
        const helper = document.createElement("textarea");
        helper.value = text;
        // select() を効かせるため display:none は使わず、画面外へ不可視配置する
        helper.style.position = "fixed";
        helper.style.left = "-9999px";
        helper.style.top = "0";
        helper.setAttribute("readonly", "");
        document.body.appendChild(helper);
        helper.focus();
        helper.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch { ok = false; }
        helper.remove();
        return ok;
      };

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      // 深刻度クラスで左アクセント色を CSS 変数経由で制御する（判定ロジック自体は変更しない）
      const sevClass = ({
        secure: "maiv-sev-secure",
        warning: "maiv-sev-warning",
        danger: "maiv-sev-danger",
        phishing: "maiv-sev-phishing"
      })[security.badgeClass] || "maiv-sev-warning";
      container.className = `maiv-container ${sevClass}`;
      // コンパクト表示が有効なときは縮小用クラスを付与する。
      // 高さ圧縮は CSS 側（.maiv-container.maiv-compact）に集約しており、
      // ここではフラグに応じてクラスを足すだけに留める。
      if (compactMode) container.classList.add("maiv-compact");

      // --- ヘッダー（アイコン中心・1行コンパクト） ---
      // 長い文言は title に退避し、常時表示はアイコン + ドメイン + ミニ指標に限定する。
      // 判定ロジック・badgeText（レポート用）は変更しない。
      // 国際化ドメインは Unicode 表記に ASCII 表記（Punycode）を併記し、見た目だけで判断させない
      const senderInfo = envelope.senderHomograph;
      const headerDomainText = (senderInfo && senderInfo.isIdn)
        ? escapeHTML(`${senderInfo.unicode} (${senderInfo.ascii})`)
        : escapeHTML(envelope.headerFromDomain);

      // 判定バッジ: アイコンのみ。フルラベルは tooltip / aria-label
      const badgeIconMap = {
        secure: BI.checkCircleFill,
        warning: BI.exclamationTriangleFill,
        danger: BI.xCircleFill,
        phishing: BI.exclamationOctagonFill
      };
      const badgeIcon = badgeIconMap[security.badgeClass] || BI.exclamationTriangleFill;
      const badgeTitle = security.badgeText;

      // メーリングリスト: アイコンのみ
      const mailingListTag = envelope.isMailingList
        ? `<span class="maiv-chip maiv-chip-ml" title="${escapeHTML(msg("mailingListVia"))}"><span class="maiv-icon">${BI.envelopeFill}</span></span>`
        : "";

      // --- SPF / DKIM / DMARC ミニ指標（折りたたみ時も常時表示） ---
      const miniStatusClass = (status) => {
        const s = (status || "none").toLowerCase();
        if (s === "pass") return "pass";
        if (s === "fail" || s === "temperror" || s === "permerror") return "fail";
        if (s === "softfail" || s === "neutral" || s === "policy") return "soft";
        return "none";
      };
      // ラベルは省略せず SPF / DKIM / DMARC と表示し、ステータスに応じたアイコンを付与
      const miniStatusIcon = (status) => {
        const s = (status || "none").toLowerCase();
        if (s === "pass") return BI.checkCircleFill;
        if (s === "fail" || s === "temperror" || s === "permerror") return BI.xCircleFill;
        if (s === "softfail" || s === "neutral" || s === "policy") return BI.exclamationTriangleFill;
        return BI.dash; // none / 未判定
      };
      const renderAuthMini = (status, methodLabel) => {
        const st = (status || "none").toLowerCase();
        const cls = miniStatusClass(st);
        const icon = miniStatusIcon(st);
        const tip = `${methodLabel}: ${st}`;
        return `<span class="maiv-auth-mini ${cls}" title="${escapeHTML(tip)}" aria-label="${escapeHTML(tip)}">` +
          `<span class="maiv-auth-mini-icon" aria-hidden="true">${icon}</span>` +
          `<span class="maiv-auth-mini-label">${escapeHTML(methodLabel)}</span>` +
          `</span>`;
      };
      const authMinisHTML = `
        <span class="maiv-auth-minis" aria-label="SPF DKIM DMARC">
          ${renderAuthMini(authResults.spf.status, "SPF")}
          ${renderAuthMini(authResults.dkim.status, "DKIM")}
          ${renderAuthMini(authResults.dmarc.status, "DMARC")}
        </span>
      `;

      // --- 判定理由: 件数チップのみ（hover で全理由） ---
      let issueChipHTML = "";
      if (!security.isSecure && security.verdictReasons.length > 0) {
        const reasonLabelMap = {
          "spf_align_fail": msg("verdictReasonSpfAlign"),
          "dkim_align_fail": msg("verdictReasonDkimAlign"),
          "domain_not_aligned": msg("verdictReasonDomainMismatch"),
          "display_name_spoofed": msg("verdictReasonSpoofing"),
          "sender_homograph": msg("verdictReasonSenderHomograph"),
          "reply_to_homograph": msg("verdictReasonReplyToHomograph"),
          "relay_original_unverified": msg("verdictReasonRelayOriginal"),
          "dkim_replay_risk": msg("verdictReasonDkimReplayRisk"),
          "phishing_suspicious": msg("verdictReasonSuspicious"),
          "link_untrusted": msg("verdictReasonUntrusted")
        };
        const reasonLabelOf = (r) => (r.includes(":") ? r : (reasonLabelMap[r] || r));
        const labels = security.verdictReasons.map(reasonLabelOf);
        const tip = labels.join(" · ");
        const count = security.verdictReasons.length;
        const issueCls = (security.badgeClass === "danger" || security.badgeClass === "phishing")
          ? "maiv-chip maiv-chip-issue danger"
          : "maiv-chip maiv-chip-issue";
        const issueIcon = security.badgeClass === "phishing" ? BI.exclamationOctagonFill : BI.exclamationTriangleFill;
        issueChipHTML = `<span class="${issueCls}" title="${escapeHTML(tip)}"><span class="maiv-icon">${issueIcon}</span><span class="maiv-chip-count">${count}</span></span>`;
      }

      // --- 信頼できない報告値: アイコンのみ（詳細は tooltip） ---
      let reportedUnverifiedTag = "";
      const ru = authResults.reportedUnverified;
      if (ru && ru.any) {
        const parts = [];
        if (ru.spf) parts.push(`SPF:${ru.spf}`);
        if (ru.dkim) parts.push(`DKIM:${ru.dkim}`);
        if (ru.dmarc) parts.push(`DMARC:${ru.dmarc}`);
        const tip = `${msg("reportedUnverifiedNotice")}\n${parts.join(" ")}`;
        reportedUnverifiedTag =
          `<span class="maiv-chip maiv-chip-info" title="${escapeHTML(tip)}"><span class="maiv-icon">${BI.infoCircleFill}</span></span>`;
      }

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="${escapeHTML(msg("toggleDetails"))}"
             aria-expanded="${security.shouldAutoExpand}" aria-controls="maiv-body-wrapper">
          <span class="maiv-badge ${security.badgeClass}" title="${escapeHTML(badgeTitle)}"
                aria-label="${escapeHTML(badgeTitle)}">${badgeIcon}</span>
          <span class="maiv-header-domain" title="${headerDomainText}">${headerDomainText}</span>
          ${authMinisHTML}
          ${mailingListTag}
          ${issueChipHTML}
          ${reportedUnverifiedTag}
          <span class="maiv-spacer"></span>
          <button class="maiv-copy-btn" id="maiv-copy-btn" title="${escapeHTML(msg("copyButton"))}"
                  type="button" aria-label="${escapeHTML(msg("copyButton"))}">${BI.clipboard}</button>
          <button class="maiv-toggle-icon" id="maiv-toggle-icon" type="button"
                  title="${escapeHTML(msg("toggleDetails"))}"
                  aria-label="${escapeHTML(msg("toggleDetails"))}"
                  aria-controls="maiv-body-wrapper">${BI.chevronDown}</button>
        </div>
      `;

      // --- 認証カード生成ヘルパー ---
      const createAuthCard = (title, tooltip, data, detailHTML, expandedHTML, cardId) => {
        let icon = BI.dashCircleFill;
        let sClass = "status-none";
        const displayStatus = data.status.toUpperCase();

        if (data.status === "pass") { icon = BI.checkCircleFill; sClass = "status-pass"; }
        else if (data.status === "fail") { icon = BI.xCircleFill; sClass = "status-fail"; }
        else if (data.status === "softfail" || data.status === "neutral" || data.status === "none") { icon = BI.exclamationTriangleFill; sClass = "status-none"; }
        else if (data.status === "temperror" || data.status === "permerror") { icon = BI.xCircleFill; sClass = "status-fail"; }

        // authserv-id: ジャッジしたサーバのドメイン
        const authServLabel = authResults.authServId
          ? `<span class="maiv-authserv">(${escapeHTML(authResults.authServId)})</span>`
          : "";

        const hasExpanded = expandedHTML && expandedHTML.trim();
        return `
          <div class="maiv-card maiv-auth-card">
            <div class="maiv-card-title${hasExpanded ? ' maiv-collapsible' : ''}"${hasExpanded ? ` data-toggle="${cardId}"` : ''}
                 title="${escapeHTML(tooltip)}">${escapeHTML(title)}</div>
            <div class="maiv-detail-stack">
              <div class="maiv-status-row">
                <span class="maiv-status-icon ${sClass}">${icon}</span>
                <span class="${sClass}">${escapeHTML(displayStatus)}</span>
                ${authServLabel}
              </div>
              <div class="maiv-detail-text">${detailHTML}</div>
              ${hasExpanded ? `<div class="maiv-collapsible-body" id="${cardId}"><div class="maiv-expanded-detail">${expandedHTML}</div></div>` : ''}
            </div>
          </div>
        `;
      };

      // --- 構造化データからHTML詳細を生成 ---
      // 共通 kv 行
      const kvRow = (key, val) => {
        if (!val && val !== 0) return "";
        return `<div class="maiv-kv-row"><span class="maiv-kv-key">${escapeHTML(key)}</span><span class="maiv-kv-val">${escapeHTML(String(val))}</span></div>`;
      };

      // SPF カード詳細: ドメイン・IP・アライメント結果を表示
      const spfDetailHTML = (() => {
        const d = authResults.spf.detail;
        const al = authResults.alignment;
        const parts = [];
        if (d.domain) parts.push(kvRow(msg("labelDomain"), d.domain));
        if (d.ip) parts.push(kvRow(msg("labelIpAddress"), d.ip));
        // SPF アライメント: SPF が pass の場合のみ表示
        if (al && authResults.spf.status === "pass") {
          const icon = al.spfAligned ? BI.checkCircleFill : BI.xCircleFill;
          const cls = al.spfAligned ? "maiv-align-pass" : "maiv-align-fail";
          const label = al.spfAligned ? msg("alignedLabel") : msg("notAlignedLabel");
          parts.push(`<div class="maiv-align-item"><span class="maiv-icon ${cls}">${icon}</span><span class="${cls}">${escapeHTML(msg("labelSpfAlign"))} ${escapeHTML(label)}</span></div>`);
        }
        return parts.join("");
      })();

      // DKIM カード詳細: 集約ドメイン・個別署名結果・アライメントを表示
      const dkimDetailHTML = (() => {
        const sigs = authResults.dkim.signatures || [];
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
        const headerOrgDomain = envelope.headerOrgDomain;
        const authServLabel = authResults.authServId
          ? `<span class="maiv-authserv">(${escapeHTML(authResults.authServId)})</span>`
          : "";

        // 認証強度の弱さ警告（鍵長・アルゴリズム・署名範囲）。
        // 署名結果の有無に関わらず DKIM-Signature ヘッダから検出されるため、
        // 早期 return 経路を含むすべての表示パスの末尾に付加する
        const strengthTypeMsg = {
          "weak_key": msg("dkimWeakKeyLength"),
          "weak_algorithm": msg("dkimWeakAlgorithm"),
          "limited_scope": msg("dkimLimitedScope"),
          "unsigned_headers": msg("dkimUnsignedHeaders")
        };
        let strengthHTML = "";
        for (const w of (authResults.strength ? authResults.strength.dkim : [])) {
          const label = strengthTypeMsg[w.type] || w.type;
          // 署名単位の警告（署名対象ヘッダの不足）はセレクタも添え、どの署名についてか明示する
          const selectorInfo = w.selector ? `, s=${w.selector}` : "";
          const domainInfo = w.domain ? ` — ${w.domain}${selectorInfo}` : "";
          strengthHTML += `<div class="maiv-strength-warn"><span class="maiv-icon">${BI.exclamationTriangleFill}</span><span>${escapeHTML(label)} (${escapeHTML(w.value)}${escapeHTML(domainInfo)})</span></div>`;
        }

        if (sigs.length === 0 || !sigs.some(s => s.domain)) {
          const st = authResults.dkim.status;

          // DKIM-Signature はあるが受信サーバの検証結果が無い場合は、「署名なし」と区別して
          // 「署名あり（未検証）」と表示する。色は none と同じ中立表示に留め、判定は変えない。
          // 署名ドメインは送信者が偽造できる値のため、未検証であることを必ず併記する
          const unverified = authResults.dkim.unverifiedSignatures || [];
          if (st === "none" && unverified.length > 0) {
            const sigLines = unverified.map(sig => {
              const parts = [`${escapeHTML(msg("dkimSignedUnverifiedDomain"))} ${escapeHTML(sig.domain || "?")}`];
              if (sig.selector) parts.push(`${escapeHTML(msg("labelSelector"))} ${escapeHTML(sig.selector)}`);
              return parts.join("<br>");
            });
            // ラベルが pass/none より長く、狭いカードでは authserv-id と並べると
            // ラベル自体が細切れに折り返すため、ラベルは改行させず authserv-id 側を次行へ回す
            return `
              <div class="maiv-status-row" style="flex-wrap:wrap;">
                <span class="maiv-status-icon status-none"><span class="maiv-icon">${BI.exclamationTriangleFill}</span></span>
                <span class="status-none" style="white-space:nowrap;">${escapeHTML(msg("dkimSignedUnverified"))}</span>
                ${authServLabel}
              </div>
              <div class="maiv-detail-text">${sigLines.join('<div style="border-top:1px dashed var(--maiv-card-title-border); margin:6px 0;"></div>')}</div>
              <div class="maiv-dkim-unverified-note">${escapeHTML(msg("dkimSignedUnverifiedNote"))}</div>
              ${strengthHTML}
            `;
          }

          const emptyIcon = (st === "fail" || st === "permerror" || st === "temperror") ? BI.xCircleFill : BI.exclamationTriangleFill;
          const emptyCls = (st === "fail" || st === "permerror" || st === "temperror") ? "status-fail" : "status-none";
          return `
            <div class="maiv-status-row">
              <span class="maiv-status-icon">${emptyIcon}</span>
              <span class="${emptyCls}">${escapeHTML(st.toUpperCase())}</span>
              ${authServLabel}
            </div>
            ${strengthHTML}
          `;
        }

        let html = "";
        for (let i = 0; i < sigs.length; i++) {
          const sig = sigs[i];
          if (!sig.domain) continue;
          if (i > 0) html += `<div class="maiv-sig-sep"></div>`;

          const icon = sig.status === "pass" ? BI.checkCircleFill : (sig.status === "fail" ? BI.xCircleFill : BI.exclamationTriangleFill);
          const sClass = sig.status === "pass" ? "status-pass" : (sig.status === "fail" ? "status-fail" : "status-none");

          // ステータス行（SPFと同じ maiv-status-row）
          html += `<div class="maiv-status-row"><span class="maiv-status-icon ${sClass}">${icon}</span><span class="${sClass}">${escapeHTML(sig.status.toUpperCase())}</span>${authServLabel}</div>`;
          const parts = [];
          parts.push(kvRow(msg("labelDomain"), sig.domain));
          if (sig.selector) parts.push(kvRow(msg("labelSelector"), sig.selector));
          if (sig.status === "pass") {
            const sigOrgDomain = getOrgDomain(domainToAscii(sig.domain));
            const aligned = (sigOrgDomain === headerOrgDomain);
            const alIcon = aligned ? BI.checkCircleFill : BI.xCircleFill;
            const alCls = aligned ? "maiv-align-pass" : "maiv-align-fail";
            const alLabel = aligned ? msg("alignedLabel") : msg("notAlignedLabel");
            parts.push(`<div class="maiv-align-item"><span class="maiv-icon ${alCls}">${alIcon}</span><span class="${alCls}">${escapeHTML(msg("labelDkimAlign"))} ${escapeHTML(alLabel)}</span></div>`);
          }
          html += `<div class="maiv-detail-text">${parts.join("")}</div>`;
        }
        return html + strengthHTML;
      })();

      const dmarcDetailHTML = (() => {
        const d = authResults.dmarc.detail;
        const parts = [];
        if (d.domain) parts.push(kvRow(msg("labelDomain"), d.domain));
        if (d.policy) {
          let policyClass = "maiv-policy-none";
          if (d.policy === "reject") policyClass = "maiv-policy-reject";
          else if (d.policy === "quarantine") policyClass = "maiv-policy-quarantine";
          parts.push(`<div class="maiv-kv-row"><span class="maiv-kv-key">${escapeHTML(msg("labelPolicy"))}</span><span class="maiv-policy-tag ${policyClass}">${escapeHTML(d.policy)}</span></div>`);
        }
        const dmarcStrengthMsg = {
          "weak_sp": msg("dmarcWeakSubpolicy"),
          "limited_pct": msg("dmarcLimitedPct")
        };
        for (const w of (authResults.strength ? authResults.strength.dmarc : [])) {
          const label = dmarcStrengthMsg[w.type] || w.type;
          parts.push(`<div class="maiv-strength-warn"><span class="maiv-icon">${BI.exclamationTriangleFill}</span><span>${escapeHTML(label)} (${escapeHTML(w.value)})</span></div>`);
        }
        return parts.join("");
      })();

      // 認証カード
      // --- 展開時の全プロパティHTML生成 ---
      // Authentication-Results 生セグメントから全 key=value ペアを抽出して表示
      const renderPropRow = (key, val) => {
        if (!val && val !== 0) return "";
        return `<div class="maiv-kv-row maiv-prop-row"><span class="maiv-kv-key maiv-prop-key">${escapeHTML(key)}</span><span class="maiv-kv-val maiv-prop-val">${escapeHTML(String(val))}</span></div>`;
      };

      // 生セグメントから全プロパティを抽出するジェネリックパーサー
      // "spf=pass (reason text) smtp.mailfrom=x smtp.helo=y" → [{key, val}, ...]
      const parseSegmentProps = (segment) => {
        if (!segment) return [];
        const props = [];
        // 括弧内のテキストを reason として先に抽出
        const reasonMatch = segment.match(/\(([^)]+)\)/);
        if (reasonMatch) props.push({ key: "reason", val: reasonMatch[1] });
        // 括弧部分を除去してから key=value を抽出（括弧内の = による誤マッチを防止）
        const cleaned = segment.replace(/\([^)]*\)/g, '');
        // クォート値対応: key="value with = signs" or key=unquoted_value
        const propRegex = /([a-zA-Z][a-zA-Z0-9._-]*)="([^"]*)"|([a-zA-Z][a-zA-Z0-9._-]*)=([^;\s"]+)/g;
        let m;
        while ((m = propRegex.exec(cleaned)) !== null) {
          const key = m[1] || m[3];
          const val = m[2] !== undefined ? m[2] : m[4];
          if (/^(spf|dkim|dmarc|arc|bimi)$/i.test(key)) continue;
          props.push({ key, val });
        }
        return props;
      };

      // SPF 展開: 生セグメントから全プロパティ
      const spfExpandedHTML = (() => {
        const props = parseSegmentProps(authResults.spf.detail.rawSegment);
        return props.map(p => renderPropRow(p.key, p.val)).join("");
      })();

      // DKIM 展開: 各署名の生セグメントから全プロパティ（常にドメイン見出し付き）
      const dkimExpandedHTML = (() => {
        const sigs = authResults.dkim.signatures || [];
        if (sigs.length === 0 || !sigs.some(s => s.domain)) return "";
        let html = "";
        for (const sig of sigs) {
          html += `<div class="maiv-sig-heading">${escapeHTML(sig.domain || "unknown")} (${escapeHTML(sig.status)})</div>`;
          const props = parseSegmentProps(sig.segment);
          html += props.map(p => renderPropRow(p.key, p.val)).join("");
        }
        return html;
      })();

      // DMARC 展開: 括弧内のポリシーパラメータを個別抽出
      const dmarcExpandedHTML = (() => {
        const seg = authResults.dmarc.detail.rawSegment;
        if (!seg) return "";
        let html = "";
        // 括弧内からポリシーパラメータを個別抽出
        const parenMatch = seg.match(/\(([^)]+)\)/);
        if (parenMatch) {
          const inner = parenMatch[1];
          const pMatch = inner.match(/(?:^|[\s])p=([^\s)]+)/i);
          const spMatch = inner.match(/\bsp=([^\s)]+)/i);
          const disMatch = inner.match(/\bdis=([^\s)]+)/i);
          const pctMatch = inner.match(/\bpct=([^\s)]+)/i);
          if (pMatch) html += renderPropRow("p", pMatch[1]);
          if (spMatch) html += renderPropRow("sp", spMatch[1]);
          if (disMatch) html += renderPropRow("dis", disMatch[1]);
          if (pctMatch) html += renderPropRow("pct", pctMatch[1]);
        }
        // 括弧外の key=value（header.from 等）
        const cleaned = seg.replace(/\([^)]*\)/g, '');
        const propRegex = /([a-zA-Z][a-zA-Z0-9._-]*)="([^"]*)"|([a-zA-Z][a-zA-Z0-9._-]*)=([^;\s"]+)/g;
        let m;
        while ((m = propRegex.exec(cleaned)) !== null) {
          const key = m[1] || m[3];
          const val = m[2] !== undefined ? m[2] : m[4];
          if (/^(dmarc)$/i.test(key)) continue;
          html += renderPropRow(key, val);
        }
        return html;
      })();

      const spfCard = createAuthCard(msg("cardTitleSpf"), msg("tooltipSpf"), authResults.spf, spfDetailHTML, spfExpandedHTML, "maiv-spf-detail");

      // DKIM カード: 署名ごとにステータス・ドメイン・セレクタ・アライメントを表示（集約行なし）
      const dkimCard = (() => {
        const hasExpanded = dkimExpandedHTML && dkimExpandedHTML.trim();
        return `
          <div class="maiv-card maiv-auth-card">
            <div class="maiv-card-title${hasExpanded ? ' maiv-collapsible' : ''}"${hasExpanded ? ' data-toggle="maiv-dkim-detail"' : ''}
                 title="${escapeHTML(msg("tooltipDkim"))}">${escapeHTML(msg("cardTitleDkim"))}</div>
            <div class="maiv-detail-stack">
              ${dkimDetailHTML}
              ${hasExpanded ? `<div class="maiv-collapsible-body" id="maiv-dkim-detail"><div class="maiv-expanded-detail">${dkimExpandedHTML}</div></div>` : ''}
            </div>
          </div>
        `;
      })();

      const dmarcCard = createAuthCard(msg("cardTitleDmarc"), msg("tooltipDmarc"), authResults.dmarc, dmarcDetailHTML, dmarcExpandedHTML, "maiv-dmarc-detail");

      // --- アドレス＆アライメント表示 ---
      let alignmentWarningHTML = "";

      // ホモグラフ検査結果を「Unicode (ASCII) — 根拠 / 紛らわしい文字」の形で説明する
      const describeHomograph = (info) => {
        const reasonKey = { mixed: "homographReasonMixed", whole: "homographReasonWholeScript", latin: "homographReasonLatin" };
        const parts = (info.reasons || []).map(r => msg(reasonKey[r] || r));
        if (info.lookalikeOf) parts.push(`${msg("homographReasonResembles")} ${info.lookalikeOf}`);
        const chars = (info.chars || []).map(c => `"${c.ch}" ${c.code}${c.script ? " " + c.script : ""}`).join(", ");
        // ASCII 表記の併記は、Unicode 表記と異なる国際化ドメインの場合のみ
        return (info.isIdn ? `${info.unicode} (${info.ascii})` : info.ascii) +
          (parts.length ? " — " + parts.join(" / ") : "") +
          (chars ? ` [${chars}]` : "");
      };

      // 送信者ドメインのホモグラフ警告: 認証が通っていても送信者を誤認させる偽装のため、
      // 送信者情報カードの先頭で最も強い表示にする。紛らわしい兆候の無い国際化ドメインは
      // 表記の併記だけを情報として示す。
      if (senderInfo && senderInfo.isHomograph) {
        alignmentWarningHTML += `<div class="align-ng"><span class="maiv-icon">${BI.xCircleFill}</span><span>${escapeHTML(msg("senderHomographWarning"))}<br>${escapeHTML(describeHomograph(senderInfo))}</span></div>`;
      } else if (senderInfo && senderInfo.isIdn) {
        alignmentWarningHTML += `<div class="align-info"><span class="maiv-icon">${BI.infoCircleFill}</span><span>${escapeHTML(msg("idnDomainInfo"))}: ${escapeHTML(`${senderInfo.unicode} (${senderInfo.ascii})`)}</span></div>`;
      }

      // 表示名なりすまし警告: 表示名に別ドメインのアドレスが埋め込まれている場合
      if (envelope.isDisplayNameSpoofed) {
        alignmentWarningHTML += `<div class="align-ng"><span class="maiv-icon">${BI.xCircleFill}</span><span>${escapeHTML(msg("displayNameSpoofWarning"))}</span></div>`;
      }

      if (!envelope.isDomainAligned && envelope.envelopeFrom !== "Unknown") {
        if (envelope.isMailingList) {
          // メーリングリスト経由: 不一致の原因が転送である可能性を明示
          alignmentWarningHTML += `<div class="align-warn"><span class="maiv-icon">${BI.envelopeFill}</span><span>${escapeHTML(msg("mailingListNote"))}</span></div>`;
        } else if (security.isSpfOk || security.isDkimOk) {
          // 認証は通っている: DMARCアライメント成立時は情報提供レベル、非成立時は警告
          alignmentWarningHTML += `<div class="align-warn"><span class="maiv-icon">${BI.exclamationTriangleFill}</span><span>${escapeHTML(msg("alignMismatch"))}</span></div>`;
        } else {
          alignmentWarningHTML += `<div class="align-ng"><span class="maiv-icon">${BI.xCircleFill}</span><span>${escapeHTML(msg("alignMismatch"))}</span></div>`;
        }
      } else if (envelope.isDomainAligned && (security.isSpfOk || security.isDkimOk)) {
        // ドメイン一致かつ認証も通っている場合はグリーン表示
        // （p=none等で総合判定がグリーンでなくても、認証自体は成功している）
        alignmentWarningHTML += `<div class="align-ok"><span class="maiv-icon">${BI.checkCircleFill}</span><span>${escapeHTML(msg("alignOk"))}</span></div>`;
      } else if (envelope.isDomainAligned && !authResults.m365Internal) {
        // ドメインは一致しているが認証が通っていない
        alignmentWarningHTML += `<div class="align-warn"><span class="maiv-icon">${BI.exclamationTriangleFill}</span><span>${escapeHTML(msg("alignNotAuth"))}</span></div>`;
      }

      // Microsoft 365 組織内配送の注記: 組織外へ出ない配送には SPF/DKIM/DMARC が
      // そもそも適用されないため、「外部送信者を検証できなかった」とは区別して伝える。
      // バッジ・判定理由は変えない情報提供（組織内配送の信頼性を保証するものではない）。
      if (authResults.m365Internal) {
        alignmentWarningHTML += `<div class="align-info"><span class="maiv-icon">${BI.infoCircleFill}</span><span>${escapeHTML(msg("m365InternalNote"))}</span></div>`;
      }

      // 転送サービスが記録した元送信者の認証結果（未検証の報告値）
      const relayOriginal = authResults.relayOriginal;
      if (relayOriginal && relayOriginal.present) {
        const relayParts = `SPF:${relayOriginal.spf} DKIM:${relayOriginal.dkim} DMARC:${relayOriginal.dmarc}`;
        const relayDomain = relayOriginal.fromDomain ? ` (${relayOriginal.fromDomain})` : "";
        const relayCls = relayOriginal.dmarcPass ? "align-info" : "align-warn";
        const relayIcon = relayOriginal.dmarcPass ? BI.infoCircleFill : BI.exclamationTriangleFill;
        alignmentWarningHTML += `<div class="${relayCls}" title="${escapeHTML(msg("relayOriginalAuthNotice"))}">` +
          `<span class="maiv-icon">${relayIcon}</span><span>${escapeHTML(msg("relayOriginalAuthLabel"))}: ${escapeHTML(relayParts + relayDomain)}</span></div>`;
      }

      // Reply-To 不一致警告: フィッシングで返信先を攻撃者に誘導する手口の可能性
      if (envelope.isReplyToMismatch) {
        alignmentWarningHTML += `<div class="align-warn"><span class="maiv-icon">${BI.exclamationTriangleFill}</span><span>${escapeHTML(msg("replyToMismatch"))} (${escapeHTML(envelope.replyToAddress)})</span></div>`;
      }
      // Reply-To ドメインのホモグラフ警告: 返信先を偽装ドメインへ誘導する手口
      if (envelope.replyToHomograph) {
        alignmentWarningHTML += `<div class="align-ng"><span class="maiv-icon">${BI.xCircleFill}</span><span>${escapeHTML(msg("replyToHomographWarning"))} (${escapeHTML(envelope.replyToHomograph.address)})<br>${escapeHTML(describeHomograph(envelope.replyToHomograph))}</span></div>`;
      }

      const addressRow = (label, value) =>
        `<div class="maiv-kv-row address-row"><span class="maiv-kv-key address-label">${escapeHTML(label)}</span><span class="maiv-kv-val address-highlight">${escapeHTML(value)}</span></div>`;
      const displayNameHTML = envelope.headerFromName
        ? addressRow(msg("labelDisplayName"), envelope.headerFromName)
        : "";
      // エンベロープTo: 取得できない場合 (Unknown) は非表示
      const envelopeToHTML = envelope.envelopeTo && envelope.envelopeTo !== "Unknown"
        ? addressRow(msg("labelEnvelopeTo"), envelope.envelopeTo)
        : "";
      const addressHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipAddress"))}">${escapeHTML(msg("cardTitleAddress"))}</div>
          <div class="maiv-detail-stack">
            ${displayNameHTML}
            ${addressRow(msg("labelHeaderFrom"), envelope.headerFromAddress)}
            ${addressRow(msg("labelEnvelopeFrom"), envelope.envelopeFrom)}
            ${envelopeToHTML}
            ${alignmentWarningHTML}
          </div>
        </div>
      `;

      // --- 送達経路表示（データがあるときだけカード表示） ---
      let routeHTML = "";
      if (routeHops.length > 0) {
        let routeRows = "";
        for (let i = 0; i < routeHops.length; i++) {
          const hop = routeHops[i];
          const isFirst = (i === 0);

          // 前ホップとの時間差を計算して遅延を表示
          let delayStr = "";
          let delayClass = "maiv-delay-none";
          if (isFirst) {
            delayStr = `<span class="maiv-icon" title="${escapeHTML(msg("tooltipRouteOrigin"))}">${BI.rocketTakeoffFill}</span>`;
            delayClass = "maiv-delay-origin";
          } else if (hop.date && routeHops[i - 1].date) {
            const diffMs = hop.date - routeHops[i - 1].date;
            const diffSec = Math.round(diffMs / 1000);
            if (diffSec < 0) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-warning"; }
            else if (diffSec < 5) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-normal"; }
            else if (diffSec < 30) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-warning"; }
            else { delayStr = `${diffSec}s`; delayClass = "maiv-delay-danger"; }
          }

          // by ホスト名を表示用に整形
          const byDisplay = hop.by ? ` <span class="maiv-route-by">→ ${escapeHTML(hop.by)}</span>` : "";

          // IPアドレスタイプ (内部/外部) をアイコンとツールチップで表示
          let ipTag = "";
          if (hop.ip) {
            const ipIcon = hop.isInternal ? BI.houseFill : BI.globe;
            const ipLabel = hop.isInternal ? msg("ipInternal") : msg("ipExternal");
            ipTag = `<span class="maiv-ip-tag" title="${escapeHTML(hop.ip)} (${escapeHTML(ipLabel)})"><span class="maiv-icon">${ipIcon}</span></span>`;
          }

          // TLS / 暗号化状態セル（このホップの Received ヘッダ記載に基づく）
          // ・バージョン記載あり → 🔒 + バージョン番号（TLS 1.0/1.1 は ⚠️ で旧版警告）
          // ・ESMTPS 等のプロトコル名のみ → 🔒（バージョン不明）
          // ・SMTP/ESMTP 等の平文プロトコル表記 → 🔓（暗号化の記録なし）
          // ・with 句なし（ローカル配送等） → 無印（判定材料がないだけで警告ではない）
          let tlsCell = "";
          const tls = hop.tls;
          if (tls && tls.version) {
            const verNum = tls.version.replace(/^TLS\s*/i, "");
            const isLegacy = /^1\.[01]$/.test(verNum);
            const tlsCls = isLegacy ? "maiv-tls-warn" : "maiv-tls-secure";
            const tlsIcon = isLegacy ? BI.exclamationTriangleFill : BI.lockFill;
            const tipParts = [tls.version];
            if (tls.cipher) tipParts.push(tls.cipher);
            tlsCell = `<span class="maiv-tls-tag ${tlsCls}" title="${escapeHTML(tipParts.join(" / "))}">${tlsIcon} ${escapeHTML(verNum)}</span>`;
          } else if (tls && tls.encrypted === true) {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-secure" title="TLS">${BI.lockFill}</span>`;
          } else if (tls && tls.encrypted === false) {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-danger" title="${escapeHTML(msg("tlsUnencrypted"))}">${BI.unlockFill}</span>`;
          } else {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-unknown" title="${escapeHTML(msg("tlsUnknown"))}">${BI.dash}</span>`;
          }

          const rowClass = isFirst ? "maiv-route-origin" : "maiv-route-hop";
          const timeDisplay = hop.date ? hop.date.toLocaleTimeString() : "";
          const escapedLabel = isFirst ? `${escapeHTML(msg("labelOrigin"))} <span class="maiv-icon" title="${escapeHTML(msg("tooltipRouteOrigin"))}">${BI.arrowUpRightCircleFill}</span>` : escapeHTML(`#${i + 1}`);

          routeRows += `
            <tr class="${rowClass}">
              <td class="maiv-route-delay"><span class="${delayClass}">${delayStr}</span></td>
              <td>${escapedLabel} ${ipTag}${byDisplay}</td>
              <td class="maiv-route-tls">${tlsCell}</td>
              <td class="maiv-route-time">${escapeHTML(timeDisplay)}</td>
            </tr>
          `;
        }

        // Envelope-To を末尾行に追加（取得できない場合は省略）
        if (envelope.envelopeTo && envelope.envelopeTo !== "Unknown") {
          const envelopeToLabel = `${escapeHTML(msg("labelEnvelopeTo"))}: ${escapeHTML(envelope.envelopeTo)}`;
          routeRows += `
            <tr class="maiv-route-hop">
              <td class="maiv-route-delay"><span class="maiv-delay-none"><span class="maiv-icon" title="${escapeHTML(msg("tooltipEnvelopeTo"))}">${BI.arrowDownLeftCircleFill}</span></span></td>
              <td>${envelopeToLabel}</td>
              <td class="maiv-route-tls"></td>
              <td class="maiv-route-time"></td>
            </tr>
          `;
        }
        routeHTML = `
          <div class="maiv-card">
            <div class="maiv-card-title" title="${escapeHTML(msg("tooltipRoute"))}">${escapeHTML(msg("cardTitleRoute"))}</div>
            <div class="maiv-detail-stack">
              <table class="maiv-route-table">${routeRows}</table>
            </div>
          </div>
        `;
      }

      // --- ARC チェーン表示（データがあるときだけカード表示） ---
      let arcHTML = "";
      if (arcChain.length > 0) {
        let arcRows = "";
        for (const chain of arcChain) {
          const cvIcon = (chain.cv === "pass" || chain.cv === "none") ? BI.checkCircleFill : (chain.cv === "fail" ? BI.xCircleFill : BI.exclamationTriangleFill);
          const cvClass = (chain.cv === "pass" || chain.cv === "none") ? "status-pass" : (chain.cv === "fail" ? "status-fail" : "status-none");
          arcRows += `
            <tr>
              <td class="maiv-arc-chain-num">#${chain.i}</td>
              <td><span class="maiv-icon ${cvClass}">${cvIcon}</span><span class="${cvClass}">${escapeHTML(chain.cv.toUpperCase())}</span></td>
              <td class="maiv-arc-domain">${escapeHTML(chain.domain)}</td>
              <td class="maiv-arc-summary">${escapeHTML(chain.authSummary)}</td>
            </tr>
          `;
        }
        arcHTML = `
          <div class="maiv-card">
            <div class="maiv-card-title" title="${escapeHTML(msg("tooltipArc"))}">${escapeHTML(msg("cardTitleArc"))}</div>
            <div class="maiv-detail-stack">
              <table class="maiv-arc-table">${arcRows}</table>
            </div>
          </div>
        `;
      }

      // --- LINK SAFETY カード: フィッシング検知結果・リンクドメイン・リソースドメイン一覧（常時表示） ---
      const hasFindings = linkSafety && linkSafety.findings && linkSafety.findings.length > 0;
      const hasLinkDomains = linkSafety && linkSafety.linkDomains && linkSafety.linkDomains.size > 0;
      const hasResourceDomains = linkSafety && linkSafety.resourceDomains && linkSafety.resourceDomains.size > 0;

      // --- LINK SAFETY カード: データがあるときだけ表示 ---
      let linkSafetyHTML = "";
      if (hasFindings || hasLinkDomains || hasResourceDomains) {
        let findingsHTML = "";
        if (hasFindings) {
          // レベル別のCSSクラスとアイコン
          // critical=🚨(赤) / suspicious=⚠️(橙) / untrusted=⚠️(黄/控えめ) / privacy=🕵️(青灰)
          const levelCls = {
            "critical": "maiv-finding-critical",
            "suspicious": "maiv-finding-suspicious",
            "untrusted": "maiv-finding-untrusted",
            "privacy": "maiv-finding-privacy"
          };
          const levelIcon = {
            "critical": BI.xCircleFill,
            "suspicious": BI.exclamationTriangleFill,
            "untrusted": BI.exclamationTriangleFill,
            "privacy": BI.eyeSlashFill
          };
          // 未信頼な外部リンクドメインが1つだけの場合、その findings 行から直接Trustできるようにする。
          // 複数ある場合はユーザーが意図せず一括信頼するリスクがあるため、下のドメイン一覧から個別操作を促す。
          const externalSet = linkSafety.externalLinkDomains || new Set();
          const untrustedSingleDomain = (externalSet.size === 1) ? Array.from(externalSet)[0] : null;
          for (const f of linkSafety.findings) {
            const cls = levelCls[f.level] || "maiv-finding-suspicious";
            const icon = levelIcon[f.level] || "⚠️";
            // untrusted レベルの行に、対象が1ドメインに特定できる場合のみワンクリック Trust ボタンを添える
            let inlineTrust = "";
            if (f.level === "untrusted" && untrustedSingleDomain &&
                !(trustedDomains && trustedDomains.has(untrustedSingleDomain))) {
              inlineTrust = ` <button class="maiv-trust-btn" data-domain="${escapeHTML(untrustedSingleDomain)}">${escapeHTML(msg("trustDomainButton"))} ${escapeHTML(untrustedSingleDomain)}</button>`;
            }
            findingsHTML += `<div class="${cls}"><span class="maiv-icon">${icon}</span><span>${escapeHTML(f.detail)}${inlineTrust}</span></div>`;
          }
        }

        // ドメイン一覧のレンダリングヘルパー
        // showTrust: trueの場合、未信頼かつHeader From不一致のドメインに「信頼」ボタンを表示
        const renderDomainList = (title, domains, deceptive, trackers, showTrust) => {
          if (!domains || domains.size === 0) return "";
          let items = "";
          const sorted = Array.from(domains.entries())
            .sort((a, b) => {
              const aD = deceptive && deceptive.has(a[0]) ? 2 : 0;
              const bD = deceptive && deceptive.has(b[0]) ? 2 : 0;
              const aM = a[1].matchesFrom ? 0 : 1;
              const bM = b[1].matchesFrom ? 0 : 1;
              return (bD + bM) - (aD + aM);
            });
          for (const [domain, info] of sorted) {
            let icon, cls;
            const isTrusted = trustedDomains && trustedDomains.has(domain);
            if (deceptive && deceptive.has(domain)) {
              icon = BI.xCircleFill; cls = "maiv-link-domain-danger";
            } else if (info.matchesFrom) {
              icon = BI.checkCircleFill; cls = "maiv-link-domain-match";
            } else if (isTrusted) {
              icon = BI.shieldFillCheck; cls = "maiv-link-domain-trusted";
            } else {
              icon = BI.exclamationTriangleFill; cls = "maiv-link-domain-mismatch";
            }
            const trackerMark = trackers && trackers.has(domain) ? ` <span class="maiv-icon">${BI.eyeSlashFill}</span>` : "";
            // 「信頼」ボタン: 任意のリンク警告(critical/suspicious/untrusted)検出時、未信頼かつ不一致ドメインに表示
            const trustBtn = (showTrust && hasFindings && !info.matchesFrom && !isTrusted)
              ? ` <button class="maiv-trust-btn" data-domain="${escapeHTML(domain)}">${escapeHTML(msg("trustDomainButton"))}</button>`
              : "";
            items += `<div class="maiv-link-domain-item"><span class="maiv-icon ${cls}">${icon}</span><span class="${cls}">${escapeHTML(domain)}</span>${trackerMark} <span class="maiv-link-domain-count">(×${info.count})</span>${trustBtn}</div>`;
          }
          return `
            <div class="maiv-link-domain-list">
              <div class="maiv-link-domain-list-title">${escapeHTML(title)}</div>
              ${items}
            </div>
          `;
        };

        const deceptive = linkSafety.deceptiveDomains || new Set();
        const trackers = linkSafety.trackingPixelDomains || new Set();
        const linkListHTML = renderDomainList(msg("linkDomainListTitle"), linkSafety.linkDomains, deceptive, null, true);
        const resourceListHTML = renderDomainList(msg("resourceDomainListTitle"), linkSafety.resourceDomains, null, trackers, false);
        const domainListsHTML = linkListHTML + resourceListHTML;
        const hasDomainLists = domainListsHTML.trim().length > 0;

        // findings があればドメイン一覧もデフォルト展開
        const expandDomains = hasFindings;
        const expandedCls = expandDomains ? " maiv-expanded" : "";

        const findingsBlock = findingsHTML
          ? `<div class="maiv-findings-stack">${findingsHTML}</div>`
          : "";
        const domainListsBlock = hasDomainLists
          ? `<div class="maiv-collapsible-body${expandedCls}" id="maiv-link-safety-detail">${domainListsHTML}</div>`
          : "";

        // ドメイン一覧がある場合はタイトルをトグル化、findings時はデフォルト展開
        const hasExpandableLinkSafety = (hasLinkDomains || hasResourceDomains);
        const linkSafetyExpandedCls = (hasExpandableLinkSafety && hasFindings) ? " maiv-expanded" : "";
        linkSafetyHTML = `
          <div class="maiv-card">
            <div class="maiv-card-title${hasExpandableLinkSafety ? ' maiv-collapsible' + linkSafetyExpandedCls : ''}"${hasExpandableLinkSafety ? ' data-toggle="maiv-link-safety-detail"' : ''} title="${escapeHTML(msg("tooltipLinkSafety"))}">${escapeHTML(msg("cardTitleLinkSafety"))}</div>
            <div class="maiv-detail-stack">
              ${findingsBlock}
              ${domainListsBlock}
            </div>
          </div>
        `;
      }

      // --- 最終マークアップの組み立て ---
      const markup = `
        ${headerHTML}
        <div class="maiv-body-wrapper" id="maiv-body-wrapper">
          <div class="maiv-body-inner">
            <div class="maiv-body-content">
              <div class="maiv-grid">
                ${addressHTML}
                ${spfCard}
                ${dkimCard}
                ${dmarcCard}
                ${routeHTML}
                ${arcHTML}
                ${linkSafetyHTML}
              </div>
            </div>
          </div>
        </div>
      `;

      const doc = new DOMParser().parseFromString(markup, "text/html");
      container.replaceChildren(...doc.body.childNodes);

      // ■ Shadow DOM によるCSS隔離
      // HTMLメール側のCSS (例: * { font-size: 20px !important; }) がアドオンUIに
      // 影響しないよう、Shadow DOM でカプセル化する。
      // mode: "closed" により外部からの shadow root への参照も遮断する。
      const hostId = "maiv-shadow-host";
      let host = document.getElementById(hostId);
      if (host) host.remove();
      host = document.createElement("div");
      host.id = hostId;

      // テキストメール等で body に付く margin/padding を相殺し、バー周囲の余白をなくす。
      // Shadow 内の :host だけでは親の余白は相殺できないため light DOM 側で調整する。
      const bodyCS = getComputedStyle(document.body);
      const insetL = (parseFloat(bodyCS.marginLeft) || 0) + (parseFloat(bodyCS.paddingLeft) || 0);
      const insetR = (parseFloat(bodyCS.marginRight) || 0) + (parseFloat(bodyCS.paddingRight) || 0);
      const insetT = (parseFloat(bodyCS.marginTop) || 0) + (parseFloat(bodyCS.paddingTop) || 0);
      host.style.cssText = [
        "display:block !important",
        "position:relative !important",
        "margin:0 !important",
        "padding:0 !important",
        "border:0 !important",
        "box-sizing:border-box !important",
        `margin-left:-${insetL}px !important`,
        `margin-right:-${insetR}px !important`,
        `margin-top:-${insetT}px !important`,
        `width:calc(100% + ${insetL + insetR}px) !important`,
        "max-width:none !important",
        "min-width:0 !important"
      ].join(";");

      document.body.insertAdjacentElement("afterbegin", host);

      const shadow = host.attachShadow({ mode: "closed" });
      shadow.appendChild(style);
      shadow.appendChild(container);

      // --- アコーディオンの開閉インタラクション ---
      const headerToggle = container.querySelector('#maiv-header-toggle');
      const bodyWrapper = container.querySelector('#maiv-body-wrapper');
      const toggleIcon = container.querySelector('#maiv-toggle-icon');

      // 開閉状態を切り替え、aria-expanded 属性も同期させる共通関数
      const togglePanel = () => {
        const isExpanded = bodyWrapper.classList.toggle('expanded');
        toggleIcon.classList.toggle('expanded');
        headerToggle.setAttribute('aria-expanded', isExpanded);
      };

      // マウスクリックによる開閉（コピーボタンは除外。キャレットは明示的なボタン）
      headerToggle.addEventListener('click', (e) => {
        if (e.target.closest('.maiv-copy-btn')) return;
        togglePanel();
      });
      // キャレット単体でも確実に反応（ヘッダ委譲と二重でも idempotent に開閉するだけ）
      if (toggleIcon) {
        toggleIcon.addEventListener('click', (e) => {
          // ヘッダ側リスナと二重発火しないよう止める
          e.stopPropagation();
          togglePanel();
        });
      }

      // --- コピーボタンハンドラー ---
      const copyBtn = container.querySelector('#maiv-copy-btn');
      if (copyBtn) {
        copyBtn.addEventListener('click', async (e) => {
          e.stopPropagation();
          let ok = false;
          try {
            const reportText = generateReportText();
            ok = await writeToClipboard(reportText);
          } catch (err) {
            console.error("MailAuthInfoViewer: Failed to copy to clipboard", err);
            ok = false;
          }
          // 成否をアイコンと title で2秒間フィードバックして元に戻す
          const prevTitle = copyBtn.getAttribute("title") || msg("copyButton");
          copyBtn.innerHTML = ok ? BI.checkCircleFill : BI.xCircleFill;
          copyBtn.title = ok ? msg("copiedSuccess") : msg("copiedFailed");
          setTimeout(() => {
            copyBtn.innerHTML = BI.clipboard;
            copyBtn.title = prevTitle;
          }, 2000);
        });
      }

      // --- カード内折りたたみセクションの開閉 ---
      // data-toggle 属性を持つ要素をクリックすると、対応するIDの折りたたみボディを開閉する
      container.addEventListener('click', (e) => {
        const toggler = e.target.closest('[data-toggle]');
        if (!toggler) return;
        // メインヘッダのクリックイベントと衝突しないよう、ヘッダ内のトグルは除外
        if (toggler.closest('#maiv-header-toggle')) return;
        const targetId = toggler.getAttribute('data-toggle');
        const target = container.querySelector('#' + targetId);
        if (!target) return;
        toggler.classList.toggle('maiv-expanded');
        target.classList.toggle('maiv-expanded');
      });

      // --- 「信頼」ボタン ---
      // findings 行のインラインTrust、ドメイン一覧内のTrust、どちらも同じハンドラで処理する
      container.addEventListener('click', async (e) => {
        const btn = e.target.closest('.maiv-trust-btn');
        if (!btn) return;
        e.stopPropagation();
        const domain = btn.getAttribute('data-domain');
        if (!domain) return;

        // Shadow DOM内カスタム確認ダイアログ（DOM APIで構築）
        const confirmText = msg("trustDomainConfirm").replace("{domain}", domain);
        const overlay = document.createElement("div");
        overlay.className = "maiv-confirm-overlay";

        const box = document.createElement("div");
        box.className = "maiv-confirm-box";

        const textEl = document.createElement("div");
        textEl.className = "maiv-confirm-text";
        textEl.textContent = confirmText;

        const buttons = document.createElement("div");
        buttons.className = "maiv-confirm-buttons";

        const cancelBtn = document.createElement("button");
        cancelBtn.className = "maiv-confirm-cancel";
        cancelBtn.textContent = "Cancel";

        const okBtn = document.createElement("button");
        okBtn.className = "maiv-confirm-ok";
        okBtn.textContent = "OK";

        buttons.appendChild(cancelBtn);
        buttons.appendChild(okBtn);
        box.appendChild(textEl);
        box.appendChild(buttons);
        overlay.appendChild(box);
        container.appendChild(overlay);

        const result = await new Promise(resolve => {
          okBtn.addEventListener('click', () => resolve(true));
          cancelBtn.addEventListener('click', () => resolve(false));
          overlay.addEventListener('click', (ev) => { if (ev.target === overlay) resolve(false); });
        });
        overlay.remove();
        if (!result) return;

        try {
          const stored = await browser.storage.local.get("trustedDomains");
          const list = stored.trustedDomains || [];
          if (!list.includes(domain)) {
            list.push(domain);
            await browser.storage.local.set({ trustedDomains: list });
          }
          btn.textContent = msg("trustDomainAdded");
          btn.disabled = true;
        } catch (err) {
          console.error("MailAuthInfoViewer: Failed to save trusted domain", err);
        }
      });

      // 「安全」以外の場合はアニメーション付き自動展開
      if (security.shouldAutoExpand) {
        setTimeout(() => {
          bodyWrapper.classList.add('expanded');
          toggleIcon.classList.add('expanded');
          headerToggle.setAttribute('aria-expanded', 'true');
        }, 50);
      }
    };

    // =========================================================
    // メイン処理: データ取得 → 解析 → UI構築
    // =========================================================
    const resp = await browser.runtime.sendMessage({ command: "getMessageDetails" });
    if (resp.error || !resp.fullMessage) return;

    const fullMsg = resp.fullMessage;
    const msgHeader = resp.messageHeader || {};
    const headers = fullMsg.headers || {};

    // ■ 信頼済みドメインのホワイトリスト読み込み
    let trustedDomains = new Set();
    try {
      const stored = await browser.storage.local.get("trustedDomains");
      if (stored.trustedDomains && Array.isArray(stored.trustedDomains)) {
        trustedDomains = new Set(stored.trustedDomains);
      }
    } catch { /* storage未対応環境ではスキップ */ }

    // ■ コンパクト表示設定の読み込み（options 画面で切り替え）
    //    通知バーの高さを抑えたいユーザー向けの表示オプション。判定には影響せず、
    //    未設定／storage 未対応環境では既定の通常表示にフォールバックする。
    let compactMode = false;
    try {
      const stored = await browser.storage.local.get("compactMode");
      compactMode = stored.compactMode === true;
    } catch { /* storage未対応環境では通常表示 */ }

    // ■ 生ヘッダ順序の取得（Authentication-Results / Received-SPF がある場合、または受信プロバイダ固有ルールが該当する場合）
    //    最上段 Received の受信ホストが PROVIDER_INGRESS_RULES のプロバイダである場合に加え、
    //    汎用経路でも A-R・Received-SPF の位置を検証するため（selectGenericAR / pickReceivedSpf）、それらを含むメールでは
    //    生ヘッダを background 経由で取得する。
    //    メッセージ全体の読み込みを伴うため、どちらも無く固有ルールにも該当しないメールでは取得しない。
    //    取得に失敗した場合は null のまま進め、A-R を信頼しない（安全側）。
    let rawHeaderOrder = null;
    //    受信ホスト名の切り出しは detectProviderRoute と同じく "(" でも区切り、判定を一致させる。
    const topReceivedBy = ((headers["received"] || [])[0] || "").match(/\bby\s+([^\s;()]+)/i);
    // Received-SPF だけのメールも、補完に使う Received-SPF の位置検証（pickReceivedSpf）に生ヘッダが要る
    if ((headers["authentication-results"] || []).length > 0 || (headers["received-spf"] || []).length > 0 ||
        (topReceivedBy && findProviderRule(topReceivedBy[1]))) {
      try {
        const rawResp = await browser.runtime.sendMessage({ command: "getRawHeaders" });
        if (rawResp && typeof rawResp.rawHeaders === "string") {
          // 折り返し行（先頭が空白）を直前のヘッダに連結し、上から順に {name, value} へ分解する
          rawHeaderOrder = [];
          for (const line of rawResp.rawHeaders.split(/\r?\n/)) {
            if (/^[ \t]/.test(line) && rawHeaderOrder.length > 0) {
              rawHeaderOrder[rawHeaderOrder.length - 1].value += " " + line.trim();
              continue;
            }
            const idx = line.indexOf(":");
            if (idx <= 0) continue;
            rawHeaderOrder.push({ name: line.slice(0, idx).trim().toLowerCase(), value: line.slice(idx + 1).trim() });
          }
        }
      } catch { /* 取得できない環境ではプロバイダ固有ルールを適用しない */ }
    }

    const envelope = parseEnvelope(fullMsg, headers, msgHeader, trustedDomains);
    const authResults = parseAuthResults(headers, envelope, rawHeaderOrder);
    const routeHops = parseRoute(headers);
    const arcChain = parseArcChain(headers);
    const bodyContent = parseMessageBody(fullMsg);
    const linkSafety = analyzeLinkSafety(bodyContent, envelope.headerOrgDomain, trustedDomains);
    const security = determineSecurityStatus(authResults, envelope.isDomainAligned, envelope.envelopeFrom, envelope.isDisplayNameSpoofed, linkSafety, envelope.senderHomograph, envelope.replyToHomograph);

    buildUI(envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains, compactMode);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();