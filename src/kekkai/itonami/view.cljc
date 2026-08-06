(ns kekkai.itonami.view
  "The public page. jp-go-dds (デジタル庁デザインシステム) — the workspace's base
  design system — with app CSS written only against the `--hig-*` token
  contract that `jp-go-dds.tokens/bridge-css` redefines on top of DADS
  primitives.

  One caveat that is measured rather than assumed: the bridge carries 27
  tokens, all of them colour, palette, font-family and hairline. It carries no
  `--hig-spacing-*`, no `--hig-text-*-size`, and no `--hig-radius-*`, and an
  unmapped custom property resolves to nothing rather than erroring. So spacing
  here is `em`-relative and the type scale is DADS's own utility classes; a
  `var(--hig-spacing-4)` would silently collapse to zero."
  (:require [jp-go-dds.core :as dds]))

(def app-css
  "Small and unlayered, which is the contract: library CSS ships inside
   `@layer`, so app CSS always wins without compound selectors."
  "
.k-lede { max-width: 46em; }
.k-endpoint { font-family: var(--hig-font-mono, ui-monospace, monospace);
              font-size: 0.9em; }
.k-price { color: var(--hig-color-label-secondary, inherit); }
.k-free { color: var(--hig-color-label-secondary, inherit); }
")

(defn- endpoint-rows [{:keys [mount]}]
  [["GET" (str mount "/health") "liveness" "free"]
   ["GET" (str mount "/blueprint.edn") "this actor's Open Business Blueprint" "free"]
   ["POST" (str mount "/netmap/verify") "verify a signed netmap envelope" "free"]
   ["POST" (str mount "/x402/acl/decide") "one deny-by-default edge decision" "USD 0.001"]])

(defn body
  [{:keys [price] :as opts}]
  [(dds/container
    (dds/section
     {}
     (dds/heading 1 "kekkai — 結界")
     [:p.k-lede
      "ゼロトラスト・メッシュの制御面を、営みとして公開したもの。"
      "エンジン本体は "
      [:a {:href "https://github.com/kotoba-lang/kekkai"} "kotoba-lang/kekkai"]
      "（制御面）と "
      [:a {:href "https://github.com/kotoba-lang/kekkai-node"} "kotoba-lang/kekkai-node"]
      "（データ面）。ここが公開しているのは、そのうち"
      [:strong "秘密鍵を必要としない部分"]
      "だけ — ポリシー判定と署名検証。netmap の発行は制御面に残る。"]

     (dds/heading 2 "何に課金し、何に課金しないか")
     [:p.k-lede
      "エンジンの憲章 (G4) は「制御面は到達性を認可するのであって、"
      "トンネルを流れたものを記録しない」— "
      [:code ":traffic/*"] " も " [:code ":user/activity"] " も名前空間として存在しない。"
      "従量課金は測定を要求するので、この憲章の上に帯域課金は載らない。"
      "だから計器は" [:strong "認可（authorization）"]
      "の側に置いてある — それは制御面がすでに下していて、"
      "すでに genealogy 台帳に書いている判断だから。"]
     [:p.k-lede
      [:strong "署名検証は無料。"]
      "本物かどうかを確かめる行為に値段を付けると、"
      "検証を払えないノードは検証せずに動くことになる — "
      "この境界がまさに防ごうとしている失敗そのもの。"]

     (dds/heading 2 "エンドポイント")
     (dds/table
      {:caption "app.itonami.cloud/kekkai"
       :headers ["method" "path" "何をするか" "価格"]
       :rows (mapv (fn [[m p d c]]
                     [m [:span.k-endpoint p] d
                      [:span {:class (if (= "free" c) "k-free" "k-price")} c]])
                   (endpoint-rows opts))})

     (dds/heading 2 "支払い")
     [:p.k-lede
      "x402（HTTP 402 Payment Required）。有料エンドポイントは "
      [:code "X-PAYMENT"] " が無ければ 402 と challenge を返す。"
      "決済の検証は facilitator "
      [:a {:href "https://x402.nexus"} "x402.nexus"]
      " に委譲していて、この Worker は鍵を持たない（"
      [:code "X402_PAY_TO"] " は公開の treasury アドレス）。"
      "USDC / Base、1 判定 " (or price "USD 0.001") "。"]
     [:p.k-lede
      "facilitator に到達できないときは " [:strong "402 を返す"]
      "（fail closed）。ただし理由は " [:code ":facilitator-unreachable"]
      " であって " [:code ":payment-invalid"]
      " ではない — 「払い直せ」と「待て」は違う指示だから。"]))])
