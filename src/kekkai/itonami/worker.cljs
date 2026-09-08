(ns kekkai.itonami.worker
  "The kekkai itonami, mounted at `app.itonami.cloud/kekkai`.

  Uploaded into `ai-gftd-repository-dispatch`, so this Worker has no URL of its
  own — `itonami-fleet-dispatch` strips the first path segment and this handler
  sees `/health` rather than `/kekkai/health`. The script name, the repository
  name and `blueprint.edn`'s `:itonami.blueprint/mount` are the same string, by
  being the same string rather than through a table.

  What it deliberately does not do: sign anything. Issuing a netmap means
  holding the authority key, and a Worker reachable from the public internet is
  the wrong place for one. Issuance stays on the control plane; this surface is
  the half that needs no secret — evaluate a policy, verify a signature."
  (:require [cljs.reader :as reader]
            [goog.object :as gobj]
            [kotoba.lang.text :as str]
            [jp-go-dds.page :as page]
            [jp-go-dds.tokens :as tokens]
            [kekkai.itonami.decide :as decide]
            [kekkai.itonami.gate :as gate]
            [kekkai.itonami.verify :as verify]
            [kekkai.itonami.view :as view])
  (:require-macros [kekkai.itonami.inline :refer [inline-file inline-resource]]))

(def dds-css (inline-resource "jp_go_dds/dds.css"))
(def blueprint-edn (inline-file "blueprint.edn"))

(def mount "/kekkai")
(def max-body-bytes (* 256 1024))

(defn- json-response [body status]
  (js/Response. (js/JSON.stringify (clj->js body))
                #js {:status status
                     :headers #js {"content-type" "application/json"
                                   "cache-control" "no-store"}}))

(defn- edn-response [text status]
  (js/Response. text
                #js {:status status
                     :headers #js {"content-type" "application/edn; charset=utf-8"
                                   "cache-control" "no-store"}}))

(defn- html-response [html]
  (js/Response. html
                #js {:status 200
                     :headers #js {"content-type" "text/html; charset=utf-8"
                                   "cache-control" "no-store"}}))

(defn- read-body
  "-> Promise of {:ok body} | {:error …}.

  Bounded before parsing rather than after: `Content-Length` is the caller's
  claim, and a reader run over an unbounded stream is the resource being spent
  by whoever chose the size."
  [request]
  (-> (.text request)
      (.then (fn [text]
               (cond
                 (> (.-length text) max-body-bytes)
                 {:error :body-too-large :limit max-body-bytes}

                 (str/blank? text)
                 {:error :empty-body}

                 :else
                 (let [parsed (try (reader/read-string text)
                                   (catch :default e {::unreadable (str e)}))]
                   (if (::unreadable parsed)
                     {:error :unreadable-edn :detail (::unreadable parsed)}
                     {:ok parsed})))))
      (.catch (fn [e] {:error :body-unreadable :detail (str e)}))))

(defn- page-html []
  (page/->page
   {:title "kekkai — 結界 | itonami"
    :description "ゼロトラスト・メッシュ制御面の営み。ポリシー判定と署名検証を公開する。"
    :lang "ja"
    :css dds-css
    :app-css (str tokens/bridge-css "\n" view/app-css)}
   (view/body {:mount mount :price "USD 0.001"})))

;; ── the free half ───────────────────────────────────────────────────────────

(defn- handle-verify [request]
  (-> (.text request)
      (.then
       (fn [text]
         (let [authority (.get (.-headers request) "x-netmap-authority")]
           (cond
             (> (.-length text) max-body-bytes)
             (js/Promise.resolve
              (json-response {:verified? false :reason :body-too-large
                              :limit max-body-bytes} 413))

             (str/blank? (str authority))
             (js/Promise.resolve
              (json-response
               {:verified? false :reason :missing-netmap-authority
                :detail (str "send the publisher's Ed25519 SPKI (base64) in the "
                             "X-Netmap-Authority header. It is deliberately not "
                             "read from the envelope: an envelope carrying the "
                             "only copy of its signer's key would authenticate "
                             "itself.")}
               400))

             :else
             (.then (verify/verify-envelope text authority)
                    (fn [result]
                      (json-response result (if (:verified? result) 200 422))))))))
      (.catch (fn [e] (json-response {:verified? false :reason :verification-failed
                                      :detail (str e)} 500)))))

;; ── the paid half ───────────────────────────────────────────────────────────

(defn- decide-requirements [env url]
  (gate/requirements
   {:pay-to (gobj/get env "X402_PAY_TO")
    :usd (or (gobj/get env "X402_DECIDE_USD") "0.001")
    :network (or (gobj/get env "X402_NETWORK") "base")
    :resource (str (.-origin url) mount "/x402/acl/decide")
    :description "one deny-by-default kekkai edge decision, organisation boundary first"}))

(defn- handle-decide [request env url]
  (let [payment (.get (.-headers request) "x-payment")
        reqs (decide-requirements env url)]
    (if (str/blank? (str payment))
      (js/Promise.resolve (json-response (gate/challenge-body reqs) 402))
      (-> (gate/verify-payment {:facilitator (or (gobj/get env "X402_FACILITATOR")
                                                 "https://x402.nexus")
                                :payment payment
                                :reqs reqs})
          (.then
           (fn [{:keys [paid? reason detail payer]}]
             (if-not paid?
               ;; Fail closed, and say WHICH closed door it is:
               ;; :facilitator-unreachable means wait, :payment-invalid means
               ;; pay again. One undifferentiated 402 would send a caller who
               ;; already paid to pay a second time for the same resource.
               (js/Promise.resolve
                (json-response (assoc (gate/challenge-body reqs (name reason))
                                      :reason reason
                                      :detail detail)
                               402))
               (.then (read-body request)
                      (fn [{:keys [ok error] :as body}]
                        (if error
                          (json-response (assoc (dissoc body :ok) :error error) 400)
                          (let [result (decide/decide ok)]
                            (json-response (assoc result :payer payer)
                                           (if (= :invalid-request (:error result))
                                             400 200)))))))))))))

;; ── routing ─────────────────────────────────────────────────────────────────

(defn handle [request env]
  (let [url (js/URL. (.-url request))
        path (.-pathname url)
        method (.-method request)]
    (cond
      (and (= "GET" method) (#{"/" ""} path))
      (js/Promise.resolve (html-response (page-html)))

      (and (= "GET" method) (= "/health" path))
      (js/Promise.resolve
       (json-response {:ok true :actor "kekkai" :mount mount
                       :engine {:control-plane "kotoba-lang/kekkai"
                                :data-plane "kotoba-lang/kekkai-node"}}
                      200))

      (and (= "GET" method) (= "/blueprint.edn" path))
      (js/Promise.resolve (edn-response blueprint-edn 200))

      (and (= "POST" method) (= "/netmap/verify" path))
      (handle-verify request)

      (and (= "POST" method) (= "/x402/acl/decide" path))
      (handle-decide request env url)

      ;; A GET on a POST-only resource is a method error, not a missing one:
      ;; answering 404 would send a caller looking for a typo in a path that is
      ;; correct.
      (#{"/netmap/verify" "/x402/acl/decide"} path)
      (js/Promise.resolve
       (json-response {:error "method not allowed" :path path :expected "POST"} 405))

      :else
      (js/Promise.resolve
       (json-response {:error "not found" :actor "kekkai" :path path
                       :routes ["/" "/health" "/blueprint.edn"
                                "POST /netmap/verify" "POST /x402/acl/decide"]}
                      404)))))

(def app
  #js {:fetch (fn [request env _ctx] (handle request env))})
