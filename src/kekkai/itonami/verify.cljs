(ns kekkai.itonami.verify
  "Signed-netmap envelope verification at the edge, on WebCrypto.

  A third implementation of one check, and that needs justifying. There is a
  JVM one (`kekkai.envelope/verify`, publisher side) and a Node one
  (`kekkai.node.signed-netmap/verify-envelope`, node side). Neither runs in a
  Cloudflare Worker: the first needs a JVM, the second needs `node:crypto`'s
  one-shot `crypto.verify`. What makes a third acceptable rather than drift is
  that all three are pinned to the same bytes — `kotoba-lang/kekkai`'s fixture
  is the artifact each of them is tested against.

  Kept free, deliberately. Charging to check whether an artifact is authentic
  puts a price on the one action that protects the caller, and a node that
  cannot afford to verify runs unverified — which is the failure the whole
  signed-netmap boundary exists to prevent."
  (:require [cljs.reader :as reader]
            [clojure.string :as str]))

(defn- b64->bytes [s]
  (let [binary (js/atob s)
        out (js/Uint8Array. (.-length binary))]
    (dotimes [i (.-length binary)]
      (aset out i (.charCodeAt binary i)))
    out))

(defn- hex [buffer]
  (str/join (map #(.padStart (.toString % 16) 2 "0")
                 (array-seq (js/Uint8Array. buffer)))))

(defn- constant-time=
  "String comparison that does not leak a match length through timing.

  The digest and the signer key are attacker-supplied, and `=` on strings
  short-circuits at the first differing character. The node-side verifier uses
  `crypto.timingSafeEqual` for the same two comparisons; WebCrypto has no
  equivalent, so it is written out."
  [a b]
  (let [a (str a) b (str b)]
    (if (not= (.-length a) (.-length b))
      false
      (zero? (reduce (fn [acc i]
                       (bit-or acc (bit-xor (.charCodeAt a i) (.charCodeAt b i))))
                     0
                     (range (.-length a)))))))

(defn refusal
  "Refusals are values, not exceptions: this runs inside a request handler that
   must answer every one of them with a reason the caller can act on. Silent or
   generic denial is what makes a deny-by-default system unoperable."
  [reason detail]
  {:verified? false :reason reason :detail detail})

(defn- parse-verified
  "Parse the payload — only now, and only if the signature held.

  A reader is an attack surface, so running one over unauthenticated bytes is
  the mistake the whole ordering exists to avoid. Both other implementations
  parse in this same position."
  [ok? payload]
  (if-not ok?
    (refusal :netmap-signature-invalid
             "the signature does not verify against the authority key")
    (let [netmap (try (reader/read-string (.decode (js/TextDecoder.) payload))
                      (catch :default _ ::unreadable))]
      (if (= ::unreadable netmap)
        (refusal :unreadable-payload "the payload verified but is not readable EDN")
        {:verified? true :netmap netmap}))))

(defn verify-envelope
  "-> Promise of {:verified? true :netmap …} or a `refusal`.

  Same order as both other implementations: signer, then digest, then
  signature, then parse. The payload is parsed only after it verifies — a
  reader is an attack surface, and running one over unauthenticated bytes is
  the mistake the ordering exists to avoid."
  [text authority-spki-b64]
  (js/Promise.
   (fn [resolve _reject]
     (if (str/blank? (str authority-spki-b64))
       (resolve (refusal :missing-netmap-authority
                         "an authority public key must be configured out of band"))
       (let [envelope (try (reader/read-string text) (catch :default _ nil))
             {:netmap/keys [payload-b64 signature-b64 signer-spki-b64 sha256]} envelope]
         (cond
           (not (map? envelope))
           (resolve (refusal :unreadable-envelope "the envelope is not readable EDN"))

           (not (and (string? payload-b64) (string? signature-b64)
                     (string? signer-spki-b64) (string? sha256)))
           (resolve (refusal :invalid-netmap-envelope
                             "envelope is missing payload / signature / signer / digest"))

           (not (constant-time= authority-spki-b64 signer-spki-b64))
           (resolve (refusal :untrusted-netmap-signer
                             "the envelope is signed by a key that is not the configured authority"))

           :else
           (let [payload (b64->bytes payload-b64)
                 subtle (.-subtle js/crypto)]
             (-> (.digest subtle "SHA-256" payload)
                 (.then (fn [digest]
                          (if-not (constant-time= sha256 (hex digest))
                            (resolve (refusal :netmap-digest-mismatch
                                              "the payload does not hash to the digest the envelope claims"))
                            (-> (.importKey subtle "spki" (b64->bytes signer-spki-b64)
                                            #js {:name "Ed25519"} false #js ["verify"])
                                (.then (fn [key]
                                         (.verify subtle #js {:name "Ed25519"} key
                                                  (b64->bytes signature-b64) payload)))
                                (.then (fn [ok?]
                                         (resolve (parse-verified ok? payload))))
                                (.catch (fn [e]
                                          (resolve (refusal :netmap-signature-invalid
                                                            (str e)))))))))
                 (.catch (fn [e]
                           (resolve (refusal :verification-failed (str e)))))))))))))
