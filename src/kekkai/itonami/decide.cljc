(ns kekkai.itonami.decide
  "The paid resource: one deny-by-default edge decision, organisation boundary
  applied first.

  This namespace holds no policy logic. `kekkai.acl/edge-decision` is the same
  function the TailnetGovernor censors proposals with, and the request is
  shaped into its arguments and its answer shaped back — nothing in between.
  That is the whole point of selling it: a second implementation at the edge
  would be a copy of the censor that drifts from it, and a policy engine that
  disagrees with the governor is worse than no policy engine.

  ## Why authorisation is the meter and traffic is not

  The engine's charter (G4) is that there is no `:traffic/*` or
  `:user/activity` namespace — the control plane authorises reachability and
  never records what flows through the tunnels. Metering bytes would require
  measuring bytes, so a per-gigabyte overlay cannot be built on this engine
  without contradicting the thing that makes it worth using. A decision, by
  contrast, is already made and already written to the genealogy ledger. It is
  the only unit here that can be counted without learning something about the
  user that the plane promised not to learn."
  (:require [clojure.string :as str]
            [kekkai.acl :as acl]))

(def max-nodes
  "An upper bound on the plane a single request may carry.

  Not a pricing device: a bound exists because `edge-decision` walks grants and
  peerings, and an unbounded request body is CPU that the caller chose and the
  seller pays for. One decision is one decision whatever the plane's size, so
  the bound is on the input rather than on the answer."
  256)

(defn problems
  "Structural problems with a decision request, as a vector.

  Returned in full rather than one at a time: a caller fixing a request should
  not have to make one round trip per mistake, and each round trip past a 402
  is a payment."
  [{:keys [plane src dst]}]
  (cond-> []
    (not (map? plane)) (conj {:problem :plane-not-a-map})
    (and (map? plane) (not (map? (:policies plane))))
    (conj {:problem :policies-not-a-map})
    (and (map? plane) (:peerings plane) (not (sequential? (:peerings plane))))
    (conj {:problem :peerings-not-sequential})
    (not (map? src)) (conj {:problem :src-not-a-node})
    (not (map? dst)) (conj {:problem :dst-not-a-node})
    (and (map? src) (str/blank? (str (:id src)))) (conj {:problem :src-missing-id})
    (and (map? dst) (str/blank? (str (:id dst)))) (conj {:problem :dst-missing-id})
    (> (+ (count (:policies plane)) (count (:peerings plane))) max-nodes)
    (conj {:problem :plane-too-large :limit max-nodes})))

(defn decide
  "-> the decision, or `{:error :invalid-request :problems [...]}`.

  The three refusal reasons `edge-decision` distinguishes are passed through
  unflattened. They call for different actions — `:deny-by-default` is a policy
  edit, `:cross-tailnet` is a negotiation between two organisations, and
  `:peering-grant-missing` is an edit to a document both organisations already
  signed — and collapsing them into one 'denied' sends an operator to change a
  policy that cannot possibly fix it."
  [{:keys [plane src dst] :as request}]
  (let [problems (problems request)]
    (if (seq problems)
      {:error :invalid-request :problems problems}
      (let [plane {:policies (:policies plane) :peerings (vec (:peerings plane))}
            decision (acl/edge-decision plane src dst)]
        (merge {:src (:id src)
                :dst (:id dst)
                :src-tailnet (acl/tailnet-of src)
                :dst-tailnet (acl/tailnet-of dst)
                ;; Reported alongside the decision because a self-claimed tag is
                ;; the escalation an allow can hide: an edge may be granted to a
                ;; tag the node's owner was never authorised to assume, and the
                ;; grant alone does not say so.
                :src-unowned-tags (acl/unowned-tags
                                   (get (:policies plane) (acl/tailnet-of src)) src)}
               decision)))))
