# Research and improvement priorities

Reviewed 5 October 2026. Primary sources inform the design; their vendors' claims and research results are not Voight's measured results.

## Findings and decisions

| Evidence | Interpretation for this project | Decision |
| --- | --- | --- |
| Cloudflare documents heuristic, JavaScript and machine-learning detection engines, with different sources of evidence. [Detection engines](https://developers.cloudflare.com/bots/concepts/bot-detection-engines/) | No single browser check should be the entire boundary. | Keep passkey admission, optional declarations, and server-side extraction budgets independent. We do not reproduce Cloudflare's network/reputation data. |
| WebDriver defines a cooperative browser automation flag. [W3C interface](https://www.w3.org/TR/webdriver/#interface) | A positive declaration can support a rejection policy; a false value is not proof of human control. | Add off/observe/enforce modes. Include a controlled suppression case in regression tests. |
| Anubis includes configurable proof-of-work challenges with different difficulty thresholds. [Maintainer policy](https://github.com/TecharoHQ/anubis/blob/main/data/botPolicies.yaml) | Computation can impose cost without proving a person is present. | Do not add a universal CPU challenge now; evaluate cost, mobile performance and accessibility before an optional future layer. |
| FP-Agent evaluates seven browsing agents on a controlled instrumented website and reports stronger discrimination from behavior than shared browser fingerprints. [Research paper](https://arxiv.org/abs/2605.01247) | Behavioral research is promising, but the study's tasks and agents do not establish our production accuracy. | First build a consent-based evaluation dataset. Do not ship a fabricated risk score or label absent telemetry as human. |
| Another controlled study of six agents reports bypasses against evaluated anti-bot mechanisms and benefits from multiple fingerprint layers. [Research paper](https://arxiv.org/abs/2606.30119) | Evaluate adversarial and ordinary users on our own infrastructure; expect adaptation. | Preserve explicit known-gap tests. Future TLS/HTTP signals require a trusted edge design rather than spoofable forwarded headers. |
| Private State Tokens convey trust established elsewhere; Chrome explicitly distinguishes conveying trust from establishing it. [Chrome documentation](https://developer.chrome.com/docs/privacy-security/private-state-tokens) | Token plumbing alone does not identify an agent-free browser. | Defer until there is a useful issuer, audience and compatibility case. |

## What was implemented in 0.3

1. Optional automation declaration policy, with observe as the default and minimal short-lived data.
2. Real Chromium enrollment and login through the production UI, using a virtual authenticator.
3. Human-readable denial pages, preserving machine-readable JSON for API-style requests.
4. A deliberately passing suppressed-signal automation case, followed by a resource-limit check.
5. A standalone interactive evidence demo, browser recordings, and evaluator instructions that keep the source repository private.

## Next experiments, in order

1. **Consenting human/assistive-tool pilot:** measure passkey completion, accidental rejections, retries, page-load failures, and abandonment. This validates usability before making enforcement the default.
2. **Actual browser-agent trials:** give named agents the same authorized tasks and test content; record their versions, tools, policies, successful content retrieval, latency and failure causes. Separate unapproved agents from agents controlling an approved account.
3. **Resource-sensitive access:** evaluate tighter export/search policies and fresh passkey verification for sensitive actions. Re-verification must not erase accumulated extraction usage.
4. **Operator review and temporary containment:** make evidence explainable, with bounded cooldowns and recovery, before adding opaque classifiers. Distinguish abuse prevention from claims about humanity.
5. **Deployment boundary:** trusted reverse-proxy configuration, origin reachability tests, controlled load testing and a security review. Do not accept arbitrary client IP/TLS identity headers.
6. **Managed-device attestation feasibility:** evaluate a narrow managed audience separately from general visitors; measure compatibility and privacy costs before promising stronger device trust.

## Positioning we can defend

An inspectable, self-hosted access gateway for small private content services and controlled pilots. Its useful distinction is the combination of approved passkeys, credential-wide extraction limits, minimal optional signals, and reproducible evidence—including failures. It is not a replacement for a global bot-reputation network or a guarantee that humans alone can read public content.
