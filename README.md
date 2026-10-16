# AI routing rules: Claude, OpenAI and verification

Reviewed **2026-10-16**. These are Stash/Mihomo **classical rule providers**, not a complete client configuration, a firewall trust list, or an account-safety guarantee.

## Coverage contract

`claude.yaml` covers the first-party families in the official Desktop list, the standalone Claude Code network table (including optional installation/telemetry rows), published Artifact library/font hosts, and documented Anthropic **inbound** API/Console IP ranges. `gpt.yaml` covers the published OpenAI domain allowlist and retains its existing non-OpenAI sections. `verification.yaml` supplies shared challenge, identity, sign-in and selected payment dependencies.

The acceptance target is **100% of the versioned declarations in `tests/routing-corpus.json`**, not 100% of all future destinations or all network traffic. The corpus contains domains, wildcard families and CIDRs independently transcribed from the linked official sources. Constructed URL tests are explicitly synthetic, not captured sessions. Optional dependencies remain enabled for recall; they are not claimed to prevent account restrictions.

Local snapshot: **162/162 declaration checks**, including **29 wildcard-family checks**; **33/33 constructed URL checks**; **93/93 negative checks**; **12/12 matcher/parser tests**. A declaration checked against three providers counts three times. These numbers are neither unique observed hosts nor a global false-positive estimate. No Stash/Mihomo binary or real-device traffic was exercised.

## Changes and corrections to the supplied research

| File | Active rules before → after | Main changes |
|---|---:|---|
| `claude.yaml` | 69 → 92 | Explicit `claude.app`, `claude.dev`, `claudemcpcontent.com`; CLI/Artifact dependencies; Persona, App Attest and Turnstile; inbound IPv4/IPv6 fallback. |
| `gpt.yaml` | 146 → 150 | `oaistatsig.com`, explicit Azure OpenAI suffix, Turnstile, Persona and App Attest; documented WorkOS frontend entry. |
| `verification.yaml` | 24 → 53 | reCAPTCHA primary hosts, Persona, App Attest, selected Google/Apple/Microsoft sign-in, WorkOS and Stripe web dependencies. |

The first report confused missing explicit entries with missing coverage: `cdn.platform.openai.com` already matched `openai.com`; `frontend-apps-multi-region.workos.com` already matched `workos.com`. Azure OpenAI previously matched the broad `openai` keyword. Its new suffix preserves that intended coverage while removing the keyword. Claude was absent from `gpt.yaml`, **not** from this repository; its separate provider is preserved.

The second report's proposed Claude block omitted the officially documented `claude.app` family. Its optional/commented-out Turnstile approach is not used here: the published shared verification dependencies are enabled because this configuration prioritizes recall. Its distinction between rule matching and actual device routing remains essential.

Four unbounded brand keywords (`claude`, `anthropic`, `openai`, `chatgpt`) were replaced by explicit evidenced host families. Routing a brand-lookalike site does not make it trustworthy; neither does failing to match it block it. The old Bedrock/Vertex keyword compatibility and unrelated TikTok rules are preserved and are not included in a claim of globally precise classification.

`ai.com` remains a legacy extra without claiming current OpenAI ownership. `cloudflare-dns.com` remains to avoid silently changing existing resolver routing; it identifies a general DoH service, not AI traffic. Cloudflare STUN/analytics entries also remain as legacy compatibility, **not** as mandatory Turnstile dependencies. Gemini, Poe, Copilot, TikTok, JetBrains and Zoom were not comprehensively re-audited.

## Load all three providers and control precedence

Merge this fragment into an existing profile; do not replace its nodes, DNS, security rules or proxy groups. Replace `AI_EGRESS` with an **existing** policy selecting the intended stable endpoint. Updating this repository does not refresh a client's downloaded provider cache automatically.

```yaml
rule-providers:
  ai-claude:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Mark-Wu2003/rules/main/claude.yaml
    path: ./rules/claude.yaml
    interval: 86400
  ai-gpt:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Mark-Wu2003/rules/main/gpt.yaml
    path: ./rules/gpt.yaml
    interval: 86400
  ai-verification:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Mark-Wu2003/rules/main/verification.yaml
    path: ./rules/verification.yaml
    interval: 86400

rules:
  # Place before generic ad/tracker rejection, GEOIP/DIRECT and final MATCH.
  # Preserve deliberate security blocks and review any conflicts explicitly.
  - RULE-SET,ai-verification,AI_EGRESS
  - RULE-SET,ai-claude,AI_EGRESS
  - RULE-SET,ai-gpt,AI_EGRESS
  # Keep the rest of your existing rules below.
```

Shared hosts cannot identify which app initiated a request. `www.google.com` also carries Search; GitHub/npm/GCS and Artifact CDNs serve unrelated projects; Persona, Stripe and Cloudflare serve unrelated websites. These matching requests will share the selected route. This is an explicit recall/precision trade-off, not tenant-specific isolation. A load-balancing group or a proxy provider with rotating exits may still produce different public IPs even when every rule names the same policy.

## Validation

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/verify_rules.py --report audit.json
# Optional live source check; performs ordinary HTTPS GETs to five official docs.
python scripts/verify_rules.py --live --report audit-live.json
```

The validator checks YAML structure/duplicates, label-aware suffixes, anchored regexes, IP boundaries, wildcard-family coverage and negative examples. Process-name rules never count as domain coverage. `no-resolve` does not trigger DNS solely to evaluate an IP rule; it is not a guarantee that unknown hostnames are captured.

The GitHub Actions workflow runs offline checks on push and pull requests. A manual workflow run with `live=true` additionally examines five bounded sections: OpenAI's allowlist, Claude Desktop, Claude Code, Anthropic inbound IPs and Persona's allowlist. It fails on uncovered targets, fetch errors, missing/ambiguous headings or suspiciously small parses. It **does not auto-edit rules**, monitor every source, validate the proxy engine, or run on a recurring schedule. The live parser's synthetic tests pass; end-to-end upstream fetching was not validated from the authoring container because outbound DNS was unavailable. A changed page layout can require human review.

## Remaining deployment gates

**No universal 100% claim.** Arbitrary MCP/tool sites, custom enterprise identity providers, gateways, bank 3DS redirects and all third-party model-hosting dependencies remain open-ended. The Stripe subsection is selected web coverage, not Stripe's entire infrastructure list. Phone rules do not control a remote Linux/K8s Claude Code process's egress.

**Voice remains a separate gap.** OpenAI documents changing raw-IP Voice destinations in [chatgpt-voice.json](https://openai.com/chatgpt-voice.json), with UDP/3478 and TCP/443 fallback. That feed was not retrievable during this audit; no guessed or stale Voice CIDRs were inserted. Existing LiveKit domain rules do not prove coverage of IP-literal media traffic. Do not disable all UDP and then claim full Voice coverage.

**Verify on the actual client.** Refresh the three providers, confirm `behavior: classical`, inspect the effective top-to-bottom rules, and test login, API streaming, uploads, Artifacts, CLI installation and ordinary verification. Record the matched provider, policy and actual exit; check for unexpected DIRECT. Preserve WebSocket upgrades and long connections; do not decrypt sensitive login traffic to make routing work. Stash iOS does not support process-name matching; preserved process rules are desktop compatibility only.

**DNS/IPv6/ECH matter.** Keep hostname attribution available to the routing engine. ECH outer SNI, a general resolver hostname or a shared CDN address does not identify the underlying AI service. DNS IPv6 flags alone do not prove all native IPv6 is captured. Handle resolver and proxy-bootstrap routing in the parent profile, separately from service identity. For a work environment requiring no accidental direct egress, enforce that property at the tunnel/firewall boundary and verify it with logs; a domain file alone cannot enforce it.

These changes do not bypass challenges, identity checks, supported-region policies or other service requirements, and cannot guarantee that an account will avoid verification or restriction.

## Primary evidence

Each corpus group links to its specific source. Key references:

- [OpenAI network allowlist, WebSockets and Voice](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps); [OpenAI Persona age verification](https://help.openai.com/en/articles/12652064-age-prediction-in-chatgpt).
- [Claude Desktop network and Artifact requirements](https://code.claude.com/docs/en/desktop); [Claude Code network table](https://code.claude.com/docs/en/corporate-proxy); [Anthropic inbound IPs](https://platform.claude.com/docs/en/api/ip-addresses); [Claude cookie domains](https://privacy.claude.com/en/articles/10023541-what-cookies-does-anthropic-use); [Claude Persona verification](https://support.claude.com/en/articles/14328960-identity-verification-on-claude).
- [Persona allowlist](https://docs.withpersona.com/security); [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/); [hCaptcha](https://docs.hcaptcha.com/); [reCAPTCHA primary/fallback hosts](https://developers.google.com/recaptcha/docs/faq); [Apple enterprise networking/App Attest](https://support.apple.com/en-us/101555).
- [Stripe published domains](https://docs.stripe.com/ips); [Stripe client risk dependencies](https://docs.stripe.com/disputes/prevention/advanced-fraud-detection); OIDC and sign-in references are in the corpus.
- [Stash rule semantics and platform support](https://stash.wiki/en/rules/rule-types); [Cloudflare ECH](https://developers.cloudflare.com/ssl/edge-certificates/ech/).
