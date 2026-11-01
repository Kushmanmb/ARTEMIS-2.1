# Connect ARTEMIS-2.1 to OXCON (read-only Phase 1)

This repository includes an authenticated HTTP service for the existing
`GET /api/artemis/status` endpoint in the OXCON Cloudflare Worker.

**This is a source-audit snapshot only.** The actual Base/GEN0X factory event
monitor is **not configured** in this release. The UI will report that state
rather than inventing deployments, block coverage, or findings.

## Before deploying

- Merge the snapshot API PR after the Python tests pass.
- Use a **dedicated Render service** for `Kushmanmb/ARTEMIS-2.1`.
- Do not deploy or change any existing Recovery Forward Foundation services.
- Keep `bot.auditor --fix`, GitHub auto-fixes, wallet transactions, and
  the `bot.auditor --monitor` CLI disabled in this web service.
- Verify authorization, billing plan, domain, and environment before
  enabling a public-facing service.

## Render service settings

| Field | Value |
| --- | --- |
| Repository | `https://github.com/Kushmanmb/ARTEMIS-2.1` |
| Branch | `main` |
| Runtime | Python |
| Root directory | Repository root |
| Build | `pip install -r requirements.txt` |
| Start | `python -m bot.snapshot_api` |
| Health check | `/healthz` |
| Port | Use Render's `PORT`; default 10000 for local work |

Create a **secret environment variable** `ARTEMIS_API_KEY` with a unique,
random 32+ character value. Generate it using a reputable password manager or
secure random generator. **Never commit, paste into a chat, or send to a
browser**. The service returns a non-ready health status until the key is set.

Allow Render to assign a dedicated HTTPS service URL.

## OXCON Cloudflare Worker settings

In **Workers & Pages → oxcon-intel-api-production → Settings →
Variables and Secrets**:

1. Add `ARTEMIS_API_URL` as the Render service's exact HTTPS origin,
   e.g. `https://your-artemis-service.onrender.com` (no trailing path).
2. Add `ARTEMIS_API_KEY` as a **secret**, with the *same* value as Render.
3. Preserve all existing Access secrets, GitHub App secrets, D1 bindings,
   rate limits and `ETH_RPC_URL`. Do not replace the Worker.
4. Deploy the updated secret configuration through the normal Cloudflare UI.

The Worker sends the Bearer key **server-to-server** and verifies the
upstream response schema. Customer accounts cannot call this internal endpoint;
it is owner-only. Browsers never receive the Render key.

## Acceptance checklist

1. `GET /healthz` on Render returns `ok: true` with a 200.
2. `GET /v1/snapshot` without the key returns 401 (never leak source data).
3. In authenticated OXCON Operations, **Refresh ARTEMIS** displays:
   - Source audit: `ready`, file count, real findings and timestamp.
   - GEN0X deployment monitor: `not_configured` with no fabricated blocks.
4. Existing OXCON GitHub, ENS, Bloksmith and bytecode tools still work.
5. No new wallet transaction, source-file mutation, or automatic fix occurs.

## Later phase: actual factory-event monitoring

Before enabling monitoring, verify the **actual deployed** GEN0X MotherContract
address on Base (a Basename is not itself a factory contract), its event ABI,
start block, RPC limits, chain ID and persistent storage. Monitor only confirmed
events and track gaps/reorgs; never claim continuous coverage from a
best-effort API snapshot. Keep explicit authorization for any write action.

## Local development

```sh
python -m pytest tests/test_snapshot_api.py -q
ARTEMIS_API_KEY='<random, long local test secret>' python -m bot.snapshot_api
```

The service reads `contracts/*.sol`, computes fresh heuristic findings with
`auto_fix=False`, exposes no report without a strong Bearer key, and does not
run any blockchain polling in the background.
