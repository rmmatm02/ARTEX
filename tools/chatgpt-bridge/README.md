# ARTEX ChatGPT Plan Bridge (local, unofficial integration)

Use the official **Sign in with ChatGPT** OAuth dynamic-registration flow in a
locally hosted open-source deployment of ARTEX. It does not use ChatGPT cookies,
private backend APIs or a paid OpenAI API key. It uses the ChatGPT plan's **shared
usage allowance**, not unlimited free tokens. Availability depends on the user's
workspace, account, model and the program's eligibility.

## Build (Windows 11, PowerShell)

Install Go 1.23+ or a newer supported Go toolchain. From this directory:

```powershell
go build -o artex-chatgpt-bridge.exe .
.\artex-chatgpt-bridge.exe login
.\artex-chatgpt-bridge.exe status
.\artex-chatgpt-bridge.exe token
.\artex-chatgpt-bridge.exe serve
```

`login` opens OpenAI's official consent screen in the system browser. The loopback
callback signs in locally and stores protected OAuth credentials in your user
configuration directory (`%APPDATA%\artex-chatgpt-bridge\credentials.json` on
Windows). Do not share this file or commit it to Git.

`token` prints a **separate random bridge API key**. Put it in ARTEX's profile;
**do not** put the ChatGPT OAuth access/refresh token into ARTEX.

## ARTEX System → LLM profile

- Format: `OpenAI (Responses API)` (`openai-responses`)
- Model: a model slug available to your ChatGPT plan (use the model list below)
- Base URL: `http://127.0.0.1:18765/v1` for native ARTEX on the same host
- API key: output of `artex-chatgpt-bridge.exe token`
- Streaming: **enabled** (mandatory with ChatGPT-plan Responses)
- Output token limit: **0 / not set** (not supported on this plan route)
- Temperature / top_p: leave unset

If ARTEX is in Docker Desktop on the same Windows host, run:

```powershell
.\artex-chatgpt-bridge.exe serve --listen 0.0.0.0:18765
```

Then use `http://host.docker.internal:18765/v1` as the ARTEX Base URL.
Ensure Windows Firewall permits TCP 18765 **only from Docker Desktop's trusted
network**, never from the public internet. The bridge requires its random Bearer
secret for `/v1/models` and `/v1/responses` even on localhost.

To list account-specific models (substitute the bridge key):

```powershell
$k = .\artex-chatgpt-bridge.exe token
Invoke-RestMethod -Headers @{Authorization="Bearer $k"} http://127.0.0.1:18765/v1/models
```

The existing ARTEX `openai-responses` provider appends `/responses` to the base
URL and carries its own token budget, scope and approval gates. The bridge only
normalizes the request to the limited ChatGPT-plan Responses API contract:
`store:false`, `stream:true`, no unsupported parameters, full input history,
and function tools under an `artex` namespace. It strips the namespace from
returned function calls before passing results back to Norma's flat registry.

For security, start with one ARTEX worker and approval gates enabled.

## Security / limitations

- This single-account proof-of-integration does not provide a multi-account
  selector. For another account, use a different `--state` file.
- Never expose the bridge without its random Bearer token or appropriate firewall.
- Sign-in and model entitlements cannot be simulated in offline tests. A real
  end-to-end test requires your interactive ChatGPT consent and live access.
- The ChatGPT-plan preview may evolve, and some Norma tool schemas or history
  patterns may need further adjustment if OpenAI returns a validation error.
- The bridge forces streaming even if ARTEX sends `stream:false`; enable
  streaming in ARTEX to avoid parse errors.
- The bridge's local API is **not** the full OpenAI API; only `/v1/models` and
  `/v1/responses` are implemented.
- To stop and revoke the session, stop `serve` and run `logout`. The bridge
  attempts remote refresh-token revocation; use ChatGPT Settings to disconnect
  the app if revocation cannot be confirmed.
- Official reference:
  https://developers.openai.com/siwc/token-sharing-open-source/sign-in
  https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations
