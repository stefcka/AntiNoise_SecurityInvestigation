# Local model setup

The AI investigator runs on a model you host. Incident data (identities, IPs, file names, mail
metadata) goes from your server to your model and back, and nowhere else.

```
Microsoft Graph / O365 / VM exports ──► your server ──► deterministic detection + scoring
                                              │
                                              ▼
                                   local model (Ollama, llama.cpp, vLLM)
                                              │   explanation only, then validated
                                              ▼
                                           analyst
```

The only outbound connections the server makes are to Microsoft (collecting telemetry, and approved
response actions). The dashboard loads no external fonts or scripts.

## Option A: Ollama (simplest)

```bash
# install from https://ollama.com, then:
ollama pull qwen2.5:7b
ollama serve            # usually already running as a service on port 11434
```

`.env`:

```
LLM_PROVIDER=local
LOCAL_LLM_API=ollama
LOCAL_LLM_BASE_URL=http://localhost:11434
LOCAL_LLM_MODEL=qwen2.5:7b
LOCAL_LLM_CONTEXT=16384
```

The app uses Ollama's native `/api/chat` and sends `num_ctx` with every request. This matters:
Ollama's default context window is only a few thousand tokens, the largest sample incident needs
about 4,400, and an oversized prompt is cut silently rather than rejected. `LOCAL_LLM_CONTEXT`
controls the window; the app also shrinks the prompt itself (context events first) if an incident
would not fit, and records that it did.

## Option B: any OpenAI-compatible server

llama.cpp `llama-server`, vLLM, and LM Studio all expose `/v1/chat/completions`.

```
LLM_PROVIDER=local
LOCAL_LLM_API=openai
LOCAL_LLM_BASE_URL=http://localhost:8080        # no /v1 suffix
LOCAL_LLM_MODEL=<the model name the server reports at /v1/models>
LOCAL_LLM_API_KEY=                              # only if you started the server with a key
```

Set the context size on the server itself (for example `--ctx-size 16384` for llama.cpp or
`--max-model-len 16384` for vLLM). If the server rejects JSON mode, the app retries without it.

## Choosing a model

Pick an instruction-tuned model that follows a JSON schema reliably. As a rough guide for 4-bit
quantized models: 7–8B needs about 6 GB of GPU memory or RAM, 14B about 10 GB, 32B about 20 GB.
On a laptop CPU expect tens of seconds to a few minutes per incident; with a GPU, a few seconds.

Try two or three candidates on the sample incidents and keep the one with the fewest problems:

```bash
python scripts/eval_local_model.py
LOCAL_LLM_MODEL=llama3.1:8b python scripts/eval_local_model.py
```

It reports time per incident, unusable outputs, and how many items the validator removed. A model
that frequently falls back or cites events that don't exist is the wrong model, whatever its size.

## What happens when the model is slow, wrong, or down

- Incidents, evidence, scores and response options appear immediately. AI assessments run one at a time
  in a background worker, and incident pages refresh themselves until theirs is ready.
- Output that isn't valid JSON, times out, or hits the token limit is replaced by the deterministic summary,
  labelled as such, with the reason shown.
- Findings citing unknown events and recommendations outside the allowed actions are removed and listed.
  Small models follow injected instructions more readily than large ones; the validator is what makes
  that safe, not the model.
- Every assessment records `local:<model>`, the prompt version, and a hash of the exact input.

## Running the model on another machine

Keep the model server on a private network segment and let only the app server reach it. Ollama listens
on localhost by default; if you set `OLLAMA_HOST=0.0.0.0` so another machine can reach it, firewall the
port, because the API has no authentication.

## Hosted model instead (optional)

`LLM_PROVIDER=anthropic` with `ANTHROPIC_API_KEY` sends incident data to a hosted API. `LLM_PROVIDER=none`
disables the model entirely.
