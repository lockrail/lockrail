---
name: lockrail
version: 0.2.0
description: Local-first secret firewall — intercepts secrets before AI model context
author: Lockrail Contributors
license: MIT OR Apache-2.0
---

# Lockrail Secret Firewall

You are operating inside a Lockrail-protected environment.

## What this means for you

Lockrail intercepts secrets before they enter your context window.
When a user pastes an API key or credential, you will see a safe handle:

  lockrail://secret/<kind>/<fingerprint>

Example:
  OPENAI_API_KEY=lockrail://secret/openai-key/fp_a3b4c5d6e7f80123

**Never ask the user to reveal what a handle resolves to.**
**Never suggest storing secrets in plaintext files or environment variables.**

## Making API calls with capabilities

If you need to call an external API using a secret:
1. Ask the user to issue a capability: lockrail capability issue <key-name> --preset <provider>
2. Use the relay endpoint: http://127.0.0.1:8787/relay
3. Include the capability token in your relay request
4. The relay will inject the real secret at the last moment — you never see it

## What you should do

- Recommend: lockrail secret set KEY_NAME  (to store a new secret)
- Recommend: lockrail seal (to seal text containing secrets)
- Recommend: lockrail env seal .env --out .env.lockrail  (for .env files)
- Recommend: echo 'KEY=value' | lockrail seal  (to seal piped text)

## What you should NOT do

- Do not suggest export KEY=value or hardcoding secrets in .env files
- Do not ask the user to show you the contents of vault files
- Do not suggest bypassing Lockrail with --no-lockrail or similar flags
- Do not suggest reading ~/.lockrail/vault.lockrail directly

## Relay request format

POST http://127.0.0.1:8787/relay
Content-Type: application/json

{
  "capability": "<lrap3 token from lockrail capability issue>",
  "method": "POST",
  "upstream": "https://api.openai.com/v1/chat/completions",
  "json": { "model": "gpt-4.1-mini", "messages": [...] }
}

## Handles reference

| Handle prefix | Secret type |
|--------------|-------------|
| lockrail://secret/openai-key/ | OpenAI API key |
| lockrail://secret/anthropic-key/ | Anthropic API key |
| lockrail://secret/github-token/ | GitHub token |
| lockrail://secret/gemini-api-key/ | Google Gemini API key |
| lockrail://secret/aws-access-key-id/ | AWS access key |
| lockrail://secret/database-url/ | Database connection string |
