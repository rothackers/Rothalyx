# AI Integration

Zara treats AI as an optional analysis layer. The reverse engineering pipeline still runs without a hosted model, and the desktop app can remain in heuristic-only mode.

## Desktop Settings Flow

The desktop application exposes provider configuration through `Settings -> AI`.

That screen supports:

- heuristic-only mode
- OpenAI
- Anthropic
- Gemini
- OpenAI-compatible gateways
- local LLM endpoints

The saved configuration covers:

- provider
- model
- endpoint URL
- organization and project fields when the provider supports them
- request timeout
- max functions per run
- daily remote request cap
- fallback to heuristics when the provider fails

## Secret Storage

Non-secret configuration is stored in normal desktop settings.

Secrets are stored separately through the host operating system:

- Windows: Credential Manager
- macOS: Keychain
- Linux: Secret Service through `secret-tool`

If secure storage is unavailable, Zara does not silently save keys in plain-text app settings. Users can still rely on environment variables or install the required host keyring tooling.

## Provider Mapping

The current provider mapping is:

- OpenAI  
  Responses API
- Anthropic  
  Messages API
- Gemini  
  `generateContent`
- OpenAI-compatible and local LLM  
  chat-completions style endpoints

Inside Zara, provider responses are normalized into a single internal insight shape:

- suggested function name
- short summary
- analyst hints
- pattern detections
- vulnerability hints

## Request and Response Pipeline

The model-backed flow is:

1. run normal static analysis
2. choose a bounded set of candidate functions
3. build a compact function-context payload
4. submit the request to the selected provider
5. normalize the provider response into Zara insight records
6. persist those results with the analysis run

The parser is deliberately conservative. If a provider response is malformed or unusable, Zara falls back to the existing heuristic path instead of blocking analysis.

## Cost and Rate Limits

Hosted provider billing stays with the user’s own key or account. Zara controls request size rather than provider-side pricing.

The desktop flow currently limits:

- max functions per run
- request timeout
- optional daily remote request cap

That keeps requests bounded and predictable without trying to hard-code token pricing that changes over time.

## Local LLM Mode

Local LLM mode keeps the same desktop workflow while sending requests to a local endpoint.

In that mode:

- requests are sent to a local OpenAI-compatible endpoint
- hosted-provider billing does not apply
- the same bounded function-selection and structured parsing path is used

That keeps the user experience consistent across hosted and local deployments.
