import { judge, matchesHost, type UrlKind, type UrlPolicy } from "./url.js";

export interface GuardOptions {
  /** Hosts whose links and images are kept. "*.example.com" matches subdomains only. Default: none. */
  allowedHosts?: string[];
  /** Keep relative URLs ("/docs", "#top"). They resolve to your own page. Default: true. */
  allowRelative?: boolean;
  /** Keep images on allowed hosts. false removes every image. Default: true. */
  images?: boolean;
  /** Link schemes that may be kept. Images are always limited to http and https. Default: ["http:", "https:"]. */
  linkProtocols?: string[];
  /** Raw HTML: "escape" shows it as text, "keep" passes it through untouched (unsafe). Default: "escape". */
  html?: "escape" | "keep";
  /** Bare URLs that GFM turns into links: "escape" stops the auto-linking, "keep" leaves them. Default: "escape". */
  bareUrls?: "escape" | "keep";
  /** Last word on a URL that isn't on allowedHosts. Return true to keep it. */
  isAllowed?: (url: URL, kind: UrlKind) => boolean;
  /** Text that replaces a removed image. Default: the alt text. */
  replaceImage?: (alt: string, url: string) => string;
}

export interface Finding {
  kind: "image" | "link" | "definition" | "autolink" | "bare-url" | "html";
  url: string;
  reason: string;
}

export interface Result {
  markdown: string;
  removed: Finding[];
}

type Ctx = { policy: UrlPolicy; opts: GuardOptions; removed: Finding[]; keep: string[] };

const OPEN = "\uE000";
const CLOSE = "\uE001";
const PLACEHOLDER = /\uE000(\d+)\uE001/g;

// Link text may hold one level of nested brackets, enough for a linked image: [![alt](img)](href).
const TEXT = String.raw`(?:[^\[\]\\]|\\[\s\S]|\[(?:[^\[\]\\]|\\[\s\S])*\])*`;
const DEST = String.raw`<(?:[^<>\n\\]|\\.)*>|(?:[^\s()\\]|\\.|\((?:[^\s()\\]|\\.)*\))*`;
const TITLE = String.raw`"(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*'|\((?:[^()\\]|\\[\s\S])*\)`;
const INLINE = new RegExp(String.raw`(!?)\[(${TEXT})\]\([ \t]*\n?[ \t]*(${DEST})(?:\s+(?:${TITLE}))?\s*\)`, "g");
const DEFINITION = new RegExp(
  // Only an optional title may follow the URL; with anything else renderers show the line as text.
  String.raw`^ {0,3}\[(?!\^)((?:[^\[\]\\\n]|\\[^\n]){1,999})\]:[ \t]*\n?[ \t]*(<[^<>\n]*>|\S+)(?:(?:[ \t]+|[ \t]*\n[ \t]*)(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*(?=\n|$)`,
  "gm",
);
const AUTOLINK = /(?<=(?:^|[^\\])(?:\\\\)*)<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)>/g;
// What GFM, markdown-it (linkify) and marked turn into links without any markup. Matched anywhere
// in a word, because marked links "www." even mid-word and markdown-it links "//host". Each match
// stops where another URL starts, so an allowed URL can't vouch for one glued onto its end.
// marked runs a URL on through ">", quotes and backticks, up to whitespace or "<".
const BARE_URL = /(?:(?:https?|ftp):\/\/|mailto:|www\.|(?<![:/])\/\/(?=[A-Za-z0-9[]))[^\s<\uE000\uE001]*?(?=[\s<\uE000\uE001]|(?:https?|ftp):\/\/|mailto:|www\.|\/\/|$)/gi;
// Each "@" that could join a local part to a domain, judged on its own: "a@x.coma@evil.com" holds two.
const EMAIL_AT = /(?<=[A-Za-z0-9._+-])@(?=([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+))/g;

function stash(ctx: Ctx, s: string) {
  ctx.keep.push(s);
  return OPEN + (ctx.keep.length - 1) + CLOSE;
}

function restore(ctx: Ctx, s: string) {
  for (let i = 0; i < 10 && s.includes(OPEN); i++) s = s.replace(PLACEHOLDER, (_, n: string) => ctx.keep[Number(n)]);
  return s;
}

/** Adds a backslash before each match unless it is already escaped. */
function escapeAt(s: string, re: RegExp) {
  return s.replace(re, (m: string, slashes: string) => (slashes.length % 2 ? m : slashes + "\\" + m.slice(slashes.length)));
}

function plain(text: string) {
  // Removed constructs leave their text behind; a trailing "!" would turn a following link into an image.
  return text.replace(/(\\*)!$/, (m, slashes: string) => (slashes.length % 2 ? m : slashes + "\\!"));
}

/**
 * Inline code spans are left exactly as written, since renderers never turn their contents into
 * links. That only holds while every renderer agrees where a span starts and ends. They don't
 * after a run that sits inside a bare URL or link destination (marked and markdown-it run the URL
 * through it, micromark opens a span), or a span that crosses a line or holds "|" (a heading, list
 * or table cell boundary may split it). After any of those, the rest of the paragraph's backticks
 * are treated as plain text.
 */
function protectCode(ctx: Ctx, s: string, prior: string) {
  let out = "";
  let trusted = true;
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (c === "\\") {
      out += s.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (c !== "`") {
      out += c;
      i++;
      continue;
    }
    let n = 1;
    while (s[i + n] === "`") n++;
    const span = trusted ? codeSpanAt(s, i, n, ctx.opts.html ?? "escape", prior + s.slice(0, i)) : null;
    if (span === "ambiguous") trusted = false;
    if (typeof span === "number") {
      out += stash(ctx, s.slice(i, span));
      i = span;
    } else {
      out += s.slice(i, i + n);
      i += n;
    }
  }
  return out;
}

/**
 * For a backtick run at i: the end of the code span it opens, null if it opens none, or
 * "ambiguous" if renderers disagree. Shared with the stream so both make the same call.
 */
export function codeSpanAt(s: string, i: number, n: number, html: "escape" | "keep", paragraph: string, limit = s.length): number | null | "ambiguous" {
  const before = s.slice(Math.max(0, i - 4096), i);
  if (inBareUrl(s, i) || /\]\([^)\s]*$/.test(before)) return "ambiguous";
  // Renderers only reliably agree on spans set off from their surroundings, outside any link
  // text or tag. Anything glued to other syntax is treated as text, which is always safe.
  if (i > 0 && !/[\s("'*_~\u0001]/.test(s[i - 1])) return "ambiguous";
  // With html "escape" every "<" ends up as "&lt;", so only "keep" can leave a tag open.
  if (unclosed(before, "[", "]") || (html === "keep" && unclosed(before, "<", ">"))) return "ambiguous";
  const close = findRun(s, i + n, n, limit);
  if (close < 0) return null;
  const after = s[close + n];
  if (after !== undefined && !/[\s.,;:!?)"'*_~]/.test(after)) return "ambiguous";
  const body = s.slice(i, close + n);
  if (body.includes("\n") || /(^|[^\\])\|/.test(body)) return "ambiguous";
  // marked matches emphasis before code spans: a "*" earlier in the paragraph pairs with one
  // inside the span and breaks it open. `paragraph` is the paragraph's text up to the span.
  // Only delimiters that can open (before) and close (inside) count: "_" inside a word, as in
  // MAX_SIZE, never does.
  if (/\*+(?=\S)/.test(paragraph) && /(?<=\S)\*+/.test(body.slice(n))) return "ambiguous";
  if (/(?:^|[^A-Za-z0-9_])_+(?=\S)/.test(paragraph) && /(?<=\S)_+(?![A-Za-z0-9_])/.test(body.slice(n))) return "ambiguous";
  return close + n;
}

function unclosed(s: string, open: string, close: string) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === open) depth++;
    else if (s[i] === close && depth > 0) depth--;
  }
  return depth > 0;
}

const URL_SO_FAR = /(?:(?:https?|ftp):\/\/|mailto:|www\.|(?<![:/])\/\/(?=[A-Za-z0-9[]))[^\s<\uE000\uE001]*$/i;

/**
 * Whether position i sits inside a bare URL. Backticks there are part of the URL (marked and
 * markdown-it link straight through them, and escaping a blocked URL escapes them too), so they
 * never open a code span.
 */
export function inBareUrl(s: string, i: number) {
  return URL_SO_FAR.test(s.slice(Math.max(0, s.lastIndexOf(" ", i) - 2048), i));
}

export function findRun(s: string, from: number, n: number, limit = s.length) {
  for (let i = from; i < limit; i++) {
    if (s[i] !== "`") continue;
    let m = 1;
    while (s[i + m] === "`") m++;
    if (m === n && i + m <= limit) return i;
    i += m - 1;
  }
  return -1;
}

function linkOrImage(ctx: Ctx, bang: string, text: string, dest: string, whole: string) {
  const kind: UrlKind = bang ? "image" : "link";
  const verdict = judge(dest, kind, ctx.policy);
  if (verdict.ok) {
    // Only the "](url" part is set aside verbatim. The text (which can hold a link of its own) and
    // the title stay in line for the passes below, so they're defanged too: if some renderer
    // doesn't read this as a link after all, it shows them as text, URLs and all.
    const textEnd = bang.length + 1 + text.length;
    const destEnd = whole.indexOf(dest, textEnd + 2) + dest.length;
    return bang + "[" + inline(ctx, text) + stash(ctx, whole.slice(textEnd, destEnd)) + whole.slice(destEnd);
  }
  ctx.removed.push({ kind, url: dest, reason: verdict.reason });
  if (kind === "image") return plain(ctx.opts.replaceImage ? ctx.opts.replaceImage(text, dest) : text);
  return plain(text);
}

function inline(ctx: Ctx, s: string) {
  for (let pass = 0; pass < 20; pass++) {
    const next = s.replace(INLINE, (whole, bang: string, text: string, dest: string) => linkOrImage(ctx, bang, text, dest, whole));
    if (next === s) break;
    s = next;
  }
  return s;
}

function paragraph(ctx: Ctx, s: string, prior = "") {
  s = s.replace(/[\uE000\uE001]/g, "\ufffd");
  // A definition can't interrupt a paragraph: it counts only at the top, or straight after
  // another definition. Anywhere else it is text, and is handled as text below.
  let defsEnd = 0;
  s = s.replace(DEFINITION, (whole, label: string, dest: string, offset: number, all: string) => {
    if (all.slice(defsEnd, offset).trim() !== "") return whole;
    defsEnd = offset + whole.length;
    const verdict = judge(dest, "link", ctx.policy);
    if (verdict.ok) {
      // As with links: the URL is kept verbatim, the label and title are defanged in case a
      // renderer shows this line as text.
      const destEnd = whole.indexOf(dest, whole.indexOf("]:")) + dest.length;
      const safeLabel = ctx.opts.html === "keep" ? defang(label) : defang(label).replace(/<(?=[A-Za-z/!?])/g, "&lt;");
      const head = whole.slice(0, destEnd).replace(label, () => safeLabel);
      return stash(ctx, head) + whole.slice(destEnd);
    }
    ctx.removed.push({ kind: "definition", url: dest, reason: verdict.reason });
    return "";
  });
  s = s.replace(AUTOLINK, (whole, target: string) => {
    const url = target.includes(":") ? target : "mailto:" + target;
    const verdict = judge(url, "link", ctx.policy);
    // A second URL inside would be linked on its own by a renderer that shows this as text.
    const glued = (target.match(new RegExp(BARE_URL.source, "gi")) ?? []).length > 1;
    if (verdict.ok && !glued) return stash(ctx, whole);
    ctx.removed.push({ kind: "autolink", url, reason: verdict.ok ? "unparseable" : verdict.reason });
    return escapeBare(target);
  });
  s = protectCode(ctx, s, prior);
  s = inline(ctx, s);

  if (ctx.opts.html !== "keep") {
    s = s.replace(/<(?=[A-Za-z/!?])/g, (lt, offset: number, all: string) => {
      ctx.removed.push({ kind: "html", url: all.slice(offset, offset + 80).split(/[\s>]/)[0], reason: "html" });
      return "&lt;";
    });
  }
  if (ctx.opts.bareUrls !== "keep") {
    s = s.replace(BARE_URL, (m) => {
      const url = /^www\./i.test(m) ? "http://" + m : m.startsWith("//") ? "http:" + m : m;
      if (judge(url, "link", ctx.policy).ok) {
        // Renderers disagree on where a bare URL ends, so only scheme and host are kept as is.
        // The rest stays in the text, where any URL or email that a renderer might split off
        // and link on its own is escaped below.
        const head = /^(?:(?:https?|ftp):\/\/|\/\/|www\.)[^/?#\s\\]*/i.exec(m)![0];
        return stash(ctx, head) + m.slice(head.length);
      }
      ctx.removed.push({ kind: "bare-url", url: m, reason: "host" });
      return escapeBare(m);
    });
    s = s.replace(EMAIL_AT, (at, domain: string, offset: number) => {
      if (matchesHost(ctx.policy.allowedHosts, domain) && ctx.policy.linkProtocols.includes("mailto:")) return at;
      ctx.removed.push({ kind: "bare-url", url: "mailto:…@" + domain, reason: "host" });
      return "\\@";
    });
  }

  // Anything the patterns above did not recognise but a renderer might: escape it rather than
  // guess. Kept constructs are already stashed, so only unvetted syntax is touched.
  s = escapeAt(s, /(\\*)\](?=\()/g);
  s = escapeAt(s, /(?<=^ {0,3})(\\*)\[(?=[^\n]*\]:)/gm);
  if (ctx.policy.images === false) s = escapeAt(s, /(\\*)!(?=\[)/g);
  return s;
}

/** Stops every URL and email in a piece of text from being auto-linked, without changing how it reads. */
function defang(text: string) {
  return text.replace(BARE_URL, escapeBare).replace(EMAIL_AT, "\\@");
}

function escapeBare(url: string) {
  return url
    .replace(/[\\`*_[\]()<>!|@]/g, "\\$&")
    .replace(/:\/\//g, "\\://")
    .replace(/(?<!:)\/\//g, "/\\/")
    .replace(/(www)\./gi, "$1\\.")
    .replace(/(mailto):/gi, "$1\\:");
}

export function makeContext(opts: GuardOptions, removed: Finding[]): Ctx {
  return {
    opts,
    removed,
    keep: [],
    policy: {
      allowedHosts: opts.allowedHosts ?? [],
      allowRelative: opts.allowRelative ?? true,
      images: opts.images ?? true,
      linkProtocols: opts.linkProtocols ?? ["http:", "https:"],
      isAllowed: opts.isAllowed,
    },
  };
}

export type Fence = { char: string; len: number; indent: number };

const FENCE_OPEN = /^( {0,3})(`{3,}|~{3,})([^\n]*)$/;

/**
 * Fenced code is passed through untouched, so a fence is only trusted where every renderer
 * agrees it is one. Callers must also check that no "[" is left open above it (see bracketDepth):
 * marked lets a link label run on across lines and swallow the opening fence.
 */
export function fenceOpener(line: string): Fence | null {
  const m = FENCE_OPEN.exec(line.replace(/\r?\n$/, ""));
  if (!m) return null;
  if (m[2][0] === "`" && m[3].includes("`")) return null;
  return { char: m[2][0], len: m[2].length, indent: m[1].length };
}

/**
 * How a line inside a fence relates to it. "close" is a closer every renderer accepts;
 * "loose-close" only marked accepts ("```~~~"); "exit" is a line indented less than an indented
 * opener, which ends the fence if it sits in a list item but not otherwise.
 */
export function fenceEnd(line: string, fence: Fence): "content" | "close" | "loose-close" | "exit" {
  const bare = line.replace(/\r?\n$/, "");
  if (closes(bare, fence, /^ {0,3}(`{3,}|~{3,})[ \t]*$/)) return "close";
  if (closes(bare, fence, /^ {0,3}(`{3,}|~{3,})[`~]*[ \t]*$/)) return "loose-close";
  if (fence.indent > 0 && bare.trim() !== "" && bare.search(/\S/) < fence.indent) return "exit";
  return "content";
}

function closes(line: string, fence: Fence, re: RegExp) {
  const m = re.exec(line);
  return !!m && m[1][0] === fence.char && m[1].length >= fence.len;
}

/**
 * Follows fenced code blocks line by line, shared by sanitize() and the stream so both decide the
 * same way. Code inside a fence passes through untouched, so everything here leans towards "text":
 * a fence ends as soon as any renderer would end it, and after an ending that not all renderers
 * agree on, it is in limbo: some renderer may still be inside it, so nothing is trusted as a new
 * fence until a line that closes it for everyone.
 */
export class FenceTracker {
  fence: Fence | null = null;
  private limbo: Fence | null = null;

  /** `depth` is the number of "[" left open in the text before this line. */
  classify(line: string, depth: number): "code" | "text" {
    if (this.fence) {
      const end = fenceEnd(line, this.fence);
      if (end !== "exit") {
        if (end !== "content") {
          this.limbo = end === "loose-close" ? this.fence : null;
          this.fence = null;
        }
        return "code";
      }
      this.limbo = this.fence;
      this.fence = null;
    }
    if (this.limbo) {
      if (fenceEnd(line, this.limbo) === "close") this.limbo = null;
      return "text";
    }
    const opener = fenceOpener(line);
    if (!opener) return "text";
    if (depth > 0 || line.includes("|")) {
      // Not trusted: marked may read it as part of a link label, and markdown-it as a table
      // header if the next line looks like "| - |". CommonMark renderers do open a fence here,
      // so it is limbo until it closes for them too.
      this.limbo = opener;
      return "text";
    }
    this.fence = opener;
    return "code";
  }
}

/** Brackets left open after `text`, starting from `depth`. Escaped brackets don't count. */
export function bracketDepth(text: string, depth = 0) {
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\\") i++;
    else if (text[i] === "[") depth++;
    else if (text[i] === "]" && depth > 0) depth--;
  }
  return depth;
}

/** Sanitizes text that holds no fenced code block. Paragraphs are handled one at a time. */
/** `prior` is the start of the first paragraph when an earlier piece of the stream already sent it. */
export function sanitizeText(ctx: Ctx, text: string, atLineStart = true, prior = "") {
  // Text that continues a line must not be read as starting one (a definition, say). A marker
  // character in front stops "^" from matching and is taken off again afterwards.
  const out = (atLineStart ? text : "\u0001" + text)
    .split(/(\n[ \t]*\n)/)
    .map((part, i) => (i % 2 ? part : restore(ctx, paragraph(ctx, part, i === 0 ? prior : ""))))
    .join("");
  return atLineStart ? out : out.slice(1);
}

/**
 * Removes links and images that point outside `allowedHosts` from markdown written by a model,
 * so a prompt-injected response can't leak data through a URL the chat UI loads or the user clicks.
 */
export function sanitize(markdown: string, options: GuardOptions = {}): Result {
  const removed: Finding[] = [];
  const ctx = makeContext(options, removed);
  const lines = markdown.split(/(?<=\n)/);
  let out = "";
  let text = "";
  let depth = 0;
  const fences = new FenceTracker();
  for (const line of lines) {
    const inFence = !!fences.fence;
    if (fences.classify(line, depth) === "code") {
      if (!inFence) {
        out += sanitizeText(ctx, text);
        text = "";
      }
      out += line;
    } else {
      text += line;
      depth = bracketDepth(line, depth);
    }
  }
  out += sanitizeText(ctx, text);
  return { markdown: out, removed };
}
