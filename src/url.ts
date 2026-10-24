export type UrlKind = "image" | "link";

export interface UrlPolicy {
  allowedHosts: string[];
  allowRelative: boolean;
  images: boolean;
  linkProtocols: string[];
  isAllowed?: (url: URL, kind: UrlKind) => boolean;
}

export type Verdict = { ok: true } | { ok: false; reason: "host" | "protocol" | "relative" | "images-disabled" | "unparseable" };

// Relative URLs resolve against the page that renders the markdown, so they can't carry data to
// another host. They are resolved against this placeholder to tell them apart from absolute ones.
const BASE = "https://relative.llm-markdown-guard.invalid";
const BASE_HOST = new URL(BASE).host;

const NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", colon: ":", sol: "/", bsol: "\\", period: ".",
  quest: "?", equals: "=", num: "#", percnt: "%", lpar: "(", rpar: ")", Tab: "\t", NewLine: "\n", nbsp: " ",
};

/**
 * Turns a markdown link destination into the string a renderer would put in href/src: strips <>,
 * removes backslash escapes and decodes entities. Returns null for anything it can't decode with
 * certainty, which callers treat as not allowed.
 */
export function decodeDestination(raw: string): string | null {
  let s = raw.trim();
  if (s.startsWith("<") && s.endsWith(">")) s = s.slice(1, -1);
  s = s.replace(/\\([!-/:-@[-`{-~])/g, "$1");
  let unknown = false;
  s = s.replace(/&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});/g, (_, body: string) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "�";
    }
    if (body in NAMED) return NAMED[body];
    unknown = true;
    return "";
  });
  return unknown ? null : s;
}

export function matchesHost(patterns: string[], host: string) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return patterns.some((p) => {
    const q = p.toLowerCase();
    return q.startsWith("*.") ? h.endsWith(q.slice(1)) : q === h;
  });
}

export function judge(raw: string, kind: UrlKind, policy: UrlPolicy): Verdict {
  if (kind === "image" && !policy.images) return { ok: false, reason: "images-disabled" };
  const decoded = decodeDestination(raw);
  if (decoded === null) return { ok: false, reason: "unparseable" };
  let url: URL;
  try {
    url = new URL(decoded, BASE);
  } catch {
    return { ok: false, reason: "unparseable" };
  }
  if (url.host === BASE_HOST && url.protocol === "https:") {
    // Shown as text by a renderer that doesn't take this for a link, "www.evil.com" or
    // "//evil.com" would be auto-linked to another host. Real relative links don't look like that.
    if (/www\.|\/\/|@|:/i.test(decoded)) return { ok: false, reason: "unparseable" };
    return policy.allowRelative ? { ok: true } : { ok: false, reason: "relative" };
  }
  // Kept URLs are written out verbatim. If some renderer shows one as text instead of a link, a
  // second URL or an email inside it would be auto-linked on its own.
  // (For mailto: the address itself is the one email allowed.)
  const rest = decoded.replace(/^mailto:[^?@]*@[^?]*/i, "").replace(/^[a-z][a-z0-9+.-]*:(\/\/[^/?#]*)?/i, "");
  if (/(?:https?|ftp):\/\/|mailto:|www\.|\/\/|[\w.+-]@[\w-]+\.\w/i.test(rest)) return { ok: false, reason: "unparseable" };
  const protocols = kind === "image" ? ["http:", "https:"] : policy.linkProtocols;
  if (!protocols.includes(url.protocol)) return { ok: false, reason: "protocol" };
  const host = url.protocol === "mailto:" ? (url.pathname.split("?")[0].split("@").pop() ?? "") : url.hostname;
  if (host && matchesHost(policy.allowedHosts, host)) return { ok: true };
  if (policy.isAllowed?.(url, kind)) return { ok: true };
  return { ok: false, reason: "host" };
}
