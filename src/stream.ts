import { bracketDepth, codeSpanAt, FenceTracker, makeContext, sanitizeText, type Finding, type GuardOptions } from "./sanitize.js";

export interface StreamOptions extends GuardOptions {
  /** Most characters held back while waiting for a construct to finish. Default: 4096. */
  maxHold?: number;
}

export interface MarkdownGuardStream {
  /** Feeds the next chunk and returns the text that is now safe to append to the output. */
  write(chunk: string): string;
  /** Flushes whatever is still held back. Call once when the model finishes. */
  end(): string;
  /** Everything removed so far. */
  readonly removed: Finding[];
}

const BLANK_LINE = /\n[ \t]*\n/g;

function paragraphEnd(s: string, from: number) {
  BLANK_LINE.lastIndex = from;
  const m = BLANK_LINE.exec(s);
  return m ? m.index : s.length;
}

function matching(s: string, from: number, open: string, close: string, limit: number) {
  let depth = 0;
  for (let i = from; i < limit; i++) {
    const c = s[i];
    if (c === "\\") i++;
    else if (c === open) depth++;
    else if (c === close && --depth === 0) return i;
  }
  return -1;
}

/**
 * Finds where the first construct that might still be growing starts (an unclosed bracket, a
 * link missing its ")", an unclosed code span or autolink) and the spans of finished ones. Text
 * before `open` can be sanitized and sent without the rest of the stream changing how it renders.
 * A construct that a blank line has already cut off can't become a link any more, so it counts as
 * plain text.
 */
function scan(s: string, html: "escape" | "keep", paraTail: string): { open: number; spans: [number, number][] } {
  const spans: [number, number][] = [];
  const done = (start: number, end: number) => (spans.push([start, end]), end);
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    const limit = paragraphEnd(s, i);
    const growing = limit === s.length;
    if (c === "\\") {
      if (i + 1 >= s.length) return { open: i, spans };
      i = done(i, i + 2);
    } else if (c === "`") {
      // Same decision as the sanitizer's protectCode, so a cut never separates two runs that it
      // (or a renderer) would pair. After an ambiguous run nothing in the paragraph is trusted,
      // so the paragraph is held whole until it ends.
      let n = 1;
      while (s[i + n] === "`") n++;
      if (i + n >= s.length) return { open: i, spans };
      BLANK_LINE.lastIndex = 0;
      let paraStart = -1;
      for (let m; (m = BLANK_LINE.exec(s)) && m.index + m[0].length <= i; ) paraStart = m.index + m[0].length;
      const paragraph = paraStart < 0 ? paraTail + s.slice(0, i) : s.slice(paraStart, i);
      const span = codeSpanAt(s, i, n, html, paragraph, limit);
      if (span === "ambiguous") {
        if (growing) return { open: i, spans };
        i = limit;
      } else if (span === null) {
        if (growing) return { open: i, spans };
        i += n;
      } else if (span >= s.length) {
        // The closing run may still grow ("``" + "``"), and then it no longer closes.
        return { open: i, spans };
      } else i = done(i, span);
    } else if (c === "<") {
      const rest = s.slice(i, limit);
      const complete = /^<[^\s<>`]*>/.exec(rest);
      if (complete) i = done(i, i + complete[0].length);
      else if (growing && (/^<[^\s<>]*$/.test(rest) || (html === "keep" && !rest.includes(">")))) return { open: i, spans };
      else i++;
    } else if (c === "[" || (c === "!" && s[i + 1] === "[")) {
      const start = i;
      const bracket = c === "!" ? i + 1 : i;
      const close = matching(s, bracket, "[", "]", limit);
      if (close < 0) {
        if (growing) return { open: start, spans };
        i = bracket + 1;
        continue;
      }
      if (close + 1 >= s.length) return { open: start, spans };
      // Backticks bind tighter than brackets: one inside may pair with a run far beyond the "]",
      // so the bracket can't be treated as a unit. Hold, or scan on through it.
      if (s.slice(bracket, close).includes("`")) {
        if (growing) return { open: start, spans };
        i = bracket + 1;
        continue;
      }
      const next = s[close + 1];
      if (next === "(" || next === "[") {
        const end = matching(s, close + 1, next, next === "(" ? ")" : "]", limit);
        if (end < 0 || s.slice(close, end).includes("`")) {
          if (growing) return { open: start, spans };
          i = close + 1;
          continue;
        }
        i = done(start, end + 1);
      } else i = done(start, close + 1);
    } else i++;
  }
  return { open: -1, spans };
}

function safeCut(s: string, html: "escape" | "keep", paraTail: string) {
  let cut = s.length;
  // A word still being typed could be the front of a URL ("https://ev" + "il.com").
  if (!/\s$/.test(s)) cut = Math.max(0, s.search(/\S+$/));
  // A line that might be a link reference definition or a fence is held until it is complete.
  const lineStart = s.lastIndexOf("\n") + 1;
  if (/^ {0,3}[[`~]/.test(s.slice(lineStart)) || /^ {0,3}$/.test(s.slice(lineStart))) cut = Math.min(cut, lineStart);
  // A definition may put its URL and title on the next two lines; hold it until they're known.
  const defs = [...s.matchAll(/(?:^|\n)( {0,3}\[[^\n]*\]:)/g)];
  if (defs.length) {
    const d = defs[defs.length - 1].index! + (s[defs[defs.length - 1].index!] === "\n" ? 1 : 0);
    const after = s.slice(d);
    if (!/\n[ \t]*\n/.test(after) && (after.match(/\n/g)?.length ?? 0) < 3) cut = Math.min(cut, d);
  }
  const { open, spans } = scan(s, html, paraTail);
  if (open >= 0) cut = Math.min(cut, open);
  // Cut only between words, and never through a finished construct: a piece starting mid-word or
  // mid-link would be sanitized without the context that decides how it renders.
  for (let prev = -1; prev !== cut; ) {
    prev = cut;
    while (cut > 0 && !/\s/.test(s[cut - 1])) cut--;
    for (let k = spans.length - 1; k >= 0; k--) if (spans[k][0] < cut && cut < spans[k][1]) cut = spans[k][0];
  }
  return cut;
}

/**
 * Sanitizes markdown as it streams from a model. Returns only text that is final: a link or image
 * is held until it is complete and has been checked, so a chat UI that renders each chunk never
 * sees, and never fetches, a URL that is later removed.
 */
export function createStream(options: StreamOptions = {}): MarkdownGuardStream {
  const removed: Finding[] = [];
  const ctx = makeContext(options, removed);
  const html = options.html ?? "escape";
  const maxHold = options.maxHold ?? 4096;
  let pending = "";
  const fences = new FenceTracker();
  // Brackets left open in the text sent so far; see fenceOpener.
  let depth = 0;
  // Whether `pending` begins at the start of a line. A chunk boundary can fall mid-line, and a
  // "```" there is ordinary text, not a fence.
  let lineStart = true;
  // How much of `pending` is complete lines already classified as text. Each line is classified
  // exactly once, because classifying moves the fence tracker on.
  let scanned = 0;
  // The current paragraph's text already sent; code-span decisions depend on it.
  let paraTail = "";

  function emitText(upTo: number) {
    const text = pending.slice(0, upTo);
    const out = sanitizeText(ctx, text, lineStart, paraTail);
    const blank = [...text.matchAll(/\n[ \t]*\n/g)].pop();
    paraTail = blank ? text.slice(blank.index! + blank[0].length) : paraTail + text;
    depth = bracketDepth(text, depth);
    if (upTo > 0) lineStart = text.endsWith("\n");
    pending = pending.slice(upTo);
    scanned = Math.max(0, scanned - upTo);
    return out;
  }

  function drain(final: boolean): string {
    let out = "";
    for (;;) {
      if (fences.fence) {
        const nl = pending.indexOf("\n");
        if (nl < 0 && !final) return out;
        const line = nl < 0 ? pending : pending.slice(0, nl + 1);
        if (!line) return out;
        if (fences.classify(line, depth) === "text") continue; // the fence ended before this line
        out += line;
        pending = pending.slice(line.length);
        continue;
      }

      // Classify the complete lines not yet seen. An opener ends the text before it.
      let opened = false;
      for (;;) {
        const nl = pending.indexOf("\n", scanned);
        const end = nl >= 0 ? nl + 1 : final ? pending.length : -1;
        if (end <= scanned) break;
        const line = pending.slice(scanned, end);
        const atLineStart = scanned > 0 || lineStart;
        if (atLineStart && fences.classify(line, bracketDepth(pending.slice(0, scanned), depth)) === "code") {
          out += emitText(scanned) + line;
          paraTail = "";
          pending = pending.slice(line.length);
          lineStart = true;
          opened = true;
          break;
        }
        scanned = end;
      }
      if (opened) continue;

      if (final) return out + emitText(pending.length);
      let cut = safeCut(pending, html, paraTail);
      if (pending.length - cut > maxHold) {
        // Held too long: give up waiting. Escaping the opening character means it can never
        // become a link, whatever arrives later; a space ends a runaway word the same way.
        const c = pending[cut];
        const at = c === "[" || c === "!" || c === "<" || c === "`" ? cut : cut + maxHold;
        pending = pending.slice(0, at) + (at === cut ? "\\" : " ") + pending.slice(at);
        if (at < scanned) scanned++;
        cut = safeCut(pending, html, paraTail);
      }
      return out + emitText(cut);
    }
  }

  return {
    write: (chunk: string) => {
      pending += chunk;
      return drain(false);
    },
    end: () => drain(true),
    removed,
  };
}
