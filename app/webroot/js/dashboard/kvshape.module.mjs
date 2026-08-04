// Pure shape helpers for the configure form's bottom-tier KV list.
//
// No DOM access — testable under `node --test` without jsdom.
// Imported by configure.module.mjs (the DOM-coupled form orchestrator);
// can also be reused by Phase 3 canonical pickers that need to flatten
// or re-nest config shapes (tag_filter's structured include / exclude,
// for example, may want flatten() before serialising to the wire).
//
// Contract:
//   - flatten / reNest are a lossless round-trip for arbitrary nested
//     objects whose leaf values are scalars, booleans, null, or arrays.
//     The flatten() output is `{dotPath: jsonString}` — every leaf is
//     JSON-encoded as a string so the configure form's text input can
//     edit it as a single value. reNest() reverses by JSON.parse-with-
//     raw-string-fallback.
//   - Known limitation: keys whose names contain a literal `.` cannot
//     round-trip because flatten doesn't escape dots in path segments.
//     The configure form's UI prevents users from typing dot keys at
//     the leaf level — they'd be interpreted as nesting on save.

/**
 * Flatten a nested object into dot-notation paths → JSON-stringified
 * leaf values. Arrays and scalars at leaves are kept as JSON strings
 * (so the UI can edit them in a single text input); the inverse
 * `reNest` parses them back.
 *
 * Empty-prefix call with a non-object input puts the value under the
 * empty-string key (degenerate case the UI never produces but the
 * function still handles deterministically).
 */
export function flatten(obj, prefix = '', out = {}) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    out[prefix] = JSON.stringify(obj);
    return out;
  }
  const keys = Object.keys(obj);
  if (keys.length === 0 && prefix) {
    out[prefix] = '{}';
    return out;
  }
  for (const k of keys) {
    const path = prefix ? `${prefix}.${k}` : k;
    flatten(obj[k], path, out);
  }
  return out;
}

/**
 * Re-nest a {dot.path: stringValue} dictionary into a real config
 * object. Each value is JSON-parsed first, falling back to the raw
 * string if it doesn't look like JSON. When two paths conflict (one
 * is a prefix of the other), later iteration order wins.
 */
export function reNest(flat) {
  const out = {};
  for (const [path, raw] of Object.entries(flat)) {
    const parts = path.split('.');
    let parsed;
    try { parsed = JSON.parse(raw); } catch (_) { parsed = raw; }
    let cur = out;
    for (let i = 0; i < parts.length - 1; i++) {
      if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null
          || Array.isArray(cur[parts[i]])) {
        cur[parts[i]] = {};
      }
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = parsed;
  }
  return out;
}

/**
 * Cheap predicate: if `value` is a JSON-encoded array string (the
 * shape `flatten()` produces for array leaves), return the parsed
 * array. Otherwise return null. The startsWith-`[` guard avoids
 * trying JSON.parse on every text input.
 */
export function asArray(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed.startsWith('[')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : null;
  } catch (_) {
    return null;
  }
}

/**
 * Parse a widget's $placeholder JSON and produce flat (key, value)
 * pairs for the bottom-tier KV list when a widget is fresh / has no
 * saved bottom-tier config (DD-06: "example keys/values from the
 * placeholder").
 *
 * Filters out keys handled by the typed-fields tier (otherwise the
 * user sees the same field twice AND the readback's Object.assign
 * lets the bottom-tier kv-row overwrite the top-tier schema control).
 *
 * Robust to legacy malformed placeholders — some MISP widgets ship
 * trailing-comma JSON that JSON.parse rejects. On parse failure (or
 * empty / non-object input), returns []; the caller falls back to a
 * single empty kv row.
 */
export function seedFromPlaceholder(raw, handledKeys) {
  if (!raw || typeof raw !== 'string') return [];
  let parsed;
  try { parsed = JSON.parse(raw); } catch (_) { return []; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
  const filtered = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (handledKeys && handledKeys.has && handledKeys.has(k)) continue;
    filtered[k] = v;
  }
  return Object.entries(flatten(filtered));
}
