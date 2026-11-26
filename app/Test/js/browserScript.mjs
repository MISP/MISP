// Loads parts of the browser scripts under app/webroot/js, which are not
// modules, into a vm context, so a test runs the code a page runs, with
// stubs for the page around it.

import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const JS = new URL('../../webroot/js/', import.meta.url);

export function file(name) {
    return readFileSync(new URL(name, JS), 'utf8');
}

/**
 * The line of `name` that starts with `start`, or with `end` given, the lines
 * from there to the next line that is exactly `end`.
 */
export function lines(name, start, end) {
    const all = file(name).split('\n');
    const from = all.findIndex(line => line.startsWith(start));
    if (from === -1) throw new Error(`${name}: no line starts with ${start}`);
    if (end === undefined) return all[from];
    const to = all.findIndex((line, i) => i > from && line === end);
    if (to === -1) throw new Error(`${name}: no ${end} after ${start}`);
    return all.slice(from, to + 1).join('\n');
}

export function run(code, globals = {}) {
    const context = vm.createContext(globals);
    vm.runInContext(code, context);
    return context;
}
