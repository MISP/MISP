// Compiles every themes/<name>/theme.scss into app/webroot/css/themes/,
// with its metadata beside it and the fonts it references copied into
// app/webroot/fonts/themes/. The output is committed; MISP never runs this.
import * as sass from 'sass';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const themesDir = path.join(here, 'themes');
const nodeModules = path.join(here, 'node_modules');
const cssOut = path.join(root, 'app/webroot/css/themes');
const fontOut = path.join(root, 'app/webroot/fonts/themes');
const fontUrlPrefix = '../../fonts/themes/';

const MODES = ['light', 'dark', 'both'];

// Bootstrap 5.3 itself triggers these; anything else is ours and should show.
const SILENCED = ['import', 'global-builtin', 'color-functions'];

const CONTRAST = /^misp-contrast: (\S+) .* against the (light|dark) background/;

function readMeta(name) {
    const file = path.join(themesDir, name, 'theme.json');
    const meta = JSON.parse(fs.readFileSync(file, 'utf8'));
    const problems = [];
    if (typeof meta.label !== 'string' || meta.label === '') {
        problems.push('label must be a non-empty string');
    }
    if (!MODES.includes(meta.mode)) {
        problems.push(`mode must be one of ${MODES.join(', ')}`);
    }
    if (!Array.isArray(meta.fonts)) {
        problems.push('fonts must be an array');
    }
    if (typeof meta.hide_from_users !== 'boolean') {
        problems.push('hide_from_users must be a boolean');
    }
    const accepted = meta.contrast_accepted ?? {};
    for (const [mode, colours] of Object.entries(accepted)) {
        if (!['light', 'dark'].includes(mode) || !Array.isArray(colours)) {
            problems.push('contrast_accepted maps light/dark to colour names');
        }
    }
    if (problems.length) {
        throw new Error(`${file}: ${problems.join('; ')}`);
    }
    return {
        label: meta.label,
        description: meta.description ?? '',
        mode: meta.mode,
        fonts: meta.fonts,
        hide_from_users: meta.hide_from_users,
        contrast_accepted: accepted,
    };
}

function isAccepted(warning, meta) {
    const match = warning.match(CONTRAST);
    return match !== null
        && (meta.contrast_accepted[match[2]] ?? []).includes(match[1]);
}

function compile(name, meta) {
    const entry = path.join(themesDir, name, 'theme.scss');
    const warnings = [];
    const source = `$misp-theme-mode: "${meta.mode}";\n`
        + fs.readFileSync(entry, 'utf8');
    const result = sass.compileString(source, {
        url: pathToFileURL(entry),
        loadPaths: [nodeModules],
        style: 'compressed',
        quietDeps: true,
        silenceDeprecations: SILENCED,
        logger: {
            warn(message, { deprecation }) {
                warnings.push((deprecation ? 'deprecation: ' : '') + message);
            },
        },
    });
    return { css: result.css, warnings };
}

// The font file and the package it ships in, whose license goes with it.
function findFont(file) {
    const fontsource = path.join(nodeModules, '@fontsource');
    for (const pkg of fs.readdirSync(fontsource)) {
        const candidate = path.join(fontsource, pkg, 'files', file);
        if (fs.existsSync(candidate)) {
            return { source: candidate, pkg };
        }
    }
    throw new Error(`font ${file} is not in any @fontsource package`);
}

function fontsReferenced(css) {
    const files = new Set();
    const pattern = /url\(["']?([^"')]+)["']?\)/g;
    for (const [, url] of css.matchAll(pattern)) {
        if (url.startsWith(fontUrlPrefix)) {
            files.add(url.slice(fontUrlPrefix.length));
        } else if (/^(https?:)?\/\//.test(url)) {
            throw new Error(`remote url() in output: ${url}`);
        }
    }
    if (/@import\s+url\(/.test(css)) {
        throw new Error('@import url() in output');
    }
    return files;
}

// Anything in the output directories that this build did not write goes, so
// the directories always match a clean build exactly.
function prune(dir, keep) {
    for (const file of fs.readdirSync(dir)) {
        if (!keep.has(file)) {
            fs.rmSync(path.join(dir, file));
        }
    }
}

fs.mkdirSync(cssOut, { recursive: true });
fs.mkdirSync(fontOut, { recursive: true });

const names = fs.readdirSync(themesDir)
    .filter((name) => fs.existsSync(path.join(themesDir, name, 'theme.scss')))
    .sort();

const cssWritten = new Set();
const fontsWritten = new Set();
let warningCount = 0;

for (const name of names) {
    const meta = readMeta(name);
    const { css, warnings } = compile(name, meta);
    for (const font of fontsReferenced(css)) {
        const { source, pkg } = findFont(font);
        fs.copyFileSync(source, path.join(fontOut, font));
        const license = `${pkg}-LICENSE.txt`;
        fs.copyFileSync(
            path.join(nodeModules, '@fontsource', pkg, 'LICENSE'),
            path.join(fontOut, license)
        );
        fontsWritten.add(font).add(license);
    }
    fs.writeFileSync(path.join(cssOut, `${name}.min.css`), css + '\n');
    const { contrast_accepted, ...published } = meta;
    fs.writeFileSync(
        path.join(cssOut, `${name}.json`),
        JSON.stringify(published, null, 4) + '\n'
    );
    cssWritten.add(`${name}.min.css`).add(`${name}.json`);

    const open = warnings.filter((warning) => !isAccepted(warning, meta));
    const size = Math.round(Buffer.byteLength(css) / 1024);
    console.log(`${name}: ${meta.mode}, ${size} KB, `
        + `${warnings.length - open.length} accepted contrast warnings`);
    for (const warning of open) {
        console.log(`  ${warning.split('\n')[0]}`);
    }
    warningCount += open.length;
}

prune(cssOut, cssWritten);
prune(fontOut, fontsWritten);

const fontCount = [...fontsWritten].filter((f) => f.endsWith('.woff2')).length;
console.log(`${names.length} themes, ${fontCount} font files, `
    + `${warningCount} warnings`);
