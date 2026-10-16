/* =============================================================================
   MISP Pivot Explorer — sidebar view
   =============================================================================
   Draws what MispPivotSidebar.build() says about a selection into pivotick's
   sidebar hooks. No fetch: the explorer performs the view-model's lazy reads
   and redraws.

   The header says what the node is (its card, restated at sidebar width) and
   then what to notice about it, as one short ranked list. Everything else sits
   below a fold, in sections the fold bar names, one click away.

   The ranking rule (fixed, the same for every entity):
     1. noise      reasons not to act on it as it is: a false-positive
                   warninglist hit (worst when the IDS flag is on), a disputed
                   analyst opinion
     2. caution    other warninglist hits, false-positive or expiration
                   sightings, an unpublished event
     3. handling   the profile's pinned handling labels (tlp, PAP), most
                   restrictive first, and on an event a pinned handling
                   taxonomy it does not carry
     4. context    the profile's other pinned, then preferred, taxonomies and
                   galaxies, in plan order (taxonomies before galaxies)
     5. reach      who else has it: sightings, correlations and related
                   events, feeds and servers, extending events, references
     6. state      authored or derived, analyst notes, reports, a lookup
                   that found nothing
   Within a tier the order is the order listed. Zero counts are not signals.
   A lazy read that could still add a noise item sits at the top while pending.

   A multi-selection says what its nodes share; pivotick's aggregated table
   holds the rest.
   ============================================================================= */
(function (root) {
    'use strict';

    var VISIBLE = 6;
    var FOLD_OPEN_BELOW = 9;
    var TIERS = ['noise', 'caution', 'handling', 'context', 'reach', 'state'];
    var HANDLING = { tlp: true, pap: true };

    /* ── small DOM helpers ─────────────────────────────────── */
    function retryButton() {
        var r = h('button', 'pes-retry', 'Retry');
        r.type = 'button';
        r.addEventListener('click', function (e) {
            e.stopPropagation();
            r.dispatchEvent(new CustomEvent('pivot-sidebar-retry', { bubbles: true }));
        });
        return r;
    }
    function h(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined && text !== null) e.textContent = String(text);
        return e;
    }
    function add(parent, child) {
        if (child) parent.appendChild(child);
        return child;
    }
    function icon(cls) {
        return h('i', cls);
    }
    function fa(name) {
        return icon('fa-solid fa-' + name);
    }
    function idsMark(on) {
        return icon('fa-solid fa-shield-halved pes-ids' + (on ? '' : ' is-off'));
    }
    function mi(family, name) {
        return icon('misp-icon misp-' + family + ' misp-icon-' + name);
    }
    function plural(n, one, many) {
        return n + ' ' + (n === 1 ? one : (many || one + 's'));
    }

    function copyText(text) {
        var clip = window.navigator && window.navigator.clipboard;
        if (clip && window.isSecureContext) return clip.writeText(text);
        return new Promise(function (resolve, reject) {
            var ta = h('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;opacity:0';
            document.body.appendChild(ta);
            ta.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
            ta.remove();
            if (ok) resolve(); else reject();
        });
    }
    function copyButton(text, what) {
        var label = 'Copy ' + (what || 'value');
        var b = h('button', 'pes-copy');
        b.type = 'button';
        b.title = label;
        b.setAttribute('aria-label', label);
        add(b, fa('copy'));
        var timer = null;
        function settle(cls, glyphName, tip) {
            clearTimeout(timer);
            b.classList.remove('is-done', 'is-failed');
            b.classList.add(cls);
            b.firstChild.className = 'fa-solid fa-' + glyphName;
            b.title = tip;
            timer = setTimeout(function () {
                b.classList.remove(cls);
                b.firstChild.className = 'fa-solid fa-copy';
                b.title = label;
            }, 1500);
        }
        b.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            copyText(String(text)).then(function () { settle('is-done', 'check', 'Copied'); },
                                        function () { settle('is-failed', 'xmark', 'The browser refused the clipboard'); });
        });
        return b;
    }

    function pad(n) { return n < 10 ? '0' + n : String(n); }
    function day(ts) {
        var d = new Date(Number(ts) * 1000);
        return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate());
    }
    function stamp(ts) {
        var d = new Date(Number(ts) * 1000);
        return day(ts) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ' UTC';
    }

    function lazyState(vm, key) {
        return vm.lazy && vm.lazy[key] ? vm.lazy[key].state : null;
    }
    function recordKnown(vm) {
        var s = lazyState(vm, 'record');
        return s === null || s === 'ready';
    }

    /* ── MISP's tag chip ───────────────────────────────────── */
    // Elements/rich_tag.ctp + TextColourHelper: the tag's own colour, black or
    // white text by weighted luminance.
    function rgb(hex) {
        var m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
        if (!m) return null;
        var n = parseInt(m[1], 16);
        return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    }
    function noHref() { return null; }
    function hingeChip(name, colour, suffix, title) {
        return hinge(window.TagChips.chip({ name: name, colour: colour }, { searchUrl: '' }), suffix, title);
    }
    // 'leaf' where the galaxy is already named beside the chip, 'full' where not
    function hingeCluster(value, galaxy, opts) {
        opts = opts || {};
        return hinge(window.TagChips.cluster({ value: value, galaxy: galaxy || '', local: opts.local },
                                             { display: opts.display || 'leaf', href: noHref }),
                     opts.suffix, opts.title);
    }
    function hinge(html, suffix, title) {
        var wrap = document.createElement('span');
        wrap.innerHTML = html;
        var chip = wrap.firstChild;
        if (suffix) {
            var small = document.createElement('small');
            small.className = 'hg-n';
            small.textContent = suffix;
            chip.querySelector('.hg-tail').appendChild(small);
        }
        if (title) chip.querySelector('.hg-chip').title = title;
        return chip;
    }
    function tagChip(name, colour, suffix) {
        if (window.TagChips) return hingeChip(name, colour, suffix);
        var c = rgb(colour) || [110, 110, 110];
        var lum = (c[0] * 299 + c[1] * 587 + c[2] * 114) / 1000;
        var chip = h('span', 'pes-chip' + (lum > 225 ? ' is-pale' : ''), name);
        chip.style.background = 'rgb(' + c.join(',') + ')';
        chip.style.color = lum > 127 ? '#000' : '#fff';
        chip.title = name;
        if (suffix) add(chip, h('small', '', suffix));
        return chip;
    }
    function clusterChip(value, suffix, galaxy, local) {
        if (window.TagChips) return hingeCluster(value, galaxy, { suffix: suffix, local: local });
        var chip = h('span', 'pes-chip is-cluster', value);
        chip.title = value;
        if (suffix) add(chip, h('small', '', suffix));
        return chip;
    }
    function tierPill(priority) {
        if (!priority) return null;
        return h('span', 'pes-tier-pill' + (priority === 'pinned' ? ' is-pinned' : ''), priority);
    }

    /* ── glyphs and hues ───────────────────────────────────── */
    var HUE = { event: 'event', object: 'object', attribute: 'attribute', cluster: 'galaxy', tag: 'tag',
                feed: 'feed', server: 'feed', edge: 'neutral', multi: 'neutral' };

    function glyph(vm) {
        switch (vm.entity) {
        case 'event': return mi('simple', 'event');
        case 'object': return mi('simple', 'object');
        case 'attribute':
            return mi('simple', 'attribute');
        case 'cluster':
            return mi('simple', 'galaxy');
        case 'tag': return mi('simple', 'tag');
        case 'feed': return fa('rss');
        case 'server': return fa('server');
        case 'edge': return fa('arrow-right-long');
        default: return fa('layer-group');
        }
    }
    function kindLabel(vm) {
        return { event: 'Event', object: 'Object', attribute: 'Attribute', cluster: 'Galaxy cluster', tag: 'Tag',
                 feed: 'Feed', server: 'Server', edge: 'Edge', multi: 'Selection' }[vm.entity] || vm.entity;
    }

    function monogram(name) {
        var words = String(name).trim().split(/[\s._-]+/).filter(Boolean);
        var letters = words.length > 1 ? words[0][0] + words[1][0] : String(name).slice(0, 2);
        var sum = 0;
        for (var i = 0; i < name.length; i++) sum += name.charCodeAt(i);
        var b = h('span', 'pes-mono-badge', letters.toUpperCase());
        b.style.background = 'var(--pes-mono-' + (sum % 6) + ')';
        return b;
    }

    var DIST_ICON = { 'Your organisation only': 'building', 'This community only': 'users',
                      'Connected communities': 'network-wired', 'All communities': 'globe',
                      'Sharing group': 'user-group', 'Inherit event': 'arrow-turn-up' };
    var THREAT = { High: 3, Medium: 2, Low: 1, Undefined: 0 };
    var ANALYSIS = { Initial: 1, Ongoing: 2, Completed: 3 };

    function meter(level) {
        var n = THREAT[level] || 0;
        var m = h('span', 'pes-meter' + (n === 3 ? ' is-high' : ''));
        for (var i = 1; i <= 3; i++) add(m, h('i', i <= n ? 'on' : ''));
        return m;
    }
    function dots(step) {
        var n = ANALYSIS[step] || 0;
        var m = h('span', 'pes-dots');
        for (var i = 1; i <= 3; i++) add(m, h('i', i <= n ? 'on' : ''));
        return m;
    }
    function stripItem(strip, parts, title) {
        var s = add(strip, h('span'));
        parts.forEach(function (p) {
            if (p === null || p === undefined) return;
            s.appendChild(typeof p === 'string' ? document.createTextNode(p) : p);
        });
        if (title) s.title = title;
        return s;
    }

    /* ── the notice list: collect, then rank ───────────────── */
    function Notices() {
        this.items = [];
    }
    Notices.prototype.push = function (tier, n) {
        n.tier = tier;
        n.at = this.items.length;
        this.items.push(n);
        return n;
    };
    Notices.prototype.ranked = function () {
        return this.items.slice().sort(function (a, b) {
            return ((a.first ? -1 : 0) - (b.first ? -1 : 0)) ||
                   (TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier)) || (a.at - b.at);
        });
    };

    var TIER_MARK = { noise: 'ban', caution: 'triangle-exclamation', handling: 'hand', context: 'star',
                      reach: 'arrows-split-up-and-left', state: 'circle-info' };

    function meaningLine(vm, tag) {
        var s = lazyState(vm, 'taxonomies');
        if (s === 'pending') return { pending: true };
        var m = tag && tag.meaning;
        if (!m) return null;
        var text = (m.value && (m.value.expanded || m.value.description)) ||
                   (m.predicate && (m.predicate.expanded || m.predicate.description)) || null;
        return text ? { text: String(text).replace(/^\([^)]*\)\s*/, '') } : null;
    }

    // Tag and cluster groups the profile ranks: pinned handling, then the
    // rest of pinned and preferred.
    function labelNotices(vm, N, labels, allowMissing) {
        if (!labels) return;
        (labels.taxonomies || []).forEach(function (g) {
            if (g.priority !== 'pinned' && g.priority !== 'preferred') return;
            var handling = g.priority === 'pinned' && HANDLING[g.key];
            var lead = g.lead ? g.lead.tag : g.tags[0];
            var others = g.lead ? g.lead.others : g.tags.length - 1;
            var line = [tagChip(lead.name, lead.colour)];
            if (!g.lead && g.tags.length > 1) {
                g.tags.slice(1, 3).forEach(function (t) { line.push(tagChip(t.name, t.colour)); });
                others = g.tags.length - 3;
            }
            var why = vm.entity === 'event' ? null : meaningLine(vm, lead);
            var whyText = g.lead ? 'Strictest of ' + (others + 1) : null;
            N.push(handling ? 'handling' : 'context', {
                hue: 'tag', mark: handling ? 'hand' : 'tag', line: line,
                more: others > 0 ? '+' + others : null,
                why: why, whyPrefix: whyText, pill: g.priority, target: 'labels'
            });
        });
        (labels.galaxies || []).forEach(function (g) {
            if (g.priority !== 'pinned' && g.priority !== 'preferred') return;
            var line = g.clusters.slice(0, 2).map(function (c) { return clusterChip(c.value, null, g.label, c.local); });
            var first = g.clusters[0];
            var why = g.label || g.key;
            if (first.detail && first.detail.synonyms && first.detail.synonyms.length) {
                why += ' · also ' + first.detail.synonyms.slice(0, 3).join(', ') +
                       (first.detail.synonyms.length > 3 ? '…' : '');
            }
            N.push('context', {
                hue: 'galaxy', mark: 'star', line: line,
                more: g.clusters.length > 2 ? '+' + (g.clusters.length - 2) : null,
                why: { text: why }, pill: g.priority, target: 'labels'
            });
        });
        if (!allowMissing || !labels.missing) return;
        (labels.missing.taxonomies || []).forEach(function (m) {
            var handling = HANDLING[m.key];
            N.push(handling ? 'handling' : 'context', {
                cls: 'is-missing', mark: handling ? 'hand' : 'tag',
                line: 'No ' + (m.key === 'pap' ? 'PAP' : m.key) + ' label',
                why: { text: 'Pinned in your profile; this event carries none' }, pill: 'pinned', target: 'labels'
            });
        });
        (labels.missing.galaxies || []).forEach(function (m) {
            N.push('context', {
                cls: 'is-missing', mark: 'star', line: 'No ' + m.key + ' cluster',
                why: { text: 'Pinned in your profile; this event carries none' }, pill: 'pinned', target: 'labels'
            });
        });
    }

    function warninglistNotices(vm, N, list, toIds, perAttribute) {
        if (!list || !list.length) return;
        var fp = list.filter(function (w) { return w.false_positive; });
        var other = list.filter(function (w) { return !w.false_positive; });
        if (fp.length) {
            var w = fp[0];
            N.push('noise', {
                mark: 'ban', target: 'warninglists',
                line: perAttribute ? plural(sumCounts(fp), 'attribute') + ' on a false-positive list'
                    : toIds ? 'IDS flag set, yet on a false-positive list' : 'On a false-positive list',
                why: { text: w.name + (w.match ? ' · matches ' + w.match : '') },
                fig: fp.length > 1 ? plural(fp.length, 'list') : null
            });
        }
        if (other.length) {
            var o = other[0];
            N.push('caution', {
                mark: 'triangle-exclamation', target: 'warninglists',
                line: perAttribute ? plural(sumCounts(other), 'attribute') + ' on a warninglist' : 'On a warninglist',
                why: { text: o.name + (o.category ? ' · ' + o.category.replace(/_/g, ' ') : '') },
                fig: other.length > 1 ? plural(other.length, 'list') : null
            });
        }
    }
    function sumCounts(list) {
        return list.reduce(function (s, w) { return s + (w.count || 1); }, 0);
    }

    function sightingNotices(N, s) {
        if (!s || !s.total) return;
        if (s.false_positive) {
            N.push('caution', {
                mark: 'triangle-exclamation', target: 'sightings',
                line: plural(s.false_positive, 'false-positive sighting'),
                why: { text: s.false_positive + ' of ' + s.total + ' sightings report it as a false positive' }
            });
        }
        if (s.expiration) {
            N.push('caution', {
                mark: 'hourglass-end', target: 'sightings',
                line: plural(s.expiration, 'expiration sighting'),
                why: { text: 'Reported as expired' }
            });
        }
        if (s.sighting) {
            var orgs = s.orgs.slice(0, 3).map(function (o) { return o.name + ' ×' + o.count; }).join(', ');
            N.push('reach', {
                mark: 'eye', target: 'sightings',
                line: plural(s.sighting, 'sighting') + (s.orgs.length ? ' from ' + plural(s.orgs.length, 'org') : ''),
                why: { text: (s.last ? 'Last ' + day(s.last) + ' · ' : '') + orgs }
            });
        }
    }

    function sourceNotices(N, sources) {
        ['feed', 'server'].forEach(function (type) {
            var list = (sources || []).filter(function (s) { return s.type === type; });
            if (!list.length) return;
            N.push('reach', {
                mark: type === 'feed' ? 'rss' : 'server', target: 'seen',
                line: 'Seen in ' + plural(list.length, type),
                why: { text: list.map(function (s) { return s.name; }).join(', ') }
            });
        });
    }

    function analystNotices(N, a) {
        if (!a) return;
        if (a.mood === 'disputed') {
            N.push('noise', { mark: 'thumbs-down', target: 'analyst', line: 'Analysts dispute it',
                              why: { text: plural(a.opinions, 'opinion') + ' on average disagree' } });
        }
        var bits = [];
        if (a.notes) bits.push(plural(a.notes, 'note'));
        if (a.opinions && a.mood !== 'disputed') bits.push(plural(a.opinions, 'opinion') + (a.mood === 'endorsed' ? ', endorsing' : ''));
        if (a.relationships) bits.push(plural(a.relationships, 'relationship'));
        if (bits.length) N.push('state', { mark: 'comment', target: 'analyst', line: 'Analyst data', why: { text: bits.join(' · ') } });
    }

    function recordNotice(vm, N) {
        var s = lazyState(vm, 'record');
        var from = vm.provenance && vm.provenance.label ? ' from ' + vm.provenance.label.toLowerCase().replace(/^event/, 'event') : '';
        if (s === 'pending') {
            N.push('state', { first: true, cls: 'is-pending', mark: 'spinner', line: 'Reading the full record' + from + '…',
                              why: { text: vm.entity === 'event' ? 'Feeds, reports and analyst data may add to this list'
                                                                 : 'Warninglists, sightings and tags may add to this list' } });
        } else if (s === 'failed') {
            N.push('state', { first: true, cls: 'is-failed', mark: 'circle-exclamation', line: 'Could not read the full record' + from,
                              why: { text: 'Showing only what the card carries' }, retry: true });
        }
    }

    function hoursAgo(seconds) {
        var h = Math.round((seconds || 0) / 3600);
        if (h < 1) return 'just now';
        return h < 48 ? h + ' h ago' : Math.round(h / 24) + ' days ago';
    }

    // Leads, for a result: MISP does not hold it, a module said it.
    function enrichmentNotices(vm, N) {
        var e = vm.enrichment;
        if (!e) return;
        N.push('caution', { first: true, mark: 'wand-magic-sparkles',
                            line: 'Not in MISP: ' + e.modules.join(', ') + ' said this',
                            why: { text: e.kept_by ? 'Kept by ' + e.kept_by + (e.age != null ? ', asked ' + hoursAgo(e.age) : '')
                                       : e.from_store ? 'Stored answer, ' + hoursAgo(e.age) : 'Asked just now' } });
        if (e.untyped) {
            N.push('caution', { mark: 'circle-question', line: 'Untyped by the module',
                                why: e.candidate_types.length ? { text: 'Also possible: ' + e.candidate_types.join(', ') } : null });
        }
    }

    /* ── per-entity: notices ───────────────────────────────── */
    function eventNotices(vm, N) {
        recordNotice(vm, N);
        var known = recordKnown(vm);
        if (vm.card && vm.card.published === false) {
            N.push('caution', { mark: 'paper-plane', target: 'record', line: 'Not published',
                                why: { text: 'Not yet shared with the community' } });
        }
        labelNotices(vm, N, vm.labels, true);
        if (known) {
            var rel = vm.relations || {};
            if (rel.related_events) N.push('reach', { mark: 'link', target: 'relations', line: plural(rel.related_events, 'related event'),
                                                       why: { text: 'Correlate with this one' } });
            sourceNotices(N, vm.sources);
            if (rel.reports && rel.reports.length) N.push('state', { mark: 'file-lines', target: 'relations',
                line: plural(rel.reports.length, 'event report'), why: { text: rel.reports[0].name } });
            analystNotices(N, vm.analyst);
        }
        var eb = vm.relations && vm.relations.extended_by;
        if (lazyState(vm, 'extended_by') === 'ready' && eb && eb.length) {
            N.push('reach', { mark: 'code-branch', target: 'relations', line: 'Extended by ' + plural(eb.length, 'event'),
                              why: { text: eb.map(function (e) { return e.info; }).join(', ') } });
        }
    }

    function attributeNotices(vm, N) {
        enrichmentNotices(vm, N);
        recordNotice(vm, N);
        var known = recordKnown(vm);
        if (known) {
            warninglistNotices(vm, N, vm.warninglists, vm.card.to_ids, false);
            labelNotices(vm, N, vm.labels, false);
            sightingNotices(N, vm.sightings);
        }
        if (vm.correlations && vm.correlations.count) {
            N.push('reach', { mark: 'arrows-left-right', target: 'seen', line: plural(vm.correlations.count, 'correlation'),
                              why: { text: 'Other attributes with this value' } });
        }
        if (known) {
            sourceNotices(N, vm.sources);
            if (vm.feed_hit_unnamed) N.push('reach', { mark: 'rss', target: 'seen', line: 'Seen in a feed', why: null });
            analystNotices(N, vm.analyst);
        }
    }

    function objectNotices(vm, N) {
        enrichmentNotices(vm, N);
        warninglistNotices(vm, N, vm.warninglists, false, true);
        labelNotices(vm, N, vm.labels, false);
        if (vm.correlations && vm.correlations.count) {
            N.push('reach', { mark: 'arrows-left-right', target: 'seen', line: plural(vm.correlations.count, 'correlation'),
                              why: { text: 'Across its attributes' } });
        }
        var refs = vm.relations && vm.relations.references;
        if (refs && (refs.out.length || refs.in.length)) {
            N.push('reach', { mark: 'diagram-project', target: 'relations',
                              line: plural(refs.out.length + refs.in.length, 'reference'),
                              why: { text: refs.out.length + ' out · ' + refs.in.length + ' in' } });
        }
        var ids = (vm.children || []).filter(function (c) { return c.to_ids; }).length;
        if (ids) N.push('state', { mark: 'shield-halved', target: 'children', line: plural(ids, 'attribute') + ' flagged for IDS', why: null });
        analystNotices(N, vm.analyst);
    }

    function tagNotices(vm, N) {
        if (vm.priority) {
            N.push(HANDLING[String(vm.card.namespace).toLowerCase()] && vm.priority === 'pinned' ? 'handling' : 'context', {
                mark: 'star', target: 'meaning', pill: vm.priority,
                line: vm.card.namespace + ' is ' + vm.priority + ' in your profile', why: null
            });
        }
        var s = lazyState(vm, 'taxonomies');
        var m = vm.meaning;
        if (s === 'ready' && m) {
            if (m.numerical_value !== null && m.numerical_value !== undefined) {
                N.push('state', { mark: 'hashtag', target: 'meaning', line: 'Numerical value ' + m.numerical_value, why: null });
            }
            if (m.taxonomy && m.taxonomy.exclusive) {
                N.push('state', { mark: 'lock', target: 'meaning', line: 'Exclusive taxonomy',
                                  why: { text: 'A record carries at most one ' + m.taxonomy.namespace + ' label' } });
            }
        }
    }

    function clusterNotices(vm, N) {
        ['cluster_tag', 'cluster'].forEach(function (k) {
            var s = lazyState(vm, k);
            if (s === 'pending') N.push('state', { first: true, cls: 'is-pending', mark: 'spinner', line: 'Looking up the cluster…', why: null });
            if (s === 'failed') N.push('state', { first: true, cls: 'is-failed', mark: 'circle-exclamation',
                                                  line: 'Could not look up the cluster', why: null, retry: true });
        });
        if (vm.priority) {
            N.push('context', { mark: 'star', target: 'about', pill: vm.priority,
                                line: (vm.card.galaxy || 'This galaxy') + ' is ' + vm.priority + ' in your profile', why: null });
        }
        var d = vm.detail;
        if (d) {
            if (d.relations) N.push('reach', { mark: 'diagram-project', target: 'meta', line: plural(d.relations, 'cluster relation'), why: null });
            if (d.synonyms && d.synonyms.length) {
                N.push('state', { mark: 'clone', target: 'about', line: 'Also known as ' + plural(d.synonyms.length, 'name'),
                                  why: { text: d.synonyms.slice(0, 4).join(', ') + (d.synonyms.length > 4 ? '…' : '') } });
            }
        } else if (!N.items.some(function (n) { return n.first; })) {
            N.push('state', { mark: 'circle-info', line: 'No cluster describes this tag', target: 'record',
                              why: { text: 'Only the tag name is known' } });
        }
    }

    function sourceNoticesFor(vm, N) {
        var c = vm.card;
        if (c.attributes_here) N.push('reach', { mark: 'bullseye', target: 'record',
            line: 'Holds ' + plural(c.attributes_here, 'attribute') + ' on this canvas', why: null });
        if (c.events) N.push('state', { mark: 'layer-group', target: 'record', line: plural(c.events, 'event') + ' in the ' + vm.entity, why: null });
    }

    function edgeNotices(vm, N) {
        var c = vm.card;
        if (c.authored) {
            N.push('state', { mark: 'pen', target: 'record', line: 'Authored — stored in MISP',
                              why: { text: 'An analyst drew it; it can be deleted' } });
        } else {
            N.push('state', { mark: 'wand-magic-sparkles', target: 'record', line: 'Derived — nothing stored',
                              why: { text: 'Drawn by a pivot from the data; there is nothing to delete' } });
        }
    }

    function multiNotices(vm, N) {
        var total = vm.card.count;
        function shareFig(n) {
            var s = h('span', 'pes-share');
            for (var i = 0; i < total && i < 8; i++) add(s, h('i', i < n ? 'on' : ''));
            var wrap = h('span');
            add(wrap, s);
            wrap.appendChild(document.createTextNode(n + '/' + total));
            return wrap;
        }
        (vm.shared.taxonomies || []).forEach(function (t) {
            var profiled = t.priority === 'pinned' || t.priority === 'preferred';
            if (!profiled && t.count !== total) return;
            var tier = t.priority === 'pinned' && HANDLING[String(t.key).toLowerCase()] ? 'handling'
                     : profiled ? 'context' : 'reach';
            N.push(tier, { mark: tier === 'handling' ? 'hand' : 'tag', line: [tagChip(t.name, t.colour)], pill: t.priority,
                           why: { text: t.count === total ? 'All ' + total + ' carry it' : t.count + ' of ' + total + (t.count === 1 ? ' carries it' : ' carry it') },
                           figNode: shareFig(t.count) });
        });
        (vm.shared.galaxies || []).forEach(function (c) {
            var profiled = c.priority === 'pinned' || c.priority === 'preferred';
            if (!profiled && c.count !== total) return;
            N.push(profiled ? 'context' : 'reach', { hue: 'galaxy', mark: 'star', line: [clusterChip(c.name, null, c.galaxy)], pill: c.priority,
                           why: { text: (c.galaxy || '') + ' · ' + (c.count === total ? 'all ' + total + ' carry it' : c.count + ' of ' + total + (c.count === 1 ? ' carries it' : ' carry it')) },
                           figNode: shareFig(c.count) });
        });
        var orgs = vm.shared.orgs || [];
        if (orgs.length === 1) N.push('state', { mark: 'building', line: 'All from ' + orgs[0].name, why: null });
        else if (orgs.length > 1) N.push('state', { mark: 'building', line: plural(orgs.length, 'organisation'),
            why: { text: orgs.map(function (o) { return o.name + ' ' + o.count; }).join(' · ') } });
    }

    /* ── drawing the notice list ───────────────────────────── */
    function drawNotices(root, N, hooks) {
        var ranked = N.ranked();
        var wrap = add(root, h('div', 'pes-notice'));
        var head = add(wrap, h('div', 'pes-notice-head'));
        add(head, h('span', 'pes-notice-title', 'Notice'));
        if (!ranked.length) {
            add(wrap, h('div', 'pes-quiet', 'Nothing here stands out for your profile.'));
            return;
        }
        var ul = add(wrap, h('ul', 'pes-list'));
        ranked.forEach(function (n, i) {
            var li = add(ul, h('li', 'pes-item' + (n.cls ? ' ' + n.cls : '')));
            li.setAttribute('data-tier', n.tier);
            if (n.hue) li.setAttribute('data-hue', n.hue);
            if (i >= VISIBLE) li.hidden = true;
            var mark = add(li, h('span', 'pes-item-mark'));
            add(mark, fa(n.mark || TIER_MARK[n.tier]));
            if (n.mark === 'spinner') mark.firstChild.classList.add('fa-spin');
            var body = add(li, h('div', 'pes-item-body'));
            var line = add(body, h('div', 'pes-item-line'));
            if (typeof n.line === 'string') line.textContent = n.line;
            else n.line.forEach(function (node) { line.appendChild(node); });
            if (n.more) add(line, h('span', 'pes-item-fig', ' ' + n.more));
            if (n.whyPrefix || n.why) {
                var why = add(body, h('div', 'pes-item-why'));
                var parts = [];
                if (n.whyPrefix) parts.push(n.whyPrefix);
                if (n.why && n.why.text) parts.push(n.why.text);
                why.textContent = parts.join(' · ');
                if (n.why && n.why.pending) add(why, h('span', 'pes-skel w80'));
            }
            if (n.retry) {
                var r = add(body, retryButton());
                r.style.marginTop = '4px';
                r.style.marginLeft = '0';
            }
            var fig = add(li, h('span', 'pes-item-fig'));
            if (n.figNode) fig.appendChild(n.figNode);
            else if (n.pill) add(fig, tierPill(n.pill));
            else if (n.fig) fig.textContent = n.fig;
            if (n.target) li.addEventListener('click', function () { hooks.jump(n.target); });
        });
        if (ranked.length > VISIBLE) {
            var more = add(wrap, h('button', 'pes-attr-more', 'Show ' + (ranked.length - VISIBLE) + ' more'));
            more.type = 'button';
            more.addEventListener('click', function () {
                [].forEach.call(ul.children, function (li) { li.hidden = false; });
                more.remove();
            });
        }
    }

    /* ── header ────────────────────────────────────────────── */
    function drawHeader(slot, vm, N, hooks) {
        var root = add(slot, h('div', 'pes pes-head'));
        root.setAttribute('data-hue', HUE[vm.entity] || 'neutral');
        var id = add(root, h('div', 'pes-id'));
        var g = add(id, h('div', 'pes-glyph'));
        add(g, glyph(vm));
        var text = add(id, h('div', 'pes-idtext'));
        var kicker = add(text, h('div', 'pes-kicker'));
        add(kicker, h('span', '', kindLabel(vm)));
        if (vm.provenance && vm.provenance.label) {
            var prov = add(kicker, h('span', 'pes-prov'));
            add(prov, fa({ self: 'location-dot', module: 'wand-magic-sparkles' }[vm.provenance.scope]
                         || 'arrow-up-right-from-square'));
            prov.appendChild(document.createTextNode(vm.provenance.label));
        }

        var clusterTitle = vm.entity === 'cluster' && window.TagChips && vm.card.value;
        if (vm.entity === 'tag') {
            var t = add(text, h('div', 'pes-title'));
            add(t, tagChip(vm.card.name, vm.card.colour));
        } else if (clusterTitle) {
            var ct = add(text, h('div', 'pes-title'));
            add(ct, hingeCluster(vm.card.value, vm.card.galaxy, { display: 'full' }));
        } else {
            var title = add(text, h('div', 'pes-title', vm.title || kindLabel(vm)));
            title.title = vm.title || '';
            if (vm.entity === 'attribute') {
                title.classList.add('is-value');
                if (vm.profile) valueCard(title, vm, vm.profile.b64);
                if (vm.card.value !== undefined && vm.card.value !== null && vm.card.value !== '') {
                    add(id, copyButton(vm.card.value));
                }
            }
        }
        var sub = clusterTitle ? null : subtitle(vm);
        if (sub) add(text, h('div', 'pes-sub', sub));

        var strip = cardStrip(vm);
        if (strip && strip.childNodes.length) add(root, strip);
        if (vm.entity === 'edge') add(root, edgeEnds(vm));
        if (vm.entity === 'object') add(root, objectTop(vm, hooks.nav));
        if (hooks.actions && hooks.actions.length) add(root, actionRow(hooks.actions));

        drawNotices(root, N, hooks);

        if (vm.links && vm.links.length) {
            var links = add(root, h('div', 'pes-links'));
            vm.links.forEach(function (l) {
                var a = add(links, h('a', 'pes-link'));
                a.href = l.path;
                add(a, fa(l.kind === 'feed' || l.kind === 'server' ? 'table-list' : 'arrow-up-right-from-square'));
                a.appendChild(document.createTextNode(l.label));
            });
        }
        return root;
    }

    // What the viewer may do to the element: { label, icon, hue, title, muted,
    // run } — or a `menu` of { label, icon, hue, hint, run } to choose from.
    function actionRow(actions) {
        var row = h('div', 'pes-actions');
        actions.forEach(function (a) {
            var b = add(row, h('button', 'pes-action'));
            b.type = 'button';
            if (a.hue) b.setAttribute('data-act', a.hue);
            if (a.title) {
                b.title = a.title;
                b.setAttribute('aria-label', a.title);
            }
            if (a.muted) b.setAttribute('aria-disabled', 'true');
            add(b, icon(a.icon));
            add(b, h('span', '', a.label));
            // Bootstrap toggles a menu itself, from its own click listener.
            var menu = a.menu && window.bootstrap && window.bootstrap.Dropdown;
            if (menu) add(row, actionMenu(b, a.menu));
            b.addEventListener('click', function (e) {
                e.stopPropagation();
                if (!menu) a.run();
            });
        });
        return row;
    }

    function actionMenu(button, items) {
        button.setAttribute('data-bs-toggle', 'dropdown');
        button.setAttribute('aria-expanded', 'false');
        add(button, fa('chevron-down')).className += ' pes-action-caret';
        var menu = h('ul', 'dropdown-menu pes-action-menu');
        items.forEach(function (it) {
            var item = add(add(menu, h('li')), h('button', 'dropdown-item'));
            item.type = 'button';
            if (it.hue) item.setAttribute('data-act', it.hue);
            add(item, icon(it.icon));
            var text = add(item, h('span', 'pes-action-menu-t'));
            add(text, h('span', '', it.label));
            if (it.hint) add(text, h('small', '', it.hint));
            item.addEventListener('click', function (e) {
                e.stopPropagation();
                window.bootstrap.Dropdown.getOrCreateInstance(button).hide();
                it.run();
            });
        });
        return menu;
    }

    function subtitle(vm) {
        switch (vm.entity) {
        case 'attribute': return null;
        case 'object': return null;
        case 'cluster': return vm.card.galaxy;
        case 'feed': case 'server': return vm.subtitle || null;
        case 'edge': return vm.card.relationship_type ? vm.card.kind_label : null;
        case 'event': return null;
        default: return vm.subtitle || null;
        }
    }

    function cardStrip(vm) {
        var s = h('div', 'pes-strip');
        var c = vm.card || {};
        if (vm.entity === 'event') {
            if (c.org) stripItem(s, [monogram(c.org), h('b', '', c.org)]);
            if (c.date) stripItem(s, [fa('calendar'), c.date], 'Event date');
            if (c.distribution) stripItem(s, [fa(DIST_ICON[c.distribution] || 'share-nodes'), c.sharing_group || c.distribution], 'Distribution');
            var counts = [];
            if (c.attributes !== null && c.attributes !== undefined) counts.push(c.attributes + ' attr');
            if (c.objects !== null && c.objects !== undefined) counts.push(c.objects + ' obj');
            if (c.reports) counts.push(plural(c.reports, 'report'));
            if (counts.length) stripItem(s, [fa('cubes'), counts.join(' · ')]);
            stripItem(s, [fa(c.published ? 'paper-plane' : 'pen-to-square'),
                          c.published ? 'Published' + (c.published_at ? ' ' + day(c.published_at) : '') : 'Unpublished']);
        } else if (vm.entity === 'attribute') {
            stripItem(s, [idsMark(c.to_ids)], c.to_ids ? 'IDS flag on' : 'IDS flag off');
            if (c.type) stripItem(s, [h('b', 'pes-code', c.type)]);
            if (c.category) stripItem(s, [c.category]);
            if (c.relation) stripItem(s, [fa('diagram-next'), c.relation], 'Object relation');
            var m = c.marks || {};
            if (recordKnown(vm)) {
                if (m.warninglisted) stripItem(s, [fa('triangle-exclamation')], 'Warninglisted');
                if (m.tagged) stripItem(s, [fa('tag'), String(m.tagged)], 'Tags and clusters');
                if (m.analyst) stripItem(s, [fa('comment')], 'Analyst data');
                if (m.feed) stripItem(s, [fa('rss')], 'Seen in a feed');
            }
        } else if (vm.entity === 'object') {
            if (c.meta_category) stripItem(s, [fa('folder'), c.meta_category], 'Meta-category');
            stripItem(s, [fa('list'), plural(c.attributes, 'attribute')]);
        } else if (vm.entity === 'tag') {
            if (c.namespace) stripItem(s, ['Namespace ', h('b', '', c.namespace)]);
            if (c.predicate) stripItem(s, ['Predicate ', h('b', '', c.predicate)]);
            if (c.value) stripItem(s, ['Value ', h('b', '', c.value)]);
            if (c.local) stripItem(s, [fa('house'), 'Local']);
        } else if (vm.entity === 'feed' || vm.entity === 'server') {
            if (c.url) {
                var u = stripItem(s, [fa('link'), h('span', 'pes-code pes-trunc', c.url)], c.url);
                u.style.maxWidth = '100%';
                u.style.minWidth = '0';
                u.lastChild.style.minWidth = '0';
            }
        } else if (vm.entity === 'multi') {
            (c.kinds || []).forEach(function (k) { stripItem(s, [h('b', '', String(k.count)), ' ' + k.entity + (k.count === 1 ? '' : 's')]); });
        }
        return s;
    }

    // MISP's triangle on an attribute on a warninglist, in its category colour.
    function warnMark(k) {
        var m = fa('triangle-exclamation');
        m.classList.add(k.false_positive ? 'is-warn' : 'is-known');
        m.title = (k.false_positive ? 'Likely false positive' : 'Known identifier') +
                  (k.warninglists && k.warninglists.length ? ' — ' + k.warninglists.join(', ') : '');
        return m;
    }

    // value-hover-card.js answers a hover on the value, where the instance has
    // the card on; the native title would cover it.
    function valueCard(el, vm, b64) {
        if (!vm.value_card || !b64) return el;
        el.classList.add('vp-hc-trigger');
        el.setAttribute('data-vp-hc-value', b64);
        el.tabIndex = 0;
        el.removeAttribute('title');
        return el;
    }

    // An object's attribute value, linked to its profile.
    function attrValue(vm, k) {
        var v = h(k.b64 ? 'a' : 'div', 'pes-attr-val', k.value);
        v.title = k.value;
        if (k.b64) {
            v.href = '/values/view/' + k.b64;
            v.target = '_blank';
            v.rel = 'noopener';
        }
        valueCard(v, vm, k.b64);
        var line = h('div', 'pes-attr-line');
        add(line, v);
        if (k.value !== undefined && k.value !== null && k.value !== '') add(line, copyButton(k.value));
        return line;
    }

    function objectTop(vm, nav) {
        var list = h('ul', 'pes-attrs');
        list.style.marginTop = '8px';
        (vm.card.top || []).forEach(function (t) {
            var li = add(list, h('li', 'pes-attr'));
            add(li, h('div', 'pes-attr-rel', t.relation));
            add(li, attrValue(vm, t));
            var marks = add(li, h('div', 'pes-attr-marks'));
            if (t.warninglisted) add(marks, warnMark(t));
            selectable(li, nav, t.uuid, t.relation || t.type);
        });
        return list;
    }

    // A listed attribute that is a node on the canvas selects it; a click on
    // its value link or copy button keeps doing what those do.
    function selectable(li, nav, uuid, what) {
        if (!nav || !uuid || !nav.selectable(uuid)) return;
        li.classList.add('is-selectable');
        li.tabIndex = 0;
        li.setAttribute('role', 'button');
        li.title = 'Select this ' + (what || 'attribute');
        var marks = li.querySelector('.pes-attr-marks') || add(li, h('div', 'pes-attr-marks'));
        add(marks, fa('chevron-right')).className += ' pes-attr-go';
        li.addEventListener('click', function (e) {
            if (e.target.closest('a, button')) return;
            nav.select(uuid);
        });
        li.addEventListener('keydown', function (e) {
            if (e.target !== li || (e.key !== 'Enter' && e.key !== ' ')) return;
            e.preventDefault();
            nav.select(uuid);
        });
    }

    function edgeEnds(vm) {
        var c = vm.card;
        var box = h('div', 'pes-ends');
        var HUED = { object: 1, attribute: 1, event: 1 };
        function end(e) {
            var t = e && e.type;
            var row = h('div', 'pes-end');
            row.setAttribute('data-end', HUED[t] ? t : 'other');
            add(row, HUED[t] ? mi('simple', t) : fa('circle-nodes'));
            var l = add(row, h('span', 'pes-end-label' + (t === 'attribute' ? ' is-value' : ''), e ? e.label : '—'));
            if (e) l.title = e.label;
            add(row, h('span', 'pes-end-kind', t || ''));
            return row;
        }
        add(box, end(c.from));
        var arrow = add(box, h('div', 'pes-end-arrow'));
        add(arrow, fa('arrow-down'));
        arrow.appendChild(document.createTextNode(c.relationship_type || c.kind_label));
        add(box, end(c.to));
        return box;
    }

    /* ── detail sections below the fold ────────────────────── */
    function section(id, title, count, lazyKey, vm) {
        var sec = h('section', 'pes-sec');
        sec.setAttribute('data-sec', id);
        var head = add(sec, h('div', 'pes-sec-h'));
        add(head, h('span', '', title));
        if (count !== null && count !== undefined) add(head, h('b', '', String(count)));
        var state = lazyKey ? lazyState(vm, lazyKey) : null;
        if (state === 'pending') add(head, h('span', 'pes-sec-state is-pending', 'loading'));
        if (state === 'failed') {
            var f = add(head, h('span', 'pes-sec-state is-failed', 'could not load'));
            f.insertBefore(fa('circle-exclamation'), f.firstChild);
        }
        return { el: sec, id: id, title: title, count: count, state: state, weight: 1 };
    }
    function rows(sec, list) {
        var dl = add(sec.el, h('dl', 'pes-rows'));
        list.forEach(function (r) {
            if (!r || r[1] === null || r[1] === undefined || r[1] === '') return;
            add(dl, h('dt', '', r[0]));
            var dd = add(dl, h('dd', r[2] === 'code' ? 'pes-code' : ''));
            if (typeof r[1] === 'object' && r[1].nodeType) dd.appendChild(r[1]);
            else dd.textContent = String(r[1]);
            if (r[3]) add(dd, copyButton(r[1], r[3]));
            sec.weight++;
        });
        return dl;
    }
    function skeleton(parent) {
        add(parent, h('span', 'pes-skel w80'));
        add(parent, h('span', 'pes-skel w60'));
    }
    function failNote(parent, text) {
        var f = add(parent, h('div', 'pes-failnote'));
        add(f, fa('circle-exclamation'));
        f.appendChild(document.createTextNode(text));
        var r = add(f, retryButton());
    }
    function recordGate(vm, sec) {
        var s = lazyState(vm, 'record');
        if (s === 'pending') { sec.state = 'pending'; skeleton(sec.el); return false; }
        if (s === 'failed') { sec.state = 'failed'; add(sec.el, h('div', 'pes-entry-sub', 'Needs the full record, which did not load.')); return false; }
        return true;
    }
    function markRecord(vm, sec) {
        var s = lazyState(vm, 'record');
        if (s && s !== 'ready' && !sec.state) {
            sec.state = s;
            var head = sec.el.firstChild;
            add(head, h('span', 'pes-sec-state ' + (s === 'pending' ? 'is-pending' : 'is-partial'), s === 'pending' ? 'loading' : 'card only'));
        }
    }

    function factRows(vm, keep) {
        return (vm.facts || []).filter(function (f) {
            if (keep && keep.indexOf(f.key) === -1) return false;
            return !(f.kind === 'time' && !f.value);
        }).map(function (f) {
            var v = f.kind === 'time' ? stamp(f.value) : f.value;
            return [f.label, v, f.kind === 'code' ? 'code' : null, f.key === 'uuid' ? 'UUID' : null];
        });
    }

    function labelsSection(vm, list) {
        var L = vm.labels;
        var tags = [], clusters = [];
        (L.taxonomies || []).forEach(function (g) { tags = tags.concat(g.tags); });
        (L.galaxies || []).forEach(function (g) {
            clusters = clusters.concat(g.clusters.map(function (c) {
                return Object.assign({ galaxy: g.label || g.key }, c);
            }));
        });
        var sec = section('labels', 'Tags and clusters', tags.length + clusters.length || null,
                          tags.length ? 'taxonomies' : null, vm);
        if (!recordKnown(vm) && vm.entity === 'attribute') { recordGate(vm, sec); list.push(sec); return; }
        if (!tags.length && !clusters.length) return;
        var described = vm.entity !== 'event';
        var tState = lazyState(vm, 'taxonomies');
        if (tags.length) {
            add(sec.el, chipCollection(tags.map(function (t) {
                var m = t.meaning;
                return { name: t.name, colour: t.colour, local: t.local, relationship_type: t.relationship_type,
                         numerical_value: m && m.numerical_value, count: t.count };
            }), false));
            if (described && tState === 'pending') skeleton(sec.el);
            if (described) tags.forEach(function (t) {
                var m = meaningLine(vm, t);
                if (m && m.text) meaning(sec.el, t.value || t.predicate || t.name, m.text);
            });
            if (described && tState === 'failed') add(sec.el, h('div', 'pes-entry-sub', 'What these tags mean could not be loaded.'));
        }
        if (clusters.length) {
            add(sec.el, chipCollection(clusters.map(function (c) {
                return { value: c.value, galaxy: c.galaxy, local: c.local, count: c.count,
                         description: c.detail && c.detail.description };
            }), true));
            clusters.forEach(function (c) {
                if (c.detail && c.detail.description) meaning(sec.el, c.value, firstSentence(c.detail.description));
            });
        }
        sec.weight += 2 + Math.ceil((tags.length + clusters.length) / 4);
        list.push(sec);
    }

    function meaning(parent, name, text) {
        var p = add(parent, h('div', 'pes-meaning'));
        add(p, h('b', '', name + ' '));
        p.appendChild(document.createTextNode(text));
    }

    // Tags or clusters grouped as the event page groups them, each with how
    // many of the node's attributes carry it.
    function chipCollection(items, isCluster) {
        if (!window.TagChips) {
            var plain = h('div', 'pes-chips');
            items.forEach(function (it) {
                var n = it.count > 1 ? '×' + it.count : null;
                add(plain, isCluster ? clusterChip(it.value, n, it.galaxy, it.local) : tagChip(it.name, it.colour, n));
            });
            return plain;
        }
        var box = h('div', 'pes-labels');
        box.innerHTML = isCluster ? window.TagChips.clusters(items, { href: noHref, searchUrl: '' })
                                  : window.TagChips.collection(items, { searchUrl: '' });
        var counts = {};
        items.forEach(function (it) {
            if (it.count > 1) counts[String(isCluster ? it.value : it.name).trim().toLowerCase()] = it.count;
        });
        [].forEach.call(box.querySelectorAll(isCluster ? '[data-cluster-item]' : '[data-tag-item]'), function (unit) {
            var n = counts[unit.getAttribute(isCluster ? 'data-cluster-name' : 'data-tag-name')];
            var tail = n && unit.querySelector('.hg-tail');
            if (tail) add(tail, h('small', 'hg-n', '×' + n)).title = 'On ' + n + ' attributes';
        });
        return box;
    }
    function firstSentence(text) {
        var t = String(text).replace(/\s+/g, ' ').trim();
        var m = /^(.{40,220}?[.!?])\s/.exec(t + ' ');
        return m ? m[1] : (t.length > 220 ? t.slice(0, 217) + '…' : t);
    }

    function warninglistSection(vm, list, perAttribute) {
        if (!vm.warninglists || !vm.warninglists.length) return;
        var sec = section('warninglists', 'Warninglists', vm.warninglists.length, 'warninglists', vm);
        var ul = add(sec.el, h('ul', 'pes-entries'));
        var s = lazyState(vm, 'warninglists');
        vm.warninglists.forEach(function (w) {
            var li = add(ul, h('li', 'pes-entry'));
            var top = add(li, h('div', 'pes-entry-top'));
            add(top, h('span', 'pes-entry-name', w.name));
            if (perAttribute && w.count) add(top, h('span', 'pes-entry-fig', plural(w.count, 'attribute')));
            var sub = add(li, h('div', 'pes-entry-sub'));
            var bits = [];
            if (w.category) bits.push(w.category.replace(/_/g, ' '));
            if (w.type) bits.push(w.type);
            sub.textContent = bits.join(' · ');
            if (w.match) {
                sub.appendChild(document.createTextNode(bits.length ? ' · matches ' : 'matches '));
                add(sub, h('span', 'pes-code', w.match));
            }
            if (s === 'pending') skeleton(li);
            else if (w.description) add(li, h('div', 'pes-meaning', w.description));
            sec.weight += 2;
        });
        if (s === 'failed') add(sec.el, h('div', 'pes-entry-sub', 'The lists’ descriptions could not be loaded.'));
        list.push(sec);
    }

    function sightingSection(vm, list) {
        if (!recordKnown(vm)) {
            var g = section('sightings', 'Sightings', null, null, vm);
            recordGate(vm, g);
            list.push(g);
            return;
        }
        var s = vm.sightings;
        if (!s || !s.total) return;
        var sec = section('sightings', 'Sightings', s.total, null, vm);
        var bar = add(sec.el, h('div', 'pes-bar'));
        [['s', s.sighting], ['fp', s.false_positive], ['ex', s.expiration]].forEach(function (p) {
            if (!p[1]) return;
            var i = add(bar, h('i', p[0]));
            i.style.width = (100 * p[1] / s.total) + '%';
        });
        rows(sec, [
            ['Sighted', s.sighting || null],
            ['False positive', s.false_positive || null],
            ['Expired', s.expiration || null],
            ['First', s.first ? stamp(s.first) : null],
            ['Last', s.last && s.last !== s.first ? stamp(s.last) : null]
        ]);
        var ul = add(sec.el, h('ul', 'pes-entries'));
        ul.style.marginTop = '6px';
        s.orgs.forEach(function (o) {
            var li = add(ul, h('li', 'pes-entry'));
            var top = add(li, h('div', 'pes-entry-top'));
            add(top, monogram(o.name));
            add(top, h('span', 'pes-entry-name', o.name));
            add(top, h('span', 'pes-entry-fig', '×' + o.count));
            sec.weight++;
        });
        list.push(sec);
    }

    function seenSection(vm, list) {
        var known = recordKnown(vm);
        var srcs = known ? (vm.sources || []) : [];
        var corr = vm.correlations;
        if (!srcs.length && !corr && known && !vm.feed_hit_unnamed) return;
        var sec = section('seen', 'Seen elsewhere', null, null, vm);
        var r = [];
        if (corr) r.push(['Correlations', String(corr.count)]);
        if (vm.feed_hit_unnamed) r.push(['Feed hit', 'yes, unnamed']);
        rows(sec, r);
        if (!known) { markRecord(vm, sec); recordGate(vm, sec); list.push(sec); return; }
        if (srcs.length) {
            var ul = add(sec.el, h('ul', 'pes-entries'));
            ul.style.marginTop = r.length ? '6px' : '0';
            srcs.forEach(function (src) {
                var li = add(ul, h('li', 'pes-entry'));
                var top = add(li, h('div', 'pes-entry-top'));
                var n = add(top, h('span', 'pes-entry-name'));
                add(n, fa(src.type === 'feed' ? 'rss' : 'server'));
                n.firstChild.style.cssText = 'font-size:10px;margin-right:5px;color:var(--pes-feed-ink)';
                n.appendChild(document.createTextNode(src.name || (src.type + ' ' + src.id)));
                if (src.events) add(top, h('span', 'pes-entry-fig', plural(src.events, 'event')));
                var bits = [src.provider, src.format ? src.format + ' format' : null].filter(Boolean);
                if (bits.length) add(li, h('div', 'pes-entry-sub', bits.join(' · ')));
                sec.weight++;
            });
        }
        list.push(sec);
    }

    /* ── analyst data, drawn as AnalystData/thread.ctp draws it ── */
    function titleCase(s) {
        return String(s).replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }
    function analystCard(it) {
        var card = h('div', 'pes-ad-card is-' + it.kind);
        var top = add(card, h('div', 'pes-ad-top'));
        if (it.distribution) {
            var dist = add(top, fa(DIST_ICON[it.distribution] || 'share-nodes'));
            dist.classList.add('pes-ad-dist');
            dist.title = it.distribution;
        }
        if (it.kind === 'opinion') {
            if (it.opinion !== null) {
                var mood = it.opinion === 50 ? 'is-neutral' : it.opinion > 50 ? 'is-agree' : 'is-disagree';
                add(top, h('span', 'pes-ad-opinion ' + mood,
                           titleCase(it.opinion_label) + ' · ' + Math.round(it.opinion) + '/100'));
            }
            if (it.text) add(card, h('div', 'pes-ad-text', it.text));
        } else {
            add(top, h('div', 'pes-ad-text', it.text));
        }
        var meta = [];
        if (it.authors) meta.push([fa('user'), it.authors]);
        if (it.created) meta.push([fa('clock'), it.created]);
        if (meta.length) {
            var m = add(card, h('div', 'pes-ad-meta'));
            meta.forEach(function (bit, i) {
                if (i) m.appendChild(document.createTextNode(' · '));
                stripItem(m, bit);
            });
        }
        if (it.children && it.children.length) {
            var replies = add(card, h('div', 'pes-ad-replies'));
            it.children.forEach(function (c) { add(replies, analystCard(c)); });
        }
        return card;
    }
    function analystThread(a) {
        var wrap = h('div', 'pes-ad');
        [['note', 'Notes', 'analyst-note'], ['opinion', 'Opinions', 'analyst-opinion']].forEach(function (g) {
            var roots = (a.roots || []).filter(function (it) { return it.kind === g[0]; });
            if (!roots.length) return;
            var group = add(wrap, h('div', 'pes-ad-group'));
            var head = add(group, h('div', 'pes-ad-h is-' + g[0]));
            add(head, mi('simple', g[2]));
            head.appendChild(document.createTextNode(g[1] + ' (' + roots.length + ')'));
            roots.forEach(function (it) { add(group, analystCard(it)); });
        });
        return wrap;
    }

    function analystSection(vm, list) {
        var a = vm.analyst;
        if (!recordKnown(vm)) return;
        if (!a) return;
        var sec = section('analyst', 'Analyst data', a.items.length + a.relationships, null, vm);
        if (a.relationships) rows(sec, [['Relationships', a.relationships]]);
        add(sec.el, analystThread(a));
        sec.weight += 2 * a.items.length;
        list.push(sec);
    }

    function eventRelations(vm, list) {
        var rel = vm.relations || {};
        var known = recordKnown(vm);
        var ebState = lazyState(vm, 'extended_by');
        var sec = section('relations', 'Related', null, 'extended_by', vm);
        var r = [];
        if (known) {
            r.push(['Related events', rel.related_events ? String(rel.related_events) : 'None']);
            if (rel.extends) r.push(['Extends', rel.extends.uuid, 'code', 'UUID']);
        }
        rows(sec, r);
        if (!known) { markRecord(vm, sec); recordGate(vm, sec); }
        if (known && rel.reports && rel.reports.length) {
            add(sec.el, h('div', 'pes-group-h', null)).appendChild(h('span', 'pes-group-name', 'Reports'));
            var ul = add(sec.el, h('ul', 'pes-entries'));
            rel.reports.forEach(function (rp) {
                var li = add(ul, h('li', 'pes-entry'));
                add(li, h('div', 'pes-entry-name', rp.name));
                if (rp.timestamp) add(li, h('div', 'pes-entry-sub', stamp(rp.timestamp)));
                sec.weight += 2;
            });
        }
        var eb = add(sec.el, h('div'));
        eb.style.marginTop = '6px';
        var ebh = add(eb, h('div', 'pes-group-h'));
        add(ebh, h('span', 'pes-group-name', 'Extended by'));
        if (ebState === 'pending') skeleton(eb);
        else if (ebState === 'failed') failNote(eb, 'Extending events could not be loaded.');
        else if (rel.extended_by && rel.extended_by.length) {
            var eul = add(eb, h('ul', 'pes-entries'));
            rel.extended_by.forEach(function (e) {
                var li = add(eul, h('li', 'pes-entry'));
                add(li, h('div', 'pes-entry-name', e.info));
                if (e.org) add(li, h('div', 'pes-entry-sub', e.org));
            });
        } else add(eb, h('div', 'pes-entry-sub', 'No event extends this one.'));
        list.push(sec);
    }

    function attributeRelations(vm, list, nav) {
        var rel = vm.relations || {};
        var sec = section('relations', 'Belongs to', null, null, vm);
        var r = [];
        if (rel.object) r.push(['Object', objectLink(rel.object, nav)]);
        if (rel.event) r.push(['Event', rel.event.self ? 'This event (' + rel.event.id + ')' : 'Event ' + rel.event.id]);
        rows(sec, r);
        if (rel.referenced_by && rel.referenced_by.length) {
            var ul = add(sec.el, h('ul', 'pes-entries'));
            ul.style.marginTop = '6px';
            rel.referenced_by.forEach(function (x) {
                var li = add(ul, h('li', 'pes-entry'));
                add(li, h('div', 'pes-entry-name', x.source.label + ' → ' + x.relationship_type));
            });
        }
        list.push(sec);
    }

    function objectLink(obj, nav) {
        if (!nav || !obj.uuid || !nav.selectable(obj.uuid)) return obj.name;
        var b = h('button', 'pes-inline-link', obj.name);
        b.type = 'button';
        b.title = 'Select this object';
        b.addEventListener('click', function () { nav.select(obj.uuid); });
        return b;
    }

    function objectRelations(vm, list) {
        var refs = vm.relations && vm.relations.references;
        if (!refs || !(refs.out.length + refs.in.length)) return;
        var sec = section('relations', 'References', refs.out.length + refs.in.length, null, vm);
        if (!refs.out.length && !refs.in.length) add(sec.el, h('div', 'pes-entry-sub', 'None, in or out.'));
        var ul = add(sec.el, h('ul', 'pes-entries'));
        refs.out.forEach(function (x) {
            var li = add(ul, h('li', 'pes-entry'));
            add(li, h('div', 'pes-entry-name', '→ ' + x.relationship_type + ' ' + (x.target.label || x.target.uuid)));
            if (x.comment) add(li, h('div', 'pes-entry-sub', x.comment));
        });
        refs.in.forEach(function (x) {
            var li = add(ul, h('li', 'pes-entry'));
            add(li, h('div', 'pes-entry-name', '← ' + (x.source.label || x.source.uuid) + ' ' + x.relationship_type));
        });
        list.push(sec);
    }

    function childrenSection(vm, list, nav) {
        var kids = vm.children || [];
        var sec = section('children', 'Attributes', kids.length, null, vm);
        var ul = add(sec.el, h('ul', 'pes-attrs'));
        var SHOW = 8;
        kids.forEach(function (k, i) {
            var li = add(ul, h('li', 'pes-attr'));
            if (i >= SHOW) li.hidden = true;
            add(li, h('div', 'pes-attr-rel', (k.relation || k.type) + (k.relation && k.type ? ' · ' + k.type : '')));
            add(li, attrValue(vm, k));
            var marks = add(li, h('div', 'pes-attr-marks'));
            if (k.to_ids) add(marks, idsMark(true)).title = 'IDS flag on';
            if (k.warninglisted) add(marks, warnMark(k));
            if (k.tags + k.clusters) { add(marks, fa('tag')); marks.appendChild(document.createTextNode(String(k.tags + k.clusters))); }
            if (k.correlations && k.correlations.count) { add(marks, fa('arrows-left-right')); marks.appendChild(document.createTextNode(String(k.correlations.count))); }
            selectable(li, nav, k.uuid, k.relation || k.type);
        });
        sec.weight += Math.min(kids.length, SHOW);
        if (kids.length > SHOW) {
            var more = add(sec.el, h('button', 'pes-attr-more', 'Show all ' + kids.length));
            more.type = 'button';
            more.addEventListener('click', function () {
                [].forEach.call(ul.children, function (li) { li.hidden = false; });
                more.remove();
            });
        }
        list.push(sec);
    }

    function recordSection(vm, list, extra, keep) {
        var sec = section('record', 'Record', null, null, vm);
        rows(sec, (extra || []).concat(factRows(vm, keep)));
        list.push(sec);
        return sec;
    }

    function detailsFor(vm, nav) {
        var list = [];
        var c = vm.card || {};
        switch (vm.entity) {
        case 'event':
            labelsSection(vm, list);
            seenSection(vm, list);
            eventRelations(vm, list);
            analystSection(vm, list);
            var known = recordKnown(vm);
            var ev = recordSection(vm, list, [
                ['Info', c.info], ['Organisation', c.org], ['Date', c.date],
                ['Distribution', c.distribution], ['Sharing group', c.sharing_group],
                ['Published', c.published ? (c.published_at ? stamp(c.published_at) : 'Yes') : 'No'],
                ['Attributes', c.attributes], ['Objects', c.objects], ['Reports', c.reports]
            ], known ? null : ['uuid', 'id']);
            if (!known) markRecord(vm, ev);
            break;
        case 'attribute':
            warninglistSection(vm, recordKnown(vm) ? list : []);
            if (!recordKnown(vm) && vm.card.marks && vm.card.marks.warninglisted) {
                var wg = section('warninglists', 'Warninglists', null, null, vm);
                recordGate(vm, wg);
                list.push(wg);
            }
            labelsSection(vm, list);
            sightingSection(vm, list);
            seenSection(vm, list);
            attributeRelations(vm, list, nav);
            analystSection(vm, list);
            var at = recordSection(vm, list, [
                ['Value', c.value, 'code'], ['Type', c.type, 'code'], ['Category', c.category], ['Relation', c.relation],
                ['IDS', c.to_ids ? 'Yes' : 'No']
            ], recordKnown(vm) ? null : ['uuid', 'matched']);
            if (!recordKnown(vm)) markRecord(vm, at);
            break;
        case 'object':
            childrenSection(vm, list, nav);
            warninglistSection(vm, list, true);
            labelsSection(vm, list);
            seenSection(vm, list);
            objectRelations(vm, list);
            analystSection(vm, list);
            recordSection(vm, list, [['Template', c.name], ['Meta-category', c.meta_category]]);
            break;
        case 'tag':
            tagMeaningSection(vm, list);
            recordSection(vm, list, [['Colour', colourSwatch(c.colour)],
                                     ['Scope', c.local ? 'Local' : 'Global']]);
            break;
        case 'cluster':
            clusterSections(vm, list);
            break;
        case 'feed': case 'server':
            recordSection(vm, list, [['Name', c.name], ['Provider', c.provider], ['Format', c.format],
                                     ['URL', c.url, 'code', 'URL'], ['Events', c.events], ['On this canvas', plural(c.attributes_here || 0, 'attribute')]]);
            break;
        case 'edge':
            recordSection(vm, list, [['Kind', c.kind_label], ['Relationship', c.relationship_type],
                                     ['Stored', c.authored ? 'Yes — can be deleted' : 'No — derived']]);
            break;
        }
        return list;
    }

    function colourSwatch(hex) {
        if (!hex) return null;
        var s = h('span', 'pes-code');
        var sw = add(s, h('span'));
        sw.style.cssText = 'display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px;box-shadow:inset 0 0 0 1px rgba(127,127,127,.5);background:' + hex;
        s.appendChild(document.createTextNode(hex));
        return s;
    }

    function tagMeaningSection(vm, list) {
        var sec = section('meaning', 'Meaning', null, vm.lazy && vm.lazy.taxonomies ? 'taxonomies' : null, vm);
        var s = lazyState(vm, 'taxonomies');
        var m = vm.meaning;
        if (s === 'pending') skeleton(sec.el);
        else if (s === 'failed') failNote(sec.el, 'The taxonomy could not be loaded.');
        else if (!m) {
            add(sec.el, h('div', 'pes-entry-sub', vm.card.namespace
                ? 'No installed taxonomy defines ' + vm.card.namespace + '.' : 'A plain tag, outside any taxonomy.'));
        } else {
            rows(sec, [
                ['Taxonomy', m.taxonomy && m.taxonomy.namespace], ['Exclusive', m.taxonomy && m.taxonomy.exclusive ? 'Yes' : null],
                ['Predicate', m.predicate && (m.predicate.expanded || m.predicate.value)],
                ['Value', m.value && (m.value.expanded || m.value.value)],
                ['Numerical', m.numerical_value]
            ]);
            var d = (m.value && m.value.description) || (m.predicate && m.predicate.description) || (m.taxonomy && m.taxonomy.description);
            if (d) add(sec.el, h('div', 'pes-meaning', d)).style.marginTop = '6px';
        }
        list.push(sec);
    }

    function clusterSections(vm, list) {
        var d = vm.detail;
        var state = lazyState(vm, 'cluster') || lazyState(vm, 'cluster_tag');
        var about = section('about', 'About', null, lazyState(vm, 'cluster') ? 'cluster' : (lazyState(vm, 'cluster_tag') ? 'cluster_tag' : null), vm);
        if (state === 'pending') skeleton(about.el);
        else if (state === 'failed') failNote(about.el, 'The cluster could not be loaded.');
        else if (!d) add(about.el, h('div', 'pes-entry-sub', 'No cluster describes this tag.'));
        else {
            if (d.description) {
                var p = add(about.el, h('div', 'pes-meaning', firstSentence(d.description)));
                p.title = d.description;
                about.weight += 2;
            }
            if (d.synonyms && d.synonyms.length) {
                var sh = add(about.el, h('div', 'pes-group-h'));
                sh.style.marginTop = '6px';
                add(sh, h('span', 'pes-group-name', 'Synonyms'));
                var chips = add(about.el, h('div', 'pes-chips'));
                d.synonyms.forEach(function (s) { add(chips, h('span', 'pes-jump-chip pes-code', s)); });
                about.weight += 2;
            }
        }
        list.push(about);
        if (d) {
            var keys = Object.keys(d.meta || {});
            var meta = section('meta', 'Meta', keys.length + (d.relations ? 1 : 0), null, vm);
            var r = keys.map(function (k) {
                var vals = d.meta[k];
                var text = vals.slice(0, 4).join(', ') + (vals.length > 4 ? ' +' + (vals.length - 4) : '');
                return [k.replace(/[-_]/g, ' '), text, /refs|url/.test(k) ? 'code' : null];
            });
            if (d.relations) r.push(['relations', String(d.relations)]);
            rows(meta, r);
            list.push(meta);
        }
        var c = vm.card;
        recordSection(vm, list, [
            ['Value', c.value], ['Galaxy', d && d.galaxy_name || c.galaxy], ['Tag', c.tag_name, 'code', 'tag name'],
            ['Source', d && d.source], ['Authors', d && d.authors && d.authors.length ? d.authors.join(', ') : null],
            ['UUID', d && d.uuid || vm.uuid, 'code', 'UUID'], ['ID', d && d.id, 'code']
        ]);
    }

    /* ── the fold ──────────────────────────────────────────── */
    function drawFold(slot, vm, sections) {
        var root = add(slot, h('div', 'pes pes-fold'));
        root.setAttribute('data-hue', HUE[vm.entity] || 'neutral');
        var weight = sections.reduce(function (s, x) { return s + x.weight; }, 0);
        var open = weight <= FOLD_OPEN_BELOW;
        if (open) root.classList.add('is-open');

        var bar = add(root, h('button', 'pes-fold-bar'));
        bar.type = 'button';
        bar.appendChild(document.createTextNode('Everything else'));
        add(bar, fa('chevron-down'));
        bar.addEventListener('click', function () { root.classList.toggle('is-open'); });

        var jump = add(root, h('div', 'pes-jump'));
        sections.forEach(function (s) {
            var b = add(jump, h('button', s.state ? 'is-' + s.state : ''));
            b.type = 'button';
            b.appendChild(document.createTextNode(s.title));
            if (s.count !== null && s.count !== undefined) add(b, h('b', '', String(s.count)));
            b.addEventListener('click', function () { reveal(s.id); });
        });

        var body = add(root, h('div', 'pes-fold-body'));
        sections.forEach(function (s) { body.appendChild(s.el); });

        function reveal(id) {
            root.classList.add('is-open');
            var el = body.querySelector('[data-sec="' + id + '"]');
            if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
        return { reveal: reveal };
    }

    /* ══ a multi-selection: what the nodes share ═══════════════ */
    var Q = (function () {
        function has(v) { return v !== undefined && v !== null && v !== ''; }
        function el(tag, cls, parent, text) {
            var e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text !== undefined && text !== null) e.textContent = String(text);
            if (parent) parent.appendChild(e);
            return e;
        }
        function icon(cls, parent) { return el('i', cls, parent); }
        function mispIcon(name, parent) { return el('span', 'misp-icon misp-simple misp-icon-' + name, parent); }
        function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
        function subHead(parent, text, tier, end) {
            var h = el('div', 'pesq-sub-h', parent, text);
            if (tier === 'pinned' || tier === 'preferred') {
                var t = el('span', 'pesq-tier', h);
                icon(tier === 'pinned' ? 'fa-solid fa-thumbtack' : 'fa-solid fa-star', t);
                t.appendChild(document.createTextNode(tier));
            }
            if (has(end)) el('span', 'pesq-end', h, end);
            return h;
        }
        function tagChip(parent, name, colour, opts) {
            opts = opts || {};
            if (window.TagChips) {
                var chip = hingeChip(name, colour, has(opts.count) ? '×' + opts.count : null,
                    opts.title ? name + ' — ' + opts.title : null);
                parent.appendChild(chip);
                return chip;
            }
            var c = el('span', 'pesq-chip is-tag' + (opts.lead ? ' is-lead' : ''), parent);
            var sw = el('i', 'pesq-sw', c);
            sw.style.background = colour || 'transparent';
            el('span', 'pesq-chip-t', c, name);
            if (has(opts.count)) el('span', 'pesq-chip-n', c, '×' + opts.count);
            c.title = name + (opts.title ? ' — ' + opts.title : '');
            return c;
        }
        function clusterChip(parent, name, opts) {
            opts = opts || {};
            if (window.TagChips) {
                var chip = hingeCluster(name, opts.galaxy, {
                    display: 'full', suffix: has(opts.count) ? '×' + opts.count : null
                });
                parent.appendChild(chip);
                return chip;
            }
            var c = el('span', 'pesq-chip is-galaxy', parent);
            mispIcon('galaxy', c);
            el('span', 'pesq-chip-t', c, name);
            if (has(opts.count)) el('span', 'pesq-chip-n', c, '×' + opts.count);
            c.title = opts.title || name;
            return c;
        }
        function chipList(parent, items, max, draw) {
            var box = el('div', 'pesq-chips', parent);
            items.slice(0, max).forEach(function (it) { draw(box, it); });
            if (items.length > max) {
                var d = el('details', 'pesq-more', parent);
                var s = el('summary', '', d);
                var k = el('span', 'pesq-more-k', s);
                el('span', '', k, '+' + (items.length - max) + ' more');
                var rest = el('div', 'pesq-chips', d);
                rest.style.marginTop = '4px';
                items.slice(max).forEach(function (it) { draw(rest, it); });
            }
            return box;
        }
        function question(parent, ask, verdict, draw, closed) {
            var d = el('details', 'pesq-q', parent);
            if (!closed) d.open = true;
            var s = el('summary', '', d);
            el('span', 'pesq-ask', s, ask);
            var v = el('span', 'pesq-verdict', s);
            if (verdict.tone) v.setAttribute('data-tone', verdict.tone);
            if (verdict.node) v.appendChild(verdict.node);
            else v.appendChild(document.createTextNode(verdict.text));
            if (verdict.state === 'pending' || verdict.state === 'failed') {
                var st = el('span', 'pesq-state', v);
                icon(verdict.state === 'pending' ? 'fa-solid fa-circle-notch fa-spin' : 'fa-solid fa-circle-exclamation', st);
                st.title = verdict.state === 'pending' ? 'Still reading; this may change' : 'Part of this could not be read';
                if (verdict.state === 'failed') st.appendChild(document.createTextNode('partial'));
            }
            var body = el('div', 'pesq-ev', d);
            draw(body);
            return d;
        }
    
        var KIND_WORD = { event: ['event', 'events'], object: ['object', 'objects'],
                          attribute: ['attribute', 'attributes'], tag: ['tag', 'tags'],
                          cluster: ['cluster', 'clusters'], feed: ['feed', 'feeds'], server: ['server', 'servers'],
                          edge: ['link', 'links'] };

        function header(vm) {
            var c = vm.card;
            var root = el('div', 'pesq-root pesq-head');
            root.setAttribute('data-hue', 'neutral');
            var eb = el('div', 'pesq-eyebrow', root);
            icon('fa-solid fa-layer-group', eb);
            el('span', '', eb, 'Selection');
            var links = c.kinds.every(function (k) { return k.entity === 'edge'; });
            el('div', 'pesq-title', root, plural(c.count, links ? 'link' : 'node') + ' selected');
            el('div', 'pesq-sub', root, c.kinds.map(function (k) {
                var w = KIND_WORD[k.entity] || [k.entity, k.entity + 's'];
                return k.count + ' ' + (k.count === 1 ? w[0] : w[1]);
            }).join(' · '));
            return root;
        }

        function shared(vm) {
            var total = vm.card.count;
            var body = el('div', 'pesq-root pesq-body pesq-shared');
            var sh = vm.shared;
            var labels = [].concat(sh.taxonomies.map(function (t) { return Object.assign({ k: 'tag' }, t); }),
                                   sh.galaxies.map(function (g) { return Object.assign({ k: 'cluster' }, g); }));
            var all = labels.filter(function (l) { return l.count === total; });
            var some = labels.filter(function (l) { return l.count > 1 && l.count < total; });
            var v = all.length ? { text: plural(all.length, 'label') + ' on all ' + total + (some.length ? ' · ' + some.length + ' on some' : '') }
                : some.length ? { text: 'Nothing on all ' + total + ' · ' + plural(some.length, 'label') + ' on some' }
                              : { text: 'No label in common', tone: 'quiet' };
            question(body, 'What do they share?', v, function (ev) {
                function grid(parent, list) {
                    var g = el('div', 'pesq-share', parent);
                    list.forEach(function (l) {
                        if (l.k === 'tag') tagChip(g, l.name, l.colour);
                        else clusterChip(g, l.name, { galaxy: l.galaxy, title: (l.galaxy ? l.galaxy + ': ' : '') + l.name });
                        el('span', 'pesq-share-n', g, l.count + '/' + total);
                        var bar = el('div', 'pesq-bar' + (l.count === total ? ' is-all' : ''), g);
                        el('b', '', bar).style.width = Math.round(l.count / total * 100) + '%';
                    });
                }
                var common = all.concat(some);
                if (common.length) grid(ev, common);
                var once = labels.filter(function (l) { return l.count === 1; });
                if (once.length) {
                    var b = el('div', 'pesq-block', ev);
                    subHead(b, 'On one node only', null, String(once.length));
                    chipList(b, once, 6, function (box, l) {
                        if (l.k === 'tag') tagChip(box, l.name, l.colour);
                        else clusterChip(box, l.name, { galaxy: l.galaxy });
                    });
                }
            });
            var orgs = sh.orgs || [];
            var ov = orgs.length === 1 ? { text: 'All by ' + orgs[0].name }
                : orgs.length ? { text: plural(orgs.length, 'org') + ' · ' + orgs[0].name + ' ' + orgs[0].count + '/' + total }
                              : { text: 'No organisation recorded', tone: 'quiet' };
            question(body, 'Who made them?', ov, function (ev) {
                var g = el('div', 'pesq-share', ev);
                orgs.forEach(function (o) {
                    var ch = el('span', 'pesq-chip is-org', g);
                    mispIcon('organisation', ch);
                    el('span', 'pesq-chip-t', ch, o.name);
                    el('span', 'pesq-share-n', g, o.count + '/' + total);
                    var bar = el('div', 'pesq-bar' + (o.count === total ? ' is-all' : ''), g);
                    el('b', '', bar).style.width = Math.round(o.count / total * 100) + '%';
                });
            });
            return body;
        }

        return { header: header, shared: shared };
    }());

    /* ══ entry ═════════════════════════════════════════════════ */
    var NOTICES = { event: eventNotices, attribute: attributeNotices, object: objectNotices, tag: tagNotices,
                    cluster: clusterNotices, feed: sourceNoticesFor, server: sourceNoticesFor, edge: edgeNotices };

    root.MispPivotSidebarView = {
        // The node's identity and card, then what to notice about it. `jump`
        // opens the detail at the section a notice points to; `actions` are
        // drawn as a row of buttons under the card; `nav` { selectable(uuid),
        // select(uuid) } reaches the node's attributes or its object.
        header: function (vm, jump, actions, nav) {
            if (vm.entity === 'multi') return Q.header(vm);
            var N = new Notices();
            (NOTICES[vm.entity] || function () {})(vm, N);
            return drawHeader(h('div'), vm, N, { jump: jump || function () {}, actions: actions || [], nav: nav });
        },
        // Everything else, below one fold.
        detail: function (vm, nav) {
            var slot = h('div');
            var fold = drawFold(slot, vm, detailsFor(vm, nav));
            return { el: slot.firstChild, reveal: fold.reveal };
        },
        // A multi-selection: the labels and orgs its nodes share.
        shared: function (vm) {
            return Q.shared(vm);
        },
        // The notes and opinions MispPivotSidebar.analyst() found on a record.
        analystThread: analystThread
    };
}(typeof window !== 'undefined' ? window : this));
