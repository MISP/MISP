/* =============================================================================
   MISP Pivot Explorer — sidebar view-models
   =============================================================================
   Pure functions from a selected node's data (plus the lazy reads it asks for)
   to what the sidebar says about it. No DOM, no fetch: the explorer performs the
   reads this module describes and hands the answers back.

   docs/dev/pivot-explorer-sidebar-prd.md §5.1.
   ============================================================================= */
(function (root) {
    'use strict';

    /* ── context priority: a port of ValueLabelPriority ─────── */
    // app/Lib/Tools/ValueIntelligence/ValueLabelPriority.php, method for
    // method, so the explorer ranks tags and clusters exactly as the event
    // page does.
    // tests/js/pivot-sidebar-model.test.js checks the two agree.
    var PINNED = 'pinned', PREFERRED = 'preferred', DEMOTED = 'demoted';
    var TIERS = [PINNED, PREFERRED, DEMOTED];
    var TAXONOMIES = 'taxonomies', GALAXIES = 'galaxies';
    var UNLISTED = { rank: 2, within: 0, tier: null };

    var HANDLING = {
        tlp: { 'red': 0, 'amber+strict': 1, 'amber': 2, 'green': 3, 'clear': 4, 'white': 4 },
        pap: { 'red': 0, 'amber': 1, 'green': 2, 'clear': 3, 'white': 3 }
    };

    function isObject(v) {
        return v !== null && typeof v === 'object';
    }

    function lower(v) {
        return String(v).trim().toLowerCase();
    }

    function section(profile) {
        if (!isObject(profile)) return {};
        if (isObject(profile.parameters) && isObject(profile.parameters.context)) {
            return profile.parameters.context;
        }
        return isObject(profile.context) ? profile.context : {};
    }

    function isPlan(candidate) {
        if (!isObject(candidate)) return false;
        return [TAXONOMIES, GALAXIES].every(function (scope) {
            return isObject(candidate[scope]) && TIERS.every(function (tier) {
                return Array.isArray(candidate[scope][tier]);
            });
        });
    }

    function planFor(profile) {
        if (isPlan(profile)) return profile;
        var declared = section(profile);
        var plan = {};
        [TAXONOMIES, GALAXIES].forEach(function (scope) {
            var lists = isObject(declared[scope]) ? declared[scope] : {};
            var taken = {};
            plan[scope] = {};
            TIERS.forEach(function (tier) {
                plan[scope][tier] = [];
                if (!Array.isArray(lists[tier])) return;
                lists[tier].forEach(function (key) {
                    if (typeof key !== 'string' && typeof key !== 'number') return;
                    key = lower(key);
                    if (key === '' || taken[key]) return;
                    taken[key] = true;
                    plan[scope][tier].push(key);
                });
            });
        });
        return plan;
    }

    function declares(plan, scope) {
        var scopes = scope == null ? [TAXONOMIES, GALAXIES] : [scope];
        return scopes.some(function (one) {
            return TIERS.some(function (tier) {
                return !!(plan[one] && plan[one][tier] && plan[one][tier].length);
            });
        });
    }

    function places(plan, scope) {
        var ranks = { pinned: 0, preferred: 1, demoted: 3 };
        var out = {};
        TIERS.forEach(function (tier) {
            ((plan[scope] && plan[scope][tier]) || []).forEach(function (key, within) {
                out[key] = { rank: ranks[tier], within: within, tier: tier };
            });
        });
        return out;
    }

    function keyOf(group) {
        if (!group || group.key == null) return null;
        var key = lower(group.key);
        return key === '' ? null : key;
    }

    function namespaceOf(name) {
        if (typeof name !== 'string' && typeof name !== 'number') return null;
        name = String(name).trim();
        var at = name.indexOf(':');
        return at <= 0 ? null : name.slice(0, at).toLowerCase();
    }

    function severity(tag, namespace, order) {
        if (!tag || !tag.name) return Infinity;
        var name = String(tag.name).toLowerCase();
        var prefix = namespace + ':';
        if (name.indexOf(prefix) !== 0) return Infinity;
        var predicate = name.slice(prefix.length);
        return Object.prototype.hasOwnProperty.call(order, predicate) ? order[predicate] : Infinity;
    }

    // The most restrictive label of a handling group, and how many others it
    // stands for; null for any other group, or one holding a single tag.
    function lead(group) {
        var key = keyOf(group);
        if (key === null || !HANDLING[key] || !group.tags || group.tags.length < 2) return null;
        var best = null, bestRank = null;
        group.tags.forEach(function (tag) {
            var rank = severity(tag, key, HANDLING[key]);
            if (bestRank === null || rank < bestRank) { best = tag; bestRank = rank; }
        });
        return best === null ? null : { tag: best, others: group.tags.length - 1 };
    }

    function byRank(a, b) {
        return (a.rank - b.rank) || (a.within - b.within) || (a.at - b.at);
    }

    // Groups carrying `key`, ordered pinned, preferred, unlisted, demoted, each
    // marked with its `priority`. A plan declaring nothing changes nothing.
    function order(groups, plan, scope) {
        plan = planFor(plan);
        if (!groups.length || !declares(plan, scope)) return groups;
        var at = places(plan, scope);
        return groups.map(function (group, i) {
            var key = keyOf(group);
            var place = key !== null && at[key] ? at[key] : UNLISTED;
            var out = Object.assign({}, group, { priority: place.tier });
            if (place.tier === PINNED) {
                var l = lead(out);
                if (l !== null) out.lead = l;
            }
            return { rank: place.rank, within: place.within, at: i, group: out };
        }).sort(byRank).map(function (row) { return row.group; });
    }

    function ranked(labels, placesByScope, scope) {
        var first = {};
        return labels.map(function (label, i) {
            var dimension = scope !== null ? scope
                : (label && (lower(label.scope || '') === TAXONOMIES || lower(label.scope || '') === GALAXIES)
                    ? lower(label.scope) : null);
            var key = keyOf(label);
            var place = dimension !== null && key !== null && placesByScope[dimension]
                && placesByScope[dimension][key] ? placesByScope[dimension][key] : UNLISTED;
            var sev = 0;
            if (place.tier !== null && dimension === TAXONOMIES && HANDLING[key]) {
                sev = severity(label, key, HANDLING[key]);
            }
            var group = 0;
            if (place.tier !== null && key !== null) {
                var id = dimension + '|' + key;
                if (!(id in first)) first[id] = i;
                group = first[id];
            }
            return { rank: place.rank, within: place.within, group: group, severity: sev, at: i,
                     label: Object.assign({}, label, { priority: place.tier }) };
        }).sort(function (a, b) {
            if (a.rank !== b.rank) return a.rank - b.rank;
            if (a.within !== b.within) return a.within - b.within;
            if (a.group !== b.group) return a.group - b.group;
            if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
            return a.at - b.at;
        }).map(function (row) { return row.label; });
    }

    // Individual labels of one dimension; inside a listed handling namespace
    // the most restrictive comes first.
    function labels(list, plan, scope) {
        plan = planFor(plan);
        if (!list.length || !declares(plan, scope)) return list;
        var p = {};
        p[scope] = places(plan, scope);
        return ranked(list, p, scope);
    }

    // Pinned keys the groups do not carry, optionally floored by the keys the
    // instance permits (an instance-disabled taxonomy beats a pin, D41).
    function absent(groups, plan, scope, permitted) {
        plan = planFor(plan);
        var pins = (plan[scope] && plan[scope][PINNED]) || [];
        if (!pins.length) return [];
        var present = {};
        groups.forEach(function (g) { var k = keyOf(g); if (k !== null) present[k] = true; });
        var floor = null;
        if (Array.isArray(permitted)) {
            floor = {};
            permitted.forEach(function (k) { floor[lower(k)] = true; });
        }
        return pins.filter(function (key) {
            return !present[key] && (floor === null || floor[key]);
        }).map(function (key) { return { key: key }; });
    }

    var priority = {
        PINNED: PINNED, PREFERRED: PREFERRED, DEMOTED: DEMOTED,
        TAXONOMIES: TAXONOMIES, GALAXIES: GALAXIES,
        planFor: planFor, declares: declares, order: order, labels: labels,
        absent: absent, lead: lead, namespaceOf: namespaceOf
    };

    /* ── MISP's enumerations ───────────────────────────────── */
    var DISTRIBUTION = { 0: 'Your organisation only', 1: 'This community only', 2: 'Connected communities',
                         3: 'All communities', 4: 'Sharing group', 5: 'Inherit event' };
    var ANALYSIS = { 0: 'Initial', 1: 'Ongoing', 2: 'Completed' };
    var THREAT_LEVEL = { 1: 'High', 2: 'Medium', 3: 'Low', 4: 'Undefined' };
    var EDGE_KINDS = {
        'object-reference':     'Object reference',
        'analyst-relationship': 'Analyst relationship',
        'in-event':             'Belongs to event',
        'correlation':          'Correlation',
        'feed-correlation':     'Seen in a feed',
        'feed-event':           'Feed event',
        'server-correlation':   'Seen on a server',
        'tag':                  'Tagged',
        'cluster-relation':     'Cluster relation'
    };
    // What a user drew and MISP stores, so the sidebar can say it can be deleted.
    var AUTHORED = { 'object-reference': true, 'analyst-relationship': true };

    /* ── small helpers ─────────────────────────────────────── */
    function present(v) {
        return v !== undefined && v !== null && v !== '';
    }

    function num(v) {
        return present(v) && !isNaN(Number(v)) ? Number(v) : null;
    }

    function bool(v) {
        return v === true || v === 1 || v === '1';
    }

    function isDeleted(rec) {
        return !!rec && bool(rec.deleted);
    }

    function fact(key, label, value, kind) {
        return present(value) ? { key: key, label: label, value: value, kind: kind || 'text' } : null;
    }

    function compact(list) {
        return list.filter(Boolean);
    }

    // A value as ValueUrlTool::address() puts it in a /values/* path segment.
    function valueKey(value) {
        return (root.MispValueAddress || require('./value-address.js')).address(value);
    }

    function enumLabel(table, v) {
        var n = num(v);
        return n === null ? null : (table[n] || null);
    }

    function galaxyTag(name) {
        var m = /^misp-galaxy:([^=]+)="(.*)"$/.exec(String(name || ''));
        return m ? { galaxy_type: m[1], value: m[2] } : null;
    }

    // `ns:predicate="value"` → its three parts; a plain tag has none.
    function tagParts(name) {
        var m = /^([^:]+):([^=]+?)(?:="(.*)")?$/.exec(String(name || ''));
        return m ? { namespace: m[1], predicate: m[2], value: m[3] === undefined ? null : m[3] } : null;
    }

    /* ── the event payload, indexed once ───────────────────── */
    // Every live record by uuid with its owner, and each element's inbound
    // object references (the payload only carries them outbound).
    var _indexes = typeof WeakMap === 'function' ? new WeakMap() : null;

    function indexOf(event) {
        var ev = event && event.Event;
        if (!ev) return null;
        var cached = _indexes && _indexes.get(event);
        if (cached) return cached;
        var byUuid = {}, inbound = {}, clusters = {}, refs = {};
        function clustersOf(rec) {
            (rec.Galaxy || []).forEach(function (g) {
                (g.GalaxyCluster || []).forEach(function (c) {
                    var hit = { cluster: c, galaxy: g };
                    if (c.uuid && !clusters[c.uuid]) clusters[c.uuid] = hit;
                    if (c.tag_name && !clusters['tag:' + c.tag_name]) clusters['tag:' + c.tag_name] = hit;
                });
            });
        }
        if (ev.uuid) byUuid[ev.uuid] = { type: 'event', rec: ev };
        clustersOf(ev);
        (ev.Attribute || []).forEach(function (a) {
            if (isDeleted(a)) return;
            byUuid[a.uuid] = { type: 'attribute', rec: a };
            clustersOf(a);
        });
        (ev.Object || []).forEach(function (o) {
            if (isDeleted(o)) return;
            byUuid[o.uuid] = { type: 'object', rec: o };
            (o.Attribute || []).forEach(function (a) {
                if (isDeleted(a)) return;
                byUuid[a.uuid] = { type: 'attribute', rec: a, object: o };
                clustersOf(a);
            });
        });
        (ev.Object || []).forEach(function (o) {
            if (isDeleted(o)) return;
            (o.ObjectReference || []).forEach(function (r) {
                if (isDeleted(r)) return;
                refs[r.uuid] = { ref: r, source: o };
                (inbound[r.referenced_uuid] = inbound[r.referenced_uuid] || []).push({ ref: r, source: o });
            });
        });
        var index = { ev: ev, byUuid: byUuid, inbound: inbound, clusters: clusters, refs: refs };
        if (_indexes) _indexes.set(event, index);
        return index;
    }

    function own(env, uuid) {
        var index = indexOf(env.event);
        return index && uuid ? index.byUuid[uuid] || null : null;
    }

    function elementLabel(env, uuid) {
        var hit = own(env, uuid);
        if (!hit) return null;
        if (hit.type === 'object') return hit.rec.name;
        if (hit.type === 'event') return hit.rec.info;
        return (hit.rec.object_relation || hit.rec.type) + ': ' + hit.rec.value;
    }

    /* ── lazy reads ────────────────────────────────────────── */
    // A read the payload cannot answer is declared, not performed: the caller
    // fetches `request`, stores the parsed body under env.lazy[key], and
    // builds again. `state` is ready, pending or failed (env.lazy[key] ===
    // false marks a failed read).
    function lazy(vm, env, key, request, apply) {
        var answer = env.lazy ? env.lazy[key] : undefined;
        var slot = { state: 'pending', request: request };
        if (answer === false) slot.state = 'failed';
        else if (answer !== undefined) {
            slot.state = 'ready';
            apply(answer);
        }
        vm.lazy[key] = slot;
    }

    /* ── labels: tags grouped by taxonomy, clusters by galaxy ─ */
    // A MISP record's Tag and Galaxy lists, in the shape node data uses.
    function labelsOfRecord(rec) {
        var named = {};
        (rec.Galaxy || []).forEach(function (g) {
            (g.GalaxyCluster || []).forEach(function (c) {
                if (c.tag_name) named[c.tag_name] = { galaxy: g, cluster: c };
            });
        });
        var tags = [], clusters = [], seen = {};
        function cluster(tagName, local) {
            var n = named[tagName], g = galaxyTag(tagName) || {};
            clusters.push({
                tag_name: tagName, local: local || undefined,
                galaxy_type: n ? n.galaxy.type : g.galaxy_type, galaxy_name: n ? n.galaxy.name : undefined,
                value: n ? n.cluster.value : (g.value || tagName), uuid: n ? n.cluster.uuid : undefined
            });
        }
        (rec.Tag || []).forEach(function (t) {
            if (!t || !t.name || t.hide_tag || seen[t.name]) return;
            seen[t.name] = true;
            if (bool(t.is_galaxy) || galaxyTag(t.name)) { cluster(t.name, bool(t.local)); return; }
            tags.push({ name: t.name, colour: t.colour, local: bool(t.local) || undefined,
                        relationship_type: t.relationship_type || undefined });
        });
        Object.keys(named).forEach(function (tagName) { if (!seen[tagName]) cluster(tagName, false); });
        return { tags: tags, clusters: clusters };
    }

    function clusterDetail(c, galaxy) {
        var meta = {};
        Object.keys(c.meta || {}).forEach(function (k) {
            if (k !== 'synonyms') meta[k] = [].concat(c.meta[k]);
        });
        (c.GalaxyElement || []).forEach(function (e) {
            if (e.key !== 'synonyms') (meta[e.key] = meta[e.key] || []).push(e.value);
        });
        var synonyms = [].concat((c.meta && c.meta.synonyms) || [],
            (c.GalaxyElement || []).filter(function (e) { return e.key === 'synonyms'; })
                .map(function (e) { return e.value; }));
        return {
            id: c.id, uuid: c.uuid, value: c.value, tag_name: c.tag_name,
            galaxy_type: c.type || (galaxy && galaxy.type), galaxy_name: galaxy ? galaxy.name : (c.Galaxy && c.Galaxy.name),
            description: c.description || null,
            synonyms: synonyms,
            meta: meta,
            relations: (c.GalaxyClusterRelation || []).length + (c.TargetingClusterRelation || []).length,
            source: c.source || null, authors: [].concat(c.authors || [])
        };
    }

    // A cluster the payload carries in full, by uuid or by its tag.
    function knownCluster(env, c) {
        var index = indexOf(env.event);
        if (!index || !c) return null;
        return (c.uuid && index.clusters[c.uuid]) || (c.tag_name && index.clusters['tag:' + c.tag_name]) || null;
    }

    // One taxonomy's text for a tag, from /tags/search's row; null for a tag
    // no installed taxonomy defines.
    function tagMeaning(row) {
        if (!row.Taxonomy) return null;
        var p = row.TaxonomyPredicate || null;
        var entry = p && p.TaxonomyEntry && p.TaxonomyEntry[0];
        return {
            taxonomy: row.Taxonomy ? { namespace: row.Taxonomy.namespace, description: row.Taxonomy.description,
                                       exclusive: bool(row.Taxonomy.exclusive) } : null,
            predicate: p ? { value: p.value, expanded: p.expanded || null, description: p.description || null } : null,
            value: entry ? { value: entry.value, expanded: entry.expanded || null, description: entry.description || null } : null,
            numerical_value: num(entry ? entry.numerical_value : (p ? p.numerical_value : null))
        };
    }

    function meaningsByName(rows) {
        var out = {};
        (Array.isArray(rows) ? rows : []).forEach(function (r) {
            if (r && r.Tag && r.Tag.name) out[r.Tag.name] = tagMeaning(r);
        });
        return out;
    }

    var TAG_SEARCH = '/tags/search/0/1.json';

    // Tags by taxonomy namespace and clusters by galaxy type, each list of
    // groups in the order the analyst's plan gives, plus the pins missing.
    function labelSection(vm, env, tags, clusters, key) {
        var groups = [], byKey = {};
        (tags || []).forEach(function (t) {
            var parts = tagParts(t.name);
            var k = parts ? parts.namespace.toLowerCase() : '';
            if (!byKey['t:' + k]) {
                byKey['t:' + k] = { key: k || null, label: parts ? parts.namespace : null, tags: [] };
                groups.push(byKey['t:' + k]);
            }
            byKey['t:' + k].tags.push({
                name: t.name, colour: t.colour || null, local: !!t.local,
                relationship_type: t.relationship_type || null,
                predicate: parts ? parts.predicate : null, value: parts ? parts.value : null,
                count: t.count || undefined, meaning: null
            });
        });
        var galaxies = [], byType = {};
        (clusters || []).forEach(function (c) {
            var k = String(c.galaxy_type || '').toLowerCase();
            if (!byType[k]) {
                byType[k] = { key: k || null, label: c.galaxy_name || c.galaxy_type || null, clusters: [] };
                galaxies.push(byType[k]);
            }
            var detail = knownCluster(env, c);
            byType[k].clusters.push(Object.assign({
                value: c.value, uuid: c.uuid || null, tag_name: c.tag_name || null, local: !!c.local,
                count: c.count || undefined
            }, detail ? { detail: clusterDetail(detail.cluster, detail.galaxy) } : {}));
        });
        var section = {
            taxonomies: order(groups, env.plan, TAXONOMIES),
            galaxies: order(galaxies, env.plan, GALAXIES),
            missing: {
                taxonomies: env.permitted ? absent(groups, env.plan, TAXONOMIES, env.permitted.taxonomies) : null,
                galaxies: env.permitted ? absent(galaxies, env.plan, GALAXIES, env.permitted.galaxies) : null
            }
        };
        var names = [];
        section.taxonomies.forEach(function (g) {
            g.tags.forEach(function (t) { if (g.key) names.push(t.name); });
        });
        if (names.length) {
            lazy(vm, env, key || 'taxonomies', { method: 'POST', url: TAG_SEARCH, body: { tag: names } },
                function (rows) {
                    var meanings = meaningsByName(rows);
                    section.taxonomies.forEach(function (g) {
                        g.tags.forEach(function (t) {
                            t.meaning = meanings[t.name] || null;
                            if (t.meaning && t.meaning.taxonomy && !g.description) {
                                g.description = t.meaning.taxonomy.description;
                            }
                        });
                    });
                });
        }
        return section;
    }

    /* ── context blocks shared by elements ─────────────────── */
    function warninglists(vm, env, list) {
        var seen = {}, out = [];
        (list || []).forEach(function (w) {
            if (!w || w.warninglist_id == null || seen[w.warninglist_id]) return;
            seen[w.warninglist_id] = true;
            out.push({ id: String(w.warninglist_id), name: w.warninglist_name,
                       category: w.warninglist_category || null,
                       false_positive: w.warninglist_category === 'false_positive',
                       match: w.match || null, count: w.count || undefined,
                       description: null, type: null });
        });
        if (out.length) {
            lazy(vm, env, 'warninglists',
                { method: 'GET', url: '/warninglists/index/id:' + out.map(function (w) { return w.id; }).join('||') + '.json' },
                function (body) {
                    var byId = {};
                    ((body && body.Warninglists) || []).forEach(function (row) {
                        if (row && row.Warninglist) byId[String(row.Warninglist.id)] = row.Warninglist;
                    });
                    out.forEach(function (w) {
                        var d = byId[w.id];
                        if (d) { w.description = d.description || null; w.type = d.type || null; }
                    });
                });
        }
        return out;
    }

    // Feeds and servers that hold a value, by id.
    function sources(rec) {
        var out = [];
        [['Feed', 'feed'], ['Server', 'server']].forEach(function (s) {
            var map = rec && rec[s[0]];
            Object.keys(map || {}).forEach(function (k) {
                var src = map[k];
                if (!src || src.id == null) return;
                if (out.some(function (o) { return o.type === s[1] && o.id === String(src.id); })) return;
                out.push({ type: s[1], id: String(src.id), name: src.name || null, provider: src.provider || null,
                           format: src.source_format || null,
                           events: src.event_uuids ? src.event_uuids.length : null });
            });
        });
        return out;
    }

    function foldSightings(rows) {
        var out = { total: 0, sighting: 0, false_positive: 0, expiration: 0, first: null, last: null, orgs: [] };
        var orgs = {};
        (rows || []).forEach(function (row) {
            var s = row.Sighting || row;
            var type = num(s.type) || 0;
            out.total++;
            out[type === 1 ? 'false_positive' : type === 2 ? 'expiration' : 'sighting']++;
            var at = num(s.date_sighting);
            if (at !== null) {
                if (out.first === null || at < out.first) out.first = at;
                if (out.last === null || at > out.last) out.last = at;
            }
            var org = (s.Organisation || row.Organisation || {}).name;
            if (org) orgs[org] = (orgs[org] || 0) + 1;
        });
        out.orgs = Object.keys(orgs).map(function (name) { return { name: name, count: orgs[name] }; })
            .sort(function (a, b) { return b.count - a.count || (a.name < b.name ? -1 : 1); });
        return out;
    }

    function opinionLabel(v) {
        return v >= 81 ? 'Strongly agree' : v >= 61 ? 'Agree' : v >= 41 ? 'Neutral'
             : v >= 21 ? 'Disagree' : 'Strongly disagree';
    }

    // Notes and opinions on a record, and those left on them in turn: flat in
    // `items`, and as the thread they form from `roots` down `children`.
    function analyst(rec) {
        var items = [];
        var roots = (function walk(r, depth) {
            var level = [];
            ['Note', 'Opinion'].forEach(function (k) {
                (r[k] || []).forEach(function (a) {
                    var op = k === 'Opinion' ? num(a.opinion) : null;
                    var it = {
                        kind: k === 'Note' ? 'note' : 'opinion', uuid: a.uuid, depth: depth,
                        text: k === 'Note' ? (a.note || '') : (a.comment || ''),
                        opinion: op, opinion_label: op === null ? null : opinionLabel(op),
                        authors: a.authors || (a.Orgc && a.Orgc.name) || null, org_uuid: a.orgc_uuid || null,
                        created: a.created || null, modified: a.modified || null,
                        language: a.language || null,
                        distribution: enumLabel(DISTRIBUTION, a.distribution)
                    };
                    items.push(it);
                    level.push(it);
                    it.children = walk(a, depth + 1);
                });
            });
            return level;
        })(rec || {}, 0);
        var relationships = ((rec && rec.Relationship) || []).filter(function (r) { return !isDeleted(r); });
        if (!items.length && !relationships.length) return null;
        var direct = items.filter(function (i) { return i.kind === 'opinion' && i.depth === 0 && i.opinion !== null; });
        var mean = direct.length ? direct.reduce(function (s, i) { return s + i.opinion; }, 0) / direct.length : null;
        return {
            notes: items.filter(function (i) { return i.kind === 'note'; }).length,
            opinions: items.filter(function (i) { return i.kind === 'opinion'; }).length,
            relationships: relationships.length,
            mood: mean === null ? 'none' : mean < 41 ? 'disputed' : mean > 60 ? 'endorsed' : 'neutral',
            items: items, roots: roots
        };
    }

    function correlations(env, type, uuid) {
        var n = typeof env.correlations === 'function' ? env.correlations(type, uuid) : null;
        return n === null || n === undefined ? null : { count: n };
    }

    // What a module said, when this element is a result of one (enrichment PRD E5).
    function enrichment(d) {
        if (d.scope !== 'module') return null;
        // Kept in a graph: who kept it, and when the newest of its origins was asked
        var kept = d.kept_by ? String(d.kept_by) : null;
        return {
            modules: (d.modules && d.modules.length ? d.modules : [d.module]).filter(Boolean),
            from_store: !!d.from_store,
            age: kept && d.ran_at ? Math.max(0, Math.floor(Date.now() / 1000) - Number(d.ran_at))
                : d.age == null ? null : Number(d.age),
            kept_by: kept,
            untyped: !!d.untyped, candidate_types: d.candidate_types || []
        };
    }

    // A module's value links to its profile only when MISP holds it (E13).
    function profiled(d) {
        return d.scope !== 'module' || !!d.known;
    }

    function provenance(env, d) {
        if (d.scope === 'module') return { scope: 'module', event_id: null, label: 'From enrichment' };
        if (d.scope === 'self') return { scope: 'self', event_id: d.event_id || null, label: 'This event' };
        if (d.event_id) return { scope: 'foreign', event_id: String(d.event_id), label: 'Event ' + d.event_id };
        return d.scope ? { scope: d.scope, event_id: null, label: null } : null;
    }

    function base(entity, d, id) {
        return {
            entity: entity, id: id || null, uuid: d.uuid || null,
            title: d.label || '', subtitle: d.description || '',
            provenance: null, card: {}, facts: [], labels: null, warninglists: [], sources: [],
            correlations: null, sightings: null, analyst: null, relations: {}, children: null,
            links: [], lazy: {}, enrichment: enrichment(d)
        };
    }

    /* ── entities ──────────────────────────────────────────── */
    function eventModel(input, env) {
        var d = input.data;
        var vm = base('event', d, input.id);
        var hit = own(env, d.uuid);
        var rec = hit && hit.type === 'event' ? hit.rec : null;
        vm.provenance = provenance(env, d);
        function build(e) {
            var labelled = e ? labelsOfRecord(e) : { tags: d.tags, clusters: d.clusters };
            vm.card = {
                info: (e && e.info) || d.info || '',
                org: (e && (e.Orgc || e.Org || {}).name) || d.org || null,
                date: (e && e.date) || d.date || null,
                threat_level: enumLabel(THREAT_LEVEL, e ? e.threat_level_id : d.threat_level_id),
                analysis: enumLabel(ANALYSIS, e ? e.analysis : d.analysis),
                distribution: enumLabel(DISTRIBUTION, e ? e.distribution : d.distribution),
                sharing_group: (e && e.SharingGroup && e.SharingGroup.name) || null,
                published: bool(e ? e.published : d.published),
                published_at: num(e ? e.publish_timestamp : d.publish_timestamp) || null,
                attributes: num(e ? e.attribute_count : d.attribute_count),
                objects: e && e.Object ? e.Object.filter(function (o) { return !isDeleted(o); }).length : num(d.object_count),
                reports: e && e.EventReport ? e.EventReport.filter(function (r) { return !isDeleted(r); }).length
                         : num(d.report_count)
            };
            vm.labels = labelSection(vm, env, labelled.tags, labelled.clusters);
            vm.facts = compact([
                fact('uuid', 'UUID', d.uuid, 'code'),
                fact('id', 'Event ID', (e && e.id) || d.event_id || d.id, 'code'),
                fact('timestamp', 'Last change', num(e && e.timestamp), 'time'),
                fact('first_publication', 'First published', num(e && e.first_publication), 'time'),
                fact('feed', 'Feed', d.feed_name)
            ]);
            if (e) {
                vm.analyst = analyst(e);
                vm.sources = sources(e);
                vm.relations.reports = (e.EventReport || []).filter(function (r) { return !isDeleted(r); })
                    .map(function (r) { return { uuid: r.uuid, name: r.name, timestamp: num(r.timestamp) }; });
                vm.relations.related_events = (e.RelatedEvent || []).length;
                if (e.extends_uuid) {
                    vm.relations.extends = { uuid: e.extends_uuid };
                }
            }
        }
        build(rec);
        if (!rec && d.uuid) {
            lazy(vm, env, 'record', { method: 'POST', url: '/events/restSearch',
                                      body: { returnFormat: 'json', uuid: d.uuid, metadata: 1 } },
                function (body) {
                    var e = body && body.response && body.response[0] && body.response[0].Event;
                    if (e) build(e);
                });
        }
        if (vm.uuid) {
            lazy(vm, env, 'extended_by', { method: 'POST', url: '/events/restSearch',
                                           body: { returnFormat: 'json', eventsExtendingUuid: vm.uuid, metadata: 1 } },
                function (body) {
                    vm.relations.extended_by = ((body && body.response) || []).map(function (row) {
                        var e = row.Event || {};
                        return { id: e.id, uuid: e.uuid, info: e.info, org: (e.Orgc || {}).name || null };
                    });
                });
        }
        var id = (rec && rec.id) || d.event_id || d.id;
        if (id && String(id) !== String(env.eventId)) vm.links.push({ kind: 'event', label: 'Open event', path: '/events/view/' + id });
        if (d.feed_id && d.uuid) vm.links.push({ kind: 'feed', label: 'Preview in feed', path: '/feeds/previewEvent/' + d.feed_id + '/' + d.uuid });
        return vm;
    }

    function childModel(env, a, ranks) {
        var labelled = a.Tag || a.Galaxy ? labelsOfRecord(a) : { tags: a.tags || [], clusters: a.clusters || [] };
        var warn = (a.warnings || []).length;
        var names = [];
        (a.warnings || []).forEach(function (w) {
            if (w.warninglist_name && names.indexOf(w.warninglist_name) === -1) names.push(w.warninglist_name);
        });
        var relation = a.object_relation || null;
        var value = a.value == null ? '' : String(a.value);
        return {
            uuid: a.uuid, relation: relation, type: a.type || a['attr-type'] || null,
            value: value, b64: value === '' || !profiled(a) ? null : valueKey(value), to_ids: bool(a.to_ids),
            priority: ranks && relation && ranks[relation] ? ranks[relation] : (a.ui_priority || 0),
            warninglisted: warn > 0, warninglists: names,
            false_positive: (a.warnings || []).some(function (w) { return w.warninglist_category === 'false_positive'; }),
            tags: labelled.tags.length, clusters: labelled.clusters.length,
            correlations: correlations(env, 'attribute', a.uuid)
        };
    }

    function objectModel(input, env) {
        var d = input.data;
        var vm = base('object', d, input.id);
        var hit = own(env, d.uuid);
        var rec = hit && hit.type === 'object' ? hit.rec : null;
        var ranks = rec && env.uiPriorities ? env.uiPriorities[rec.template_uuid + '.' + rec.template_version] : null;
        vm.provenance = provenance(env, d);
        var attrs = rec ? (rec.Attribute || []).filter(function (a) { return !isDeleted(a); })
                        : (input.children || []);
        vm.children = attrs.map(function (a) { return childModel(env, a, ranks); })
            .sort(function (a, b) { return (b.priority - a.priority); });
        vm.card = {
            name: (rec && rec.name) || d.name || null,
            meta_category: (rec && rec['meta-category']) || d['meta-category'] || null,
            attributes: vm.children.length,
            top: vm.children.slice(0, 3)
        };
        // What its attributes carry, counted per attribute.
        var tagCount = {}, tagFirst = [], clusterCount = {}, clusterFirst = [], warnCount = {}, warnFirst = [];
        attrs.forEach(function (a) {
            var l = a.Tag || a.Galaxy ? labelsOfRecord(a) : { tags: a.tags || [], clusters: a.clusters || [] };
            l.tags.forEach(function (t) {
                if (!tagCount[t.name]) { tagCount[t.name] = 0; tagFirst.push(t); }
                tagCount[t.name]++;
            });
            l.clusters.forEach(function (c) {
                if (!clusterCount[c.tag_name]) { clusterCount[c.tag_name] = 0; clusterFirst.push(c); }
                clusterCount[c.tag_name]++;
            });
            (a.warnings || []).forEach(function (w) {
                if (!warnCount[w.warninglist_id]) { warnCount[w.warninglist_id] = 0; warnFirst.push(w); }
                warnCount[w.warninglist_id]++;
            });
        });
        var objLabels = rec ? labelsOfRecord(rec) : { tags: [], clusters: [] };
        vm.labels = labelSection(vm, env,
            objLabels.tags.concat(tagFirst.map(function (t) { return Object.assign({}, t, { count: tagCount[t.name] }); })),
            objLabels.clusters.concat(clusterFirst.map(function (c) { return Object.assign({}, c, { count: clusterCount[c.tag_name] }); })));
        vm.warninglists = warninglists(vm, env, warnFirst.map(function (w) {
            return Object.assign({}, w, { count: warnCount[w.warninglist_id] });
        }));
        vm.correlations = correlations(env, 'object', d.uuid);
        vm.facts = compact([
            fact('comment', 'Comment', rec && rec.comment),
            fact('first_seen', 'First seen', rec && rec.first_seen, 'date'),
            fact('last_seen', 'Last seen', rec && rec.last_seen, 'date'),
            fact('distribution', 'Distribution', enumLabel(DISTRIBUTION, rec && rec.distribution)),
            fact('template', 'Template', rec && rec.template_uuid ? rec.template_uuid + ' v' + rec.template_version : null, 'code'),
            fact('timestamp', 'Last change', num(rec && rec.timestamp), 'time'),
            fact('uuid', 'UUID', d.uuid, 'code')
        ]);
        if (rec) {
            vm.analyst = analyst(rec);
            vm.relations.references = references(env, rec);
            vm.relations.event = { id: rec.event_id || null, self: true };
        }
        vm.value_card = !!env.valueCard;
        var foreign = d.event_id && String(d.event_id) !== String(env.eventId);
        if (foreign) vm.links.push({ kind: 'event', label: 'Open its event', path: '/events/view/' + d.event_id });
        return vm;
    }

    function refTarget(env, uuid, type) {
        var hit = own(env, uuid);
        return { uuid: uuid, type: hit ? hit.type : (String(type) === '1' ? 'object' : 'attribute'),
                 label: elementLabel(env, uuid) };
    }

    function references(env, rec) {
        var index = indexOf(env.event);
        return {
            out: (rec.ObjectReference || []).filter(function (r) { return !isDeleted(r); }).map(function (r) {
                return { uuid: r.uuid, relationship_type: r.relationship_type, comment: r.comment || null,
                         target: refTarget(env, r.referenced_uuid, r.referenced_type) };
            }),
            in: ((index && index.inbound[rec.uuid]) || []).map(function (x) {
                return { uuid: x.ref.uuid, relationship_type: x.ref.relationship_type, comment: x.ref.comment || null,
                         source: { uuid: x.source.uuid, type: 'object', label: x.source.name } };
            })
        };
    }

    // Which of another event's slices brought this attribute onto the canvas.
    function matchedBy(env, keys) {
        if (!Array.isArray(keys) || !keys.length) return null;
        var names = env.matchedLabels || {};
        return keys.map(function (k) { return names[k] || k; }).join(', ');
    }

    function attributeModel(input, env) {
        var d = input.data;
        var vm = base('attribute', d, input.id);
        var hit = own(env, d.uuid);
        var rec = hit && hit.type === 'attribute' ? hit.rec : null;
        vm.provenance = provenance(env, d);
        function build(a, obj) {
            var labelled = a ? labelsOfRecord(a) : { tags: d.tags || [], clusters: d.clusters || [] };
            var warn = a ? a.warnings : d.warnings;
            vm.card = {
                value: a ? String(a.value == null ? '' : a.value) : (d.value || ''),
                type: (a && a.type) || d['attr-type'] || null,
                category: (a && a.category) || d.category || null,
                relation: (a && a.object_relation) || d.object_relation || null,
                to_ids: bool(a ? a.to_ids : d.to_ids),
                marks: {
                    warninglisted: !!(warn && warn.length),
                    tagged: labelled.tags.length + labelled.clusters.length,
                    analyst: a ? (analyst(a) ? true : false) : !!d.analyst_count,
                    feed: !!((a && (a.Feed || a.Server || a.FeedHit)) || d.feed_hit)
                }
            };
            vm.labels = labelSection(vm, env, labelled.tags, labelled.clusters);
            vm.warninglists = warninglists(vm, env, warn);
            vm.facts = compact([
                fact('comment', 'Comment', (a && a.comment) || d.comment),
                fact('first_seen', 'First seen', a && a.first_seen, 'date'),
                fact('last_seen', 'Last seen', a && a.last_seen, 'date'),
                fact('distribution', 'Distribution', enumLabel(DISTRIBUTION, a && a.distribution)),
                fact('timestamp', 'Last change', num(a && a.timestamp), 'time'),
                fact('matched', 'Matched', matchedBy(env, d.matched)),
                fact('uuid', 'UUID', d.uuid, 'code')
            ]);
            if (a) {
                vm.sources = sources(a);
                vm.feed_hit_unnamed = !!a.FeedHit && !vm.sources.length;
                vm.sightings = a.Sighting ? foldSightings(a.Sighting) : null;
                vm.analyst = analyst(a);
            }
            vm.relations.object = obj ? { uuid: obj.uuid, name: obj.name } : null;
            vm.relations.event = { id: (a && a.event_id) || d.event_id || null, self: d.scope === 'self' };
            if (a && obj) {
                var index = indexOf(env.event);
                vm.relations.referenced_by = ((index && index.inbound[a.uuid]) || []).map(function (x) {
                    return { uuid: x.ref.uuid, relationship_type: x.ref.relationship_type,
                             source: { uuid: x.source.uuid, type: 'object', label: x.source.name } };
                });
            }
        }
        build(rec, hit && hit.object);
        vm.correlations = correlations(env, 'attribute', d.uuid);
        if (!rec && d.uuid) {
            lazy(vm, env, 'record', { method: 'POST', url: '/attributes/restSearch',
                                      body: { returnFormat: 'json', uuid: d.uuid, includeSightings: 1,
                                              includeWarninglistHits: 1, includeEventTags: 0 } },
                function (body) {
                    var a = body && body.response && body.response.Attribute && body.response.Attribute[0];
                    if (a) build(a, null);
                });
        }
        vm.value_card = !!env.valueCard;
        vm.profile = vm.card.value === '' || !profiled(d) ? null : { value: vm.card.value, b64: valueKey(vm.card.value) };
        if (d.event_id && String(d.event_id) !== String(env.eventId)) {
            vm.links.push({ kind: 'event', label: 'Open its event', path: '/events/view/' + d.event_id });
        }
        return vm;
    }

    function tagModel(input, env) {
        var d = input.data;
        var vm = base('tag', d, input.id);
        var parts = tagParts(d.name);
        vm.card = { name: d.name, colour: d.colour || null, local: !!d.local,
                    namespace: parts ? parts.namespace : null, predicate: parts ? parts.predicate : null,
                    value: parts ? parts.value : null };
        vm.meaning = null;
        if (parts) {
            lazy(vm, env, 'taxonomies', { method: 'POST', url: TAG_SEARCH, body: { tag: [d.name] } },
                function (rows) { vm.meaning = meaningsByName(rows)[d.name] || null; });
        }
        vm.priority = parts ? (order([{ key: parts.namespace }], env.plan, TAXONOMIES)[0].priority || null) : null;
        return vm;
    }

    function clusterModel(input, env) {
        var d = input.data;
        var vm = base('cluster', d, input.id);
        var known = knownCluster(env, d);
        vm.card = { value: d.value, galaxy: d.galaxy_name || d.galaxy_type || null, tag_name: d.tag_name || null };
        vm.detail = known ? clusterDetail(known.cluster, known.galaxy) : null;
        // Another event's cluster: found by its tag first when the node has
        // no uuid, then read in full — by id when known, as one uuid can name
        // a cluster in several galaxies.
        var uuid = known ? null : (d.cluster_id ? String(d.cluster_id) : d.uuid);
        if (!known && !uuid && d.tag_name) {
            lazy(vm, env, 'cluster_tag', { method: 'POST', url: TAG_SEARCH, body: { tag: [d.tag_name] } },
                function (rows) {
                    var row = (Array.isArray(rows) ? rows : []).filter(function (r) { return r && r.GalaxyCluster; })[0];
                    if (row) uuid = row.GalaxyCluster.id || row.GalaxyCluster.uuid;
                });
        }
        if (uuid) {
            lazy(vm, env, 'cluster', { method: 'GET', url: '/galaxy_clusters/view/' + uuid + '.json' },
                function (body) { if (body && body.GalaxyCluster) vm.detail = clusterDetail(body.GalaxyCluster, null); });
        }
        vm.priority = d.galaxy_type ? (order([{ key: d.galaxy_type }], env.plan, GALAXIES)[0].priority || null) : null;
        var id = vm.detail ? vm.detail.id : null;
        if (id) vm.links.push({ kind: 'cluster', label: 'Open cluster', path: '/galaxy_clusters/view/' + id });
        return vm;
    }

    function sourceModel(input, env) {
        var d = input.data;
        var vm = base(d.type, d, input.id);
        var held = 0;
        var index = indexOf(env.event);
        if (index) {
            Object.keys(index.byUuid).forEach(function (uuid) {
                var hit = index.byUuid[uuid];
                if (hit.type !== 'attribute') return;
                if (sources(hit.rec).some(function (s) { return s.type === d.type && s.id === String(d.source_id); })) held++;
            });
        }
        vm.card = { name: d.label, provider: d.provider || null, format: d.source_format || null,
                    url: d.url || null, events: num(d.feed_events), attributes_here: held };
        vm.facts = compact([fact('id', d.type === 'feed' ? 'Feed ID' : 'Server ID', d.source_id, 'code')]);
        if (d.type === 'feed' && d.source_id) vm.links.push({ kind: 'feed', label: 'Browse feed', path: '/feeds/previewIndex/' + d.source_id });
        if (d.type === 'server' && d.source_id) vm.links.push({ kind: 'server', label: 'Browse server', path: '/servers/previewIndex/' + d.source_id });
        return vm;
    }

    function endpoint(env, n) {
        if (!n) return null;
        var d = n.data || {};
        return { id: n.id || null, type: d.type || null, label: d.label || null, uuid: d.uuid || null };
    }

    function edgeModel(input, env) {
        var d = input.data || {};
        var vm = base('edge', d, input.id);
        var index = indexOf(env.event);
        var ref = d.uuid && index && index.refs[d.uuid] ? index.refs[d.uuid].ref : null;
        vm.title = d.relationship_type || EDGE_KINDS[d.kind] || d.kind || '';
        vm.subtitle = EDGE_KINDS[d.kind] || d.kind || '';
        vm.card = {
            kind: d.kind || null, kind_label: EDGE_KINDS[d.kind] || d.kind || null,
            relationship_type: d.relationship_type || null,
            from: endpoint(env, input.from), to: endpoint(env, input.to),
            authored: !!AUTHORED[d.kind] && !!d.uuid,
            derived: !AUTHORED[d.kind]
        };
        vm.facts = compact([
            fact('comment', 'Comment', ref && ref.comment),
            fact('authors', 'Authors', d.authors),
            fact('timestamp', 'Last change', num(ref && ref.timestamp), 'time'),
            fact('uuid', 'UUID', d.uuid, 'code')
        ]);
        return vm;
    }

    // What a multi-selection shares: kinds, labels and organisations, each
    // with how many of the selection carry it.
    function multiModel(input, env) {
        var items = input.items || [];
        var vm = base('multi', {}, null);
        var kinds = {}, tags = {}, clusters = {}, orgs = {};
        function count(map, key, extra) {
            if (!map[key]) map[key] = Object.assign({ count: 0 }, extra);
            map[key].count++;
        }
        items.forEach(function (item) {
            var d = item.data || {};
            count(kinds, d.type || 'node', { entity: d.type || 'node' });
            var hit = own(env, d.uuid);
            var l = hit ? labelsOfRecord(hit.rec) : { tags: d.tags || [], clusters: d.clusters || [] };
            var seenT = {}, seenC = {};
            l.tags.forEach(function (t) {
                if (seenT[t.name]) return;
                seenT[t.name] = true;
                count(tags, t.name, { name: t.name, colour: t.colour || null, key: (tagParts(t.name) || {}).namespace || null });
            });
            l.clusters.forEach(function (c) {
                if (seenC[c.tag_name]) return;
                seenC[c.tag_name] = true;
                count(clusters, c.tag_name, { name: c.value, tag_name: c.tag_name, galaxy: c.galaxy_name || c.galaxy_type || null,
                                              key: c.galaxy_type || null });
            });
            var org = d.org || (hit && hit.type === 'event' && (hit.rec.Orgc || {}).name);
            if (org) count(orgs, org, { name: org });
        });
        function list(map) {
            return Object.keys(map).map(function (k) { return map[k]; })
                .sort(function (a, b) { return b.count - a.count; });
        }
        vm.title = items.length + ' selected';
        vm.card = { count: items.length, kinds: list(kinds) };
        vm.shared = {
            taxonomies: labels(list(tags), env.plan, TAXONOMIES),
            galaxies: labels(list(clusters), env.plan, GALAXIES),
            orgs: list(orgs)
        };
        return vm;
    }

    var BUILDERS = { event: eventModel, object: objectModel, attribute: attributeModel, tag: tagModel,
                     cluster: clusterModel, feed: sourceModel, server: sourceModel };

    /**
     * The sidebar's view-model for one selection.
     *
     * input  { kind: 'node', id, data, children? }     children: another event's object's attribute data
     *      | { kind: 'edge', id, data, from, to }      from/to: { id, data } of its ends
     *      | { kind: 'nodes', items: [node input…] }
     * env    { event        the explorer's /events/view payload
     *          eventId      the page's event
     *          plan         ValueLabelPriority::planFor() of the viewer's profile
     *          permitted    { taxonomies: [ns…], galaxies: [type…] } enabled on the instance, or null
     *          uiPriorities template uuid.version → { relation: rank }
     *          matchedLabels a card slice's key → what it brought (Attributes, IDS indicators, …)
     *          correlations (type, uuid) → count, or null when not known
     *          valueCard    MISP.value_hover_card: values open the hover card
     *          lazy         key → parsed response of a declared read; false when it failed }
     */
    function build(input, env) {
        env = env || {};
        if (input.kind === 'nodes') return multiModel(input, env);
        if (input.kind === 'edge') return edgeModel(input, env);
        var type = input.data && input.data.type;
        var fn = BUILDERS[type];
        return fn ? fn(input, env) : base(type || 'node', input.data || {}, input.id);
    }

    /**
     * pivotick's nodePropertiesMap rows, one per value, so the aggregated
     * table of a multi-selection counts what the nodes share.
     */
    function propertyRows(input, env) {
        var d = input.data || {};
        var hit = own(env || {}, d.uuid);
        var l = hit ? labelsOfRecord(hit.rec) : { tags: d.tags || [], clusters: d.clusters || [] };
        var rows = [{ name: 'Element', value: d.type }];
        if (d.org) rows.push({ name: 'Organisation', value: d.org });
        if (d['attr-type']) rows.push({ name: 'Attribute type', value: d['attr-type'] });
        if (d.category) rows.push({ name: 'Category', value: d.category });
        if (d.name && d.type === 'object') rows.push({ name: 'Template', value: d.name });
        if (d.name && d.type === 'tag') rows.push({ name: 'Tag', value: d.name });
        if (d.value && d.type === 'cluster') {
            rows.push({ name: 'Galaxy cluster', value: (d.galaxy_name || d.galaxy_type) + ': ' + d.value });
        }
        l.tags.forEach(function (t) { rows.push({ name: 'Tag', value: t.name }); });
        l.clusters.forEach(function (c) { rows.push({ name: 'Galaxy cluster', value: (c.galaxy_name || c.galaxy_type) + ': ' + c.value }); });
        (d.warnings || []).forEach(function (w) { rows.push({ name: 'Warninglist', value: w.warninglist_name }); });
        return rows;
    }

    var api = {
        priority: priority,
        build: build,
        valueKey: valueKey,
        propertyRows: propertyRows,
        analyst: analyst,
        DISTRIBUTION: DISTRIBUTION, ANALYSIS: ANALYSIS, THREAT_LEVEL: THREAT_LEVEL, EDGE_KINDS: EDGE_KINDS
    };

    root.MispPivotSidebar = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : this));
