/**
 * misp-report-markdown.js — event report markdown for the Overmind theme.
 *
 * An event report is not plain markdown: it also carries MISP's own element
 * syntax, which the stock theme resolves with jQuery + doT + CodeMirror
 * (js/markdownEditor/event-report.js). Overmind's BS5 pages load none of
 * those, so this is the vanilla equivalent, and the ONE place that knows how
 * to turn a report's content into HTML — the report's General tab preview, the
 * event view teaser and the Edit Content live preview all go through it.
 *
 *   @[attribute](uuid)       an attribute, as a type / value pill
 *   @![attribute](uuid)      the attachment behind an attribute, as a picture
 *   @[object](uuid)          an object, as a name / first-value pill
 *   @[tag](tag name)         a tag, in its own colour (a galaxy cluster tag
 *                            resolves to `type ↦ value` once looked up)
 *   @[galaxymatrix](uuid)    a galaxy, as a card linking to it
 *   {{ variable }}           an event report template variable
 *
 * Everything the pills need comes from one request —
 * /eventReports/getProxyMISPElements/<id> — except a tag that is not attached
 * to the event, which /tags/search resolves in one batched call per render.
 *
 * Usage:
 *   var r = MispReportMarkdown.create({reportId: 12, eventId: 34});
 *   r.ready.then(function () { r.render(raw, document.getElementById('x')); });
 *
 * The styling lives in mainOvermind.css (.markdown-preview-body, .ov-md-*), so
 * CSS stays authoritative the way it does everywhere else in the theme.
 */
(function (window, document) {
    'use strict';

    if (window.MispReportMarkdown) { return; }

    var UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

    /* The scopes `@[...]` accepts. Anything else renders as an invalid pill,
       which is how a typo becomes visible instead of silently disappearing. */
    var SCOPES = ['attribute', 'object', 'tag', 'galaxymatrix'];

    /* A rendering rule turned off keeps the element parsed but prints its bare
       value — the stock theme's "Markdown rendering rules" menu. */
    var RENDERING_RULES = [
        'attribute', 'attribute-picture', 'object',
        'object-attribute', 'tag', 'galaxymatrix'
    ];

    var GREY = '#8a8f98';

    function base() {
        return typeof window.baseurl === 'string' ? window.baseurl : '';
    }

    function esc(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /* Mirrors MISPElementHTMLFormatterTool::getTextColour so a tag reads the
       same here as it does in a server-rendered report. */
    function textColour(rgb) {
        if (typeof rgb !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(rgb)) {
            return '#ffffff';
        }
        var r = parseInt(rgb.substr(1, 2), 16);
        var g = parseInt(rgb.substr(3, 2), 16);
        var b = parseInt(rgb.substr(5, 2), 16);
        return (((2 * r) + b + (3 * g)) / 6) < 127 ? '#ffffff' : '#000000';
    }

    /* Galaxy and cluster icons are stored bare ("bug", "btc", "android"), and
       a brand glyph only draws under fab. js/font-awesome-helper.js holds Font
       Awesome's brand list — the same file the stock report editor loads — so
       the answer comes from there; the fallback covers the brands MISP's own
       galaxies actually use, for a page that did not load the helper. */
    var FALLBACK_BRANDS = [
        'android', 'apple', 'bitcoin', 'btc', 'chrome', 'firefox', 'github',
        'gitlab', 'internet-explorer', 'linux', 'optin-monster', 'safari',
        'ubuntu', 'windows'
    ];

    function faClass(icon) {
        if (!icon) { return 'fas fa-atlas'; }
        var namespace;
        if (typeof window.getFontAwesomeNamespace === 'function') {
            namespace = window.getFontAwesomeNamespace(icon);
        } else {
            namespace = FALLBACK_BRANDS.indexOf(icon) !== -1 ? 'fab' : 'fas';
        }
        return namespace + ' fa-' + icon;
    }

    /* ───────────────────────────── parsing ─────────────────────────────── */

    /**
     * A tag name may hold spaces, quotes and brackets — `misp-galaxy:mitre-
     * attack-pattern="Multi-hop Proxy - T1090.003"` — so its destination is
     * read by matching parentheses rather than by markdown-it's link rules.
     */
    function parseDestinationValue(str, pos, max) {
        var level = 0;
        var start = pos;
        var code;
        while (pos < max) {
            code = str.charCodeAt(pos);
            if (code < 0x20 || code === 0x7F) { break; }
            if (code === 0x5C /* \ */ && pos + 1 < max) { pos += 2; continue; }
            if (code === 0x28 /* ( */) { level++; }
            if (code === 0x29 /* ) */) {
                level--;
                if (level === 0) { pos++; break; }
            }
            pos++;
        }
        if (start === pos || level !== 0) { return {ok: false}; }
        return {ok: true, pos: pos, str: str.slice(start, pos)};
    }

    /* markdown-it inline rule for `@[scope](id)` / `@![scope](id)`. */
    function mispElementRule(state, silent) {
        var oldPos = state.pos;
        var max = state.posMax;
        var labelStart, labelEnd, scope, elementId, res, pos;

        if (state.src.charCodeAt(state.pos) !== 0x40 /* @ */) { return false; }
        var isPicture = state.src.charCodeAt(state.pos + 1) === 0x21 /* ! */;
        if (isPicture) {
            if (state.src.charCodeAt(state.pos + 2) !== 0x5B /* [ */) { return false; }
            labelStart = state.pos + 3;
            labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 2, false);
        } else {
            if (state.src.charCodeAt(state.pos + 1) !== 0x5B /* [ */) { return false; }
            labelStart = state.pos + 2;
            labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 1, false);
        }
        if (labelEnd < 0) { return false; }
        scope = state.src.slice(labelStart, labelEnd);

        pos = labelEnd + 1;
        if (pos < max && state.src.charCodeAt(pos) === 0x28 /* ( */) {
            if (scope === 'tag') {
                res = parseDestinationValue(state.src, pos, state.posMax);
            } else {
                res = state.md.helpers.parseLinkDestination(state.src, pos, state.posMax);
            }
            if (res.ok) {
                /* parseLinkDestination keeps whatever trails the link, so walk
                   back to the closing paren that belongs to us. */
                var destinationEnd = res.str.length - 1;
                var trailing = 0;
                for (var i = res.str.length - 1; i > 1; i--) {
                    if (res.str.charCodeAt(i) === 0x29 /* ) */) {
                        destinationEnd = i;
                        break;
                    }
                    trailing++;
                }
                elementId = res.str.substring(1, destinationEnd);
                pos = res.pos - 1 - trailing;
            }
        }
        if (pos >= max || state.src.charCodeAt(pos) !== 0x29 /* ) */) {
            state.pos = oldPos;
            return false;
        }
        pos++;

        if (scope === 'tag') {
            if (!/^[^\n)]+$/.test(elementId)) { return false; }
        } else if (!UUID_RE.test(elementId)) {
            return false;
        }

        if (!silent) {
            var token = state.push(isPicture ? 'misp_picture' : 'misp_element', 'span', 0);
            token.meta = {scope: scope, elementId: elementId};
            token.content = state.src.slice(oldPos, pos);
        }
        state.pos = pos;
        state.posMax = max;
        return true;
    }

    /**
     * Template variables reach a view as MISP hands them over — a list of rows,
     * each possibly still wrapped in its model name — so both that and a plain
     * {name: value} map are accepted, and a view passes what it has.
     */
    function normaliseTemplateVariables(value) {
        if (!value) { return {}; }
        if (!Array.isArray(value)) { return value; }
        var map = {};
        value.forEach(function (entry) {
            var variable = entry.EventReportTemplateVariable || entry;
            if (variable && variable.name) {
                map[variable.name] = variable.value === undefined ? '' : variable.value;
            }
        });
        return map;
    }

    /* ───────────────────────────── renderer ────────────────────────────── */

    function Renderer(options) {
        options = options || {};
        this.reportId = options.reportId || null;
        this.eventId = options.eventId || null;
        this.templateVariables = normaliseTemplateVariables(options.templateVariables);
        this.onProxyError = options.onProxyError || null;
        this.invalidMessage = options.invalidMessage || 'invalid scope or id';

        this.proxy = null;
        this.tagData = {};        /* tag name → resolved tag payload */
        this.tagsMissing = {};    /* tag name → true once looked up in vain */
        this.popovers = [];
        this.openPopover = null;
        this.dismissBound = false;

        this.renderingRules = {};
        for (var i = 0; i < RENDERING_RULES.length; i++) {
            this.renderingRules[RENDERING_RULES[i]] = true;
        }
        this.parsingRules = {image: true, link: true, misp: true};

        this.md = window.markdownit({html: false, linkify: true, typographer: true});
        this._installRules();
        this.ready = this._loadProxy();
    }

    Renderer.prototype._installRules = function () {
        var self = this;

        this.md.inline.ruler.push('misp_element', mispElementRule);
        this.md.renderer.rules.misp_element = function (tokens, idx) {
            return self._renderElement(tokens[idx].meta);
        };
        this.md.renderer.rules.misp_picture = function (tokens, idx) {
            return self._renderPicture(tokens[idx].meta);
        };
    };

    Renderer.prototype._loadProxy = function () {
        var self = this;
        if (!this.reportId) { return Promise.resolve(null); }
        return fetch(base() + '/eventReports/getProxyMISPElements/' + this.reportId, {
            headers: {'Accept': 'application/json'}
        }).then(function (response) {
            if (!response.ok) { throw new Error('HTTP ' + response.status); }
            return response.json();
        }).then(function (data) {
            self.proxy = data || null;
            return self.proxy;
        }).catch(function (err) {
            self.proxy = null;
            if (self.onProxyError) { self.onProxyError(err); }
            return null;
        });
    };

    Renderer.prototype.hasProxy = function () {
        return this.proxy !== null;
    };

    Renderer.prototype.setRenderingRule = function (name, enabled) {
        if (this.renderingRules[name] === undefined) { return false; }
        this.renderingRules[name] = !!enabled;
        return true;
    };

    Renderer.prototype.getRenderingRule = function (name) {
        return !!this.renderingRules[name];
    };

    Renderer.prototype.renderingRuleNames = function () {
        return RENDERING_RULES.slice();
    };

    /**
     * name is 'image', 'link' (markdown-it's own rules) or 'misp' (the element
     * syntax above). Returns the new state.
     */
    Renderer.prototype.setParsingRule = function (name, enabled) {
        enabled = !!enabled;
        if (this.parsingRules[name] === undefined) { return false; }
        this.parsingRules[name] = enabled;
        if (name === 'misp') {
            if (enabled) {
                this.md.inline.ruler.enable(['misp_element'], true);
            } else {
                this.md.inline.ruler.disable(['misp_element'], true);
            }
        } else if (enabled) {
            this.md.enable([name], true);
        } else {
            this.md.disable([name], true);
        }
        return true;
    };

    Renderer.prototype.getParsingRule = function (name) {
        return !!this.parsingRules[name];
    };

    Renderer.prototype.toggleParsingRule = function (name) {
        this.setParsingRule(name, !this.parsingRules[name]);
        return this.parsingRules[name];
    };

    Renderer.prototype.injectTemplateVariables = function (raw) {
        var out = raw;
        Object.keys(this.templateVariables).forEach(function (name) {
            var re = new RegExp('{{\\s*' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*}}', 'g');
            out = out.replace(re, this.templateVariables[name]);
        }, this);
        return out;
    };

    Renderer.prototype.toHtml = function (raw) {
        return this.md.render(this.injectTemplateVariables(raw || ''));
    };

    /**
     * Renders into a container and wires what needs the DOM: the tags that
     * still have to be looked up, and the detail popovers.
     */
    Renderer.prototype.render = function (raw, container) {
        var html = this.toHtml(raw);
        if (container) {
            this._disposePopovers();
            container.innerHTML = html;
            this._resolveTags(container);
            this._bindPopovers(container);
        }
        return html;
    };

    /* ── element markup ───────────────────────────────────────────────── */

    Renderer.prototype._pill = function (parts) {
        return '<span class="ov-md-el ' + parts.cls + '"'
            + ' data-scope="' + esc(parts.scope) + '"'
            + ' data-elementid="' + esc(parts.elementId) + '"'
            + (parts.popover ? ' data-md-pop="1" tabindex="0"' : '')
            + '><span class="ov-md-el-k">' + parts.key + '</span>'
            + '<span class="ov-md-el-v">' + esc(parts.value) + '</span></span>';
    };

    /* A rule switched off: the element is still recognised, but only its value
       is printed — no pill, no popover. */
    Renderer.prototype._plain = function (scope, elementId, value) {
        return '<span class="ov-md-el ov-md-plain" data-scope="' + esc(scope)
            + '" data-elementid="' + esc(elementId) + '">' + esc(value) + '</span>';
    };

    Renderer.prototype._invalid = function (scope, elementId) {
        return '<span class="ov-md-el ov-md-invalid" title="' + esc(this.invalidMessage) + '">'
            + esc(scope) + '<span class="ov-md-el-id"> (' + esc(elementId) + ')</span></span>';
    };

    Renderer.prototype._objectOf = function (attribute) {
        if (!this.proxy || !attribute || !attribute.object_uuid) { return undefined; }
        return this.proxy.object ? this.proxy.object[attribute.object_uuid] : undefined;
    };

    Renderer.prototype._renderElement = function (meta) {
        var scope = meta.scope;
        var elementId = meta.elementId;

        if (SCOPES.indexOf(scope) === -1) {
            return this._invalid(scope, elementId);
        }
        if (scope === 'tag') {
            return this._renderTag(elementId);
        }
        if (!this.proxy) {
            return this._invalid(scope, elementId);
        }
        if (scope === 'attribute') {
            var attribute = this.proxy.attribute ? this.proxy.attribute[elementId] : undefined;
            if (!attribute) { return this._invalid(scope, elementId); }
            var mispObject = attribute.object_relation ? this._objectOf(attribute) : undefined;
            if (mispObject) {
                if (!this.renderingRules['object-attribute']) {
                    return this._plain(scope, elementId, attribute.value);
                }
                return this._pill({
                    cls: 'ov-md-objattr',
                    scope: scope,
                    elementId: elementId,
                    popover: true,
                    key: esc(mispObject.name) + '<i class="ov-md-el-arrow">↦</i>'
                        + '<span class="ov-md-el-rel">' + esc(attribute.object_relation) + '</span>',
                    value: attribute.value
                });
            }
            if (!this.renderingRules.attribute) {
                return this._plain(scope, elementId, attribute.value);
            }
            return this._pill({
                cls: 'ov-md-attr',
                scope: scope,
                elementId: elementId,
                popover: true,
                key: esc(attribute.type),
                value: attribute.value
            });
        }
        if (scope === 'object') {
            var object = this.proxy.object ? this.proxy.object[elementId] : undefined;
            if (!object) { return this._invalid(scope, elementId); }
            var value = this._objectTopValue(object);
            if (!this.renderingRules.object) {
                return this._plain(scope, elementId, value);
            }
            return this._pill({
                cls: 'ov-md-obj',
                scope: scope,
                elementId: elementId,
                popover: true,
                key: esc(object.name),
                value: value
            });
        }
        /* galaxymatrix */
        var galaxy = this.proxy.galaxymatrix ? this.proxy.galaxymatrix[elementId] : undefined;
        if (!galaxy) { return this._invalid(scope, elementId); }
        if (!this.renderingRules.galaxymatrix) {
            return this._plain(scope, elementId, galaxy.name);
        }
        return '<span class="ov-md-matrix">'
            + '<i class="' + esc(faClass(galaxy.icon)) + '"></i>'
            + '<span class="ov-md-matrix-name">' + esc(galaxy.name) + '</span>'
            + '<a class="ov-md-matrix-link" href="' + esc(base() + '/galaxies/view/' + galaxy.id) + '">'
            + 'galaxy</a></span>';
    };

    /**
     * The value a report shows for an object: the attribute its template ranks
     * highest, falling back to the first one.
     */
    Renderer.prototype._objectTopValue = function (object) {
        var attributes = object.Attribute || [];
        if (!attributes.length) { return '- no attributes -'; }
        var templates = this.proxy.objectTemplates || {};
        var template = templates[object.template_uuid + '.' + object.template_version];
        if (template && template.ObjectTemplateElement) {
            var elements = template.ObjectTemplateElement;
            for (var i = 0; i < elements.length; i++) {
                for (var j = 0; j < attributes.length; j++) {
                    if (attributes[j].object_relation === elements[i].object_relation) {
                        return attributes[j].value;
                    }
                }
            }
        }
        return attributes[0].value;
    };

    Renderer.prototype._renderPicture = function (meta) {
        if (meta.scope !== 'attribute' || !this.proxy) {
            return this._invalid(meta.scope, meta.elementId);
        }
        var attribute = this.proxy.attribute ? this.proxy.attribute[meta.elementId] : undefined;
        if (!attribute) { return this._invalid(meta.scope, meta.elementId); }
        if (!this.renderingRules['attribute-picture']) {
            return this._plain(meta.scope, meta.elementId, attribute.value);
        }
        return '<span class="ov-md-picture">'
            + '<img src="' + esc(base() + '/attributes/viewPicture/' + attribute.id) + '"'
            + ' alt="' + esc(attribute.type + ' ' + attribute.value) + '"'
            + ' title="' + esc(attribute.type + ' ' + attribute.value) + '"></span>';
    };

    /* ── tags ─────────────────────────────────────────────────────────── */

    /**
     * A tag is rendered from whatever is known at parse time — the event's own
     * tags come with the proxy — and upgraded in place by _resolveTags() for
     * the ones that need a lookup (a galaxy cluster tag, or a tag that is not
     * on the event at all).
     */
    Renderer.prototype._renderTag = function (name) {
        if (!this.renderingRules.tag) {
            return this._plain('tag', name, name);
        }
        var known = this.tagData[name]
            || (this.proxy && this.proxy.tagname ? {Tag: this.proxy.tagname[name]} : null);
        var body = this._tagBody(name, known && known.Tag ? known : null);
        return '<span class="ov-md-tag" data-scope="tag" data-md-pop="1" tabindex="0"'
            + ' data-tagname="' + esc(name) + '"'
            + (body.resolved ? '' : ' data-md-tag-pending="1"')
            + ' style="' + body.style + '">' + body.html + '</span>';
    };

    /**
     * The inside of a tag pill. A galaxy cluster tag reads `type ↦ value`
     * behind its galaxy's glyph, like every other cluster tag in MISP; any
     * other tag is its own name.
     */
    Renderer.prototype._tagBody = function (name, data) {
        var colour = GREY;
        var resolved = false;
        var html = esc(name);

        if (data) {
            if (data.Tag && data.Tag.colour) { colour = data.Tag.colour; }
            else if (data.TaxonomyPredicate && data.TaxonomyPredicate.colour) {
                colour = data.TaxonomyPredicate.colour;
            }
            if (data.GalaxyCluster) {
                var cluster = data.GalaxyCluster;
                var icon = cluster.Galaxy ? cluster.Galaxy.icon : null;
                html = '<i class="' + esc(faClass(icon)) + '"></i>'
                    + esc(cluster.type + ' ↦ ' + cluster.value);
                resolved = true;
            } else if (data.resolved) {
                resolved = true;
            }
        }
        return {
            html: html,
            style: 'background-color:' + esc(colour) + ';color:' + textColour(colour) + ';',
            resolved: resolved
        };
    };

    /* One batched /tags/search per render for everything still unresolved. */
    Renderer.prototype._resolveTags = function (container) {
        var self = this;
        var pending = container.querySelectorAll('.ov-md-tag[data-md-tag-pending]');
        if (!pending.length) { return; }

        var names = [];
        var nodes = [];
        for (var i = 0; i < pending.length; i++) {
            var name = pending[i].getAttribute('data-tagname');
            nodes.push(pending[i]);
            if (this.tagData[name] || this.tagsMissing[name]) {
                this._paintTag(pending[i], name);
            } else if (names.indexOf(name) === -1) {
                names.push(name);
            }
        }
        if (!names.length) { return; }

        var body = new URLSearchParams();
        names.forEach(function (name) { body.append('tag[]', name); });

        fetch(base() + '/tags/search/0/1/0', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            },
            body: body.toString()
        }).then(function (response) {
            if (!response.ok) { throw new Error('HTTP ' + response.status); }
            return response.json();
        }).then(function (tags) {
            (tags || []).forEach(function (tag) {
                if (tag && tag.Tag && tag.Tag.name) {
                    tag.resolved = true;
                    self.tagData[tag.Tag.name] = tag;
                }
            });
        }).catch(function () {
            /* Leave the name showing: a tag that cannot be looked up is still
               readable, and the colour stays neutral. */
        }).then(function () {
            names.forEach(function (name) {
                if (!self.tagData[name]) { self.tagsMissing[name] = true; }
            });
            nodes.forEach(function (node) {
                self._paintTag(node, node.getAttribute('data-tagname'));
            });
        });
    };

    Renderer.prototype._paintTag = function (node, name) {
        var data = this.tagData[name]
            || (this.proxy && this.proxy.tagname ? {Tag: this.proxy.tagname[name]} : null);
        var body = this._tagBody(name, data && data.Tag ? data : null);
        node.innerHTML = body.html;
        node.setAttribute('style', body.style);
        node.removeAttribute('data-md-tag-pending');
    };

    /* ── popovers ─────────────────────────────────────────────────────── */

    Renderer.prototype._disposePopovers = function () {
        this.popovers.forEach(function (instance) {
            try { instance.dispose(); } catch (e) { /* already gone */ }
        });
        this.popovers = [];
        this.openPopover = null;
    };

    /**
     * One delegated listener per container rather than a Popover per pill: the
     * editor re-renders on every keystroke, and a long report holds hundreds
     * of them. A popover is built the first time its pill is clicked.
     */
    Renderer.prototype._bindPopovers = function (container) {
        if (!window.bootstrap || !window.bootstrap.Popover) { return; }
        if (container.dataset.mdPopBound === '1') { return; }
        container.dataset.mdPopBound = '1';

        var self = this;
        container.addEventListener('click', function (event) {
            var node = event.target.closest('[data-md-pop]');
            if (!node || !container.contains(node)) { return; }
            var instance = window.bootstrap.Popover.getInstance(node);
            if (!instance) {
                var content = self._popoverContent(node);
                if (!content) { return; }
                instance = new window.bootstrap.Popover(node, {
                    html: true,
                    trigger: 'manual',
                    placement: 'top',
                    container: 'body',
                    customClass: 'ov-md-popover',
                    title: content.title,
                    content: content.body
                });
                self.popovers.push(instance);
            }
            if (self.openPopover === instance) {
                self._hidePopover();
                return;
            }
            self._hidePopover();
            instance.show();
            self.openPopover = instance;
        });

        /* Manual trigger, so dismissing is ours to do: anywhere outside a pill,
           and Escape. */
        if (!this.dismissBound) {
            this.dismissBound = true;
            document.addEventListener('click', function (event) {
                if (event.target.closest('[data-md-pop], .ov-md-popover')) { return; }
                self._hidePopover();
            });
            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape') { self._hidePopover(); }
            });
        }
    };

    Renderer.prototype._hidePopover = function () {
        if (!this.openPopover) { return; }
        try { this.openPopover.hide(); } catch (e) { /* already gone */ }
        this.openPopover = null;
    };

    Renderer.prototype._popoverContent = function (node) {
        var scope = node.getAttribute('data-scope');
        if (scope === 'tag') {
            var name = node.getAttribute('data-tagname');
            var tag = this.tagData[name];
            var rows = [['Tag', name]];
            if (tag && tag.GalaxyCluster) {
                rows.push(['Galaxy', tag.GalaxyCluster.type]);
                rows.push(['Cluster', tag.GalaxyCluster.value]);
                if (tag.GalaxyCluster.description) {
                    rows.push(['Description', tag.GalaxyCluster.description]);
                }
            } else if (tag && tag.TaxonomyPredicate) {
                if (tag.TaxonomyPredicate.expanded) {
                    rows.push(['Expanded', tag.TaxonomyPredicate.expanded]);
                }
                if (tag.TaxonomyPredicate.description) {
                    rows.push(['Description', tag.TaxonomyPredicate.description]);
                }
            }
            return {title: 'Tag', body: this._popoverRows(rows)};
        }

        var elementId = node.getAttribute('data-elementid');
        if (!this.proxy) { return null; }
        if (scope === 'attribute') {
            var attribute = this.proxy.attribute ? this.proxy.attribute[elementId] : null;
            if (!attribute) { return null; }
            var attrRows = [
                ['ID', attribute.id],
                ['Category', attribute.category],
                ['Type', attribute.type],
                ['Value', attribute.value]
            ];
            if (attribute.object_relation) {
                var owner = this._objectOf(attribute);
                attrRows.splice(1, 0, ['Object', (owner ? owner.name + ' ↦ ' : '') + attribute.object_relation]);
            }
            if (attribute.comment) { attrRows.push(['Comment', attribute.comment]); }
            return {title: 'Attribute', body: this._popoverRows(attrRows)};
        }
        if (scope === 'object') {
            var object = this.proxy.object ? this.proxy.object[elementId] : null;
            if (!object) { return null; }
            var objectRows = [
                ['ID', object.id],
                ['Name', object.name],
                ['Attributes', (object.Attribute || []).length]
            ];
            if (object.comment) { objectRows.push(['Comment', object.comment]); }
            (object.Attribute || []).slice(0, 8).forEach(function (attribute) {
                objectRows.push([attribute.object_relation, attribute.value]);
            });
            return {title: 'Object', body: this._popoverRows(objectRows)};
        }
        return null;
    };

    /* Bootstrap sanitises popover HTML against an allow list that has no table
       elements in it, so the detail rows are divs. */
    Renderer.prototype._popoverRows = function (rows) {
        return rows.filter(function (row) {
            return row[1] !== undefined && row[1] !== null && row[1] !== '';
        }).map(function (row) {
            return '<div class="ov-md-pop-row">'
                + '<span class="ov-md-pop-k">' + esc(row[0]) + '</span>'
                + '<span class="ov-md-pop-v">' + esc(row[1]) + '</span></div>';
        }).join('');
    };

    /* ── what the editor can offer ────────────────────────────────────── */

    /**
     * The event's elements, flattened into what a completion list needs: one
     * entry per element, with everything worth matching on folded into a single
     * haystack. A report references an attribute by UUID, and nobody types a
     * UUID from memory — this is what lets the writer find it by its value, its
     * type or its id instead.
     */
    Renderer.prototype.hints = function (scope) {
        if (!this.proxy) { return []; }
        if (!this.hintCache) { this.hintCache = {}; }
        if (this.hintCache[scope]) { return this.hintCache[scope]; }

        var list = [];
        var push = function (label, detail, value, terms) {
            list.push({
                label: String(label === undefined || label === null ? '' : label),
                detail: String(detail === undefined || detail === null ? '' : detail),
                value: value,
                search: terms.filter(Boolean).join(' ').toLowerCase()
            });
        };

        if (scope === 'attribute') {
            var attributes = this.proxy.attribute || {};
            Object.keys(attributes).forEach(function (uuid) {
                var attribute = attributes[uuid];
                var label = attribute.object_relation || attribute.type;
                push(label, attribute.value, uuid,
                    [attribute.type, attribute.object_relation, attribute.value, attribute.id, uuid]);
            });
        } else if (scope === 'object') {
            var objects = this.proxy.object || {};
            Object.keys(objects).forEach(function (uuid) {
                var object = objects[uuid];
                push(object.name, this._objectTopValue(object), uuid,
                    [object.name, object.id, uuid]);
            }, this);
        } else if (scope === 'galaxymatrix') {
            var galaxies = this.proxy.galaxymatrix || {};
            Object.keys(galaxies).forEach(function (uuid) {
                var galaxy = galaxies[uuid];
                push(galaxy.name, galaxy.namespace, uuid,
                    [galaxy.name, galaxy.namespace, galaxy.type, galaxy.id, uuid]);
            });
        } else if (scope === 'tag') {
            var tags = this.proxy.tagname || {};
            Object.keys(tags).forEach(function (name) {
                push(name, '', name, [name]);
            });
        }

        list.sort(function (a, b) { return a.label.localeCompare(b.label); });
        this.hintCache[scope] = list;
        return list;
    };

    /* ── GFM substitution ─────────────────────────────────────────────── */

    /**
     * The "Download GFM simplified format" of the stock theme: every MISP
     * element becomes plain text, so the document parses anywhere.
     */
    Renderer.prototype.toGfm = function (raw) {
        var self = this;
        var re = /@!?\[(attribute|object|tag)\]\(([^)]+)\)/g;
        return this.injectTemplateVariables(raw || '').replace(re, function (match, scope, elementId) {
            var element = null;
            if (self.proxy) {
                if (scope === 'tag') {
                    element = self.proxy.tagname ? self.proxy.tagname[elementId] : null;
                    if (element) { return 'tag[' + element.name + ']'; }
                } else {
                    element = self.proxy[scope] ? self.proxy[scope][elementId] : null;
                }
            }
            if (!element) { return scope + '-' + elementId; }
            if (scope === 'attribute') {
                var type = element.object_relation || element.type;
                return 'attribute[type:' + type + '][value:' + element.value + ']';
            }
            return 'object[name:' + element.name + '][value:' + self._objectTopValue(element) + ']';
        });
    };

    /* ─────────────────────── the raw markdown pane ─────────────────────── */

    /**
     * Colours the source a report is written in. A `<textarea>` cannot hold
     * markup, so the editor lays a `<pre>` under a transparent one and this is
     * what fills it: the same text, escaped, with the parts worth telling
     * apart wrapped in a span. Nothing here has to agree with anything else —
     * both layers share one box and one set of metrics, so they line up by
     * construction.
     *
     * The MISP elements are keyed by scope, so an @[attribute] and an @[object]
     * read as differently in the source as their pills do in the preview.
     */
    var RAW_RE = new RegExp([
        '(?<fence>^```[^\\n]*\\n[\\s\\S]*?^```)',
        '(?<heading>^ {0,3}#{1,6}[^\\n]*)',
        '(?<quote>^ {0,3}&gt;[^\\n]*)',
        '(?<rule>^ {0,3}(?:-{3,}|\\*{3,}|_{3,})[ \\t]*$)',
        '(?<table>^ {0,3}\\|[^\\n]*)',
        '(?<misp>@!?\\[(?<scope>' + SCOPES.join('|') + ')\\]\\([^)\\n]*\\))',
        '(?<tvar>\\{\\{[^}\\n]*\\}\\})',
        '(?<code>`[^`\\n]+`)',
        '(?<link>!?\\[[^\\]\\n]*\\]\\([^)\\n]*\\))',
        '(?<bold>\\*\\*[^*\\n]+\\*\\*)',
        '(?<italic>\\*[^*\\n]+\\*)',
        '(?<bullet>^ {0,6}(?:[-*+]|\\d+[.)]) )'
    ].join('|'), 'gm');

    function highlightSource(raw) {
        var text = esc(raw === undefined || raw === null ? '' : String(raw));
        var out = '';
        var last = 0;
        var match;

        RAW_RE.lastIndex = 0;
        while ((match = RAW_RE.exec(text)) !== null) {
            if (match[0].length === 0) { RAW_RE.lastIndex++; continue; }
            var groups = match.groups;
            var kind = null;
            Object.keys(groups).forEach(function (name) {
                if (name !== 'scope' && kind === null && groups[name] !== undefined) {
                    kind = name;
                }
            });
            if (kind === null) { continue; }

            var cls = 'ov-raw-' + kind;
            if (kind === 'misp') { cls += ' ov-raw-misp-' + groups.scope; }
            out += text.slice(last, match.index)
                + '<span class="' + cls + '">' + match[0] + '</span>';
            last = match.index + match[0].length;
        }
        /* The trailing newline a <pre> would swallow, kept so the layer is
           exactly as tall as the textarea over it. */
        return out + text.slice(last) + '\n';
    }

    /**
     * Binds the pair: repaint on input, and keep the textarea exactly as tall
     * as its content so the pane around them is the only thing that scrolls —
     * one scrollbar, nothing to synchronise.
     */
    function bindSourceHighlight(textarea, layer) {
        var pane = textarea.parentElement;
        var paneHeight = -1;

        /**
         * The textarea's box has to be exactly as tall as its text, since that
         * is what makes the layer under it the same height and the pane scroll
         * at the right moment. Measuring that means taking the flex grow out
         * of the way first — a textarea stretched to fill its pane reports the
         * pane's height as its scrollHeight, not the text's — and putting it
         * back afterwards, so a short document still fills the half.
         */
        function grow() {
            textarea.style.flexGrow = '0';
            textarea.style.height = '0px';
            var content = textarea.scrollHeight;
            textarea.style.height = content + 'px';
            textarea.style.flexGrow = '';
        }
        function paint() {
            layer.innerHTML = highlightSource(textarea.value);
            grow();
        }

        textarea.addEventListener('input', paint);
        window.addEventListener('resize', grow);

        /* The pane is as tall as the preview beside it, so it changes height
           whenever the preview re-renders — and the textarea has to be
           re-measured against it. */
        var observer = null;
        if (pane && window.ResizeObserver) {
            observer = new ResizeObserver(function () {
                if (pane.clientHeight !== paneHeight) {
                    paneHeight = pane.clientHeight;
                    grow();
                }
            });
            observer.observe(pane);
        }

        paint();
        /* Only now does the textarea's own text go transparent: until the
           layer under it holds something, hiding it would just blank the
           editor. */
        if (pane) { pane.setAttribute('data-raw-highlight', '1'); }

        return {
            refresh: paint,
            destroy: function () {
                textarea.removeEventListener('input', paint);
                window.removeEventListener('resize', grow);
                if (observer) { observer.disconnect(); }
                if (pane) { pane.removeAttribute('data-raw-highlight'); }
                textarea.style.height = '';
                textarea.style.flexGrow = '';
            }
        };
    }

    /* ───────────────────── writing in the raw pane ─────────────────────── */

    /* What `@[` can be followed by, and what Ctrl+M offers first. */
    var ELEMENT_SCOPES = SCOPES.slice();

    var RE_SCOPE = /@(!?)\[([A-Za-z]*)$/;
    var RE_ELEMENT = new RegExp('@(!?)\\[(' + ELEMENT_SCOPES.join('|') + ')\\]\\(([^)\\n]*)$');

    /**
     * Writes into a textarea the way the browser would, so the native undo
     * stack survives — a markdown editor whose Ctrl+Z does nothing is worse
     * than one with no shortcuts at all. execCommand is the only API that
     * does that; the fallback is there for the day it finally goes.
     */
    function writeInto(textarea, start, end, text, selectFrom, selectTo) {
        textarea.focus();
        textarea.setSelectionRange(start, end);
        var written = false;
        try {
            written = document.execCommand('insertText', false, text);
        } catch (e) {
            written = false;
        }
        if (!written) {
            var value = textarea.value;
            textarea.value = value.slice(0, start) + text + value.slice(end);
            textarea.dispatchEvent(new Event('input', {bubbles: true}));
        }
        var caret = start + text.length;
        textarea.setSelectionRange(
            selectFrom === undefined ? caret : selectFrom,
            selectTo === undefined ? (selectFrom === undefined ? caret : selectFrom) : selectTo
        );
    }

    /**
     * Where the caret is on screen. Measured on a throwaway copy of the
     * textarea rather than kept in step with one: it only has to be right at
     * the moment the completion opens.
     */
    function caretPosition(textarea) {
        var style = window.getComputedStyle(textarea);
        var rect = textarea.getBoundingClientRect();
        var mirror = document.createElement('div');
        var marker = document.createElement('span');

        mirror.setAttribute('style', [
            'position:absolute', 'visibility:hidden', 'pointer-events:none',
            'left:' + (rect.left + window.pageXOffset) + 'px',
            'top:' + (rect.top + window.pageYOffset) + 'px',
            'width:' + rect.width + 'px',
            'box-sizing:' + style.boxSizing,
            'padding:' + style.padding,
            'border-width:' + style.borderWidth,
            'font-family:' + style.fontFamily,
            'font-size:' + style.fontSize,
            'line-height:' + style.lineHeight,
            'letter-spacing:' + style.letterSpacing,
            'tab-size:' + (style.tabSize || '8'),
            'white-space:pre-wrap', 'overflow-wrap:break-word', 'word-break:break-word'
        ].join(';'));
        mirror.textContent = textarea.value.slice(0, textarea.selectionStart);
        marker.textContent = '​';
        mirror.appendChild(marker);
        document.body.appendChild(mirror);

        var markerRect = marker.getBoundingClientRect();
        var mirrorRect = mirror.getBoundingClientRect();
        mirror.remove();

        /* The mirror sits where the textarea sits, so the marker's offset
           inside it is the caret's offset inside the textarea. */
        return {
            left: rect.left + (markerRect.left - mirrorRect.left),
            top: rect.top + (markerRect.top - mirrorRect.top),
            bottom: rect.top + (markerRect.bottom - mirrorRect.top)
        };
    }

    /**
     * The shortcuts the help modal lists, and the completion behind Ctrl+Space:
     * a report points at an attribute by UUID, so being able to find one by its
     * value or its type is what makes the syntax usable by hand at all.
     *
     * `renderer` is what holds the event's elements (see Renderer.hints).
     */
    var TABLE_TEMPLATE = '| Column 1 | Column 2 | Column 3 |\n'
        + '| -------- | -------- | -------- |\n'
        + '| Text     | Text     | Text     |\n';

    function bindSourceEditing(textarea, renderer, toolbar) {
        var popup = null;
        var items = [];
        var active = 0;
        var context = null;
        var closeTimer = null;

        /* ── the text transforms ──────────────────────────────────────── */

        function wrap(marker) {
            var start = textarea.selectionStart;
            var end = textarea.selectionEnd;
            var selected = textarea.value.slice(start, end);
            writeInto(textarea, start, end, marker + selected + marker,
                start + marker.length, start + marker.length + selected.length);
        }

        function heading() {
            var start = textarea.selectionStart;
            var lineStart = textarea.value.lastIndexOf('\n', start - 1) + 1;
            /* Each press adds a level, the way the stock editor's Ctrl+H does. */
            var already = textarea.value.charAt(lineStart) === '#';
            writeInto(textarea, lineStart, lineStart, already ? '#' : '# ');
        }

        /** The block of whole lines the selection touches. */
        function selectedBlock() {
            var value = textarea.value;
            var from = value.lastIndexOf('\n', textarea.selectionStart - 1) + 1;
            var end = value.indexOf('\n', textarea.selectionEnd);
            var to = end === -1 ? value.length : end;
            return {from: from, to: to, lines: value.slice(from, to).split('\n')};
        }

        /**
         * A line prefix over every line the selection touches: it goes on
         * unless all of them already carry it, in which case the click is
         * read as "take it off".
         */
        function linePrefix(prefix, pattern) {
            var block = selectedBlock();
            var on = block.lines.every(function (line) { return pattern.test(line); });
            var lines = block.lines.map(function (line) {
                return on ? line.replace(pattern, '') : prefix + line;
            });
            var text = lines.join('\n');
            writeInto(textarea, block.from, block.to, text,
                block.from, block.from + text.length);
        }

        /**
         * Inline backticks for a piece of one line, a fenced block for a
         * selection that spans several — the distinction every markdown
         * editor makes, and the one the writer means.
         */
        function code() {
            var value = textarea.value;
            var start = textarea.selectionStart;
            var end = textarea.selectionEnd;
            if (value.slice(start, end).indexOf('\n') === -1) {
                wrap('`');
                return;
            }
            var block = selectedBlock();
            var text = '```\n' + value.slice(block.from, block.to) + '\n```';
            writeInto(textarea, block.from, block.to, text,
                block.from + 4, block.from + text.length - 4);
        }

        function table() {
            var value = textarea.value;
            var start = textarea.selectionStart;
            var lineStart = value.lastIndexOf('\n', start - 1) + 1;
            var lineEnd = value.indexOf('\n', start);
            var at = lineEnd === -1 ? value.length : lineEnd;
            var onEmptyLine = value.slice(lineStart, at).trim() === '';
            var text = (onEmptyLine ? '' : '\n') + TABLE_TEMPLATE;
            /* The first header cell, so the writer types over it straight away. */
            var caret = at + text.indexOf('Column 1');
            writeInto(textarea, at, at, text, caret, caret + 'Column 1'.length);
        }

        /**
         * `@[scope]()` with the caret between the parentheses, then the
         * suggestion list for that scope — the point of the button is to spare
         * the writer the UUID, not just the brackets.
         */
        function element(scope, picture) {
            var start = textarea.selectionStart;
            var text = '@' + (picture ? '!' : '') + '[' + (scope || '') + ']()';
            var caret = start + text.length - (scope ? 1 : 3);
            writeInto(textarea, start, textarea.selectionEnd, text, caret, caret);
            open();
        }

        var ACTIONS = {
            'bold': function () { wrap('**'); },
            'italic': function () { wrap('*'); },
            'heading': heading,
            'strikethrough': function () { wrap('~~'); },
            'list-ul': function () { linePrefix('* ', /^\s*[-*+] /); },
            'list-ol': function () { linePrefix('1. ', /^\s*\d+[.)] /); },
            'quote': function () { linePrefix('> ', /^\s*> ?/); },
            'code': code,
            'table': table,
            'element': function () { element('', false); },
            'attribute': function () { element('attribute', false); },
            'attribute-picture': function () { element('attribute', true); },
            'object': function () { element('object', false); },
            'tag': function () { element('tag', false); },
            'galaxymatrix': function () { element('galaxymatrix', false); }
        };

        function apply(action) {
            if (!ACTIONS[action]) { return false; }
            ACTIONS[action]();
            return true;
        }

        /* ── the completion ───────────────────────────────────────────── */

        /** What the caret is sitting in, or null. */
        function readContext() {
            var caret = textarea.selectionStart;
            if (caret !== textarea.selectionEnd) { return null; }
            var lineStart = textarea.value.lastIndexOf('\n', caret - 1) + 1;
            var before = textarea.value.slice(lineStart, caret);

            var element = RE_ELEMENT.exec(before);
            if (element) {
                return {
                    kind: 'element',
                    scope: element[2],
                    picture: element[1] === '!',
                    term: element[3],
                    from: caret - element[0].length,
                    to: caret
                };
            }
            var scope = RE_SCOPE.exec(before);
            if (scope) {
                return {
                    kind: 'scope',
                    picture: scope[1] === '!',
                    term: scope[2],
                    from: caret - scope[0].length,
                    to: caret
                };
            }
            return null;
        }

        function candidates(ctx) {
            var term = (ctx.term || '').toLowerCase();
            if (ctx.kind === 'scope') {
                return ELEMENT_SCOPES.filter(function (scope) {
                    return scope.indexOf(term) === 0;
                }).map(function (scope) {
                    return {label: scope, detail: '', value: scope, kind: 'scope'};
                });
            }
            var list = renderer ? renderer.hints(ctx.scope) : [];
            if (term === '') { return list.slice(0, 50); }
            return list.filter(function (hint) {
                return hint.search.indexOf(term) !== -1;
            }).slice(0, 50);
        }

        function accept(index) {
            if (!context || !items[index]) { return; }
            var hint = items[index];
            var ctx = context;
            close();

            if (ctx.kind === 'scope') {
                /* Ctrl+M leaves `@[]()` around the caret, and a writer who
                   typed the brackets themselves has the same tail — the pick
                   replaces it rather than landing in front of it. */
                var tail = /^\](?:\([^)\n]*\))?/.exec(textarea.value.slice(ctx.to));
                var scopeTo = ctx.to + (tail ? tail[0].length : 0);
                var text = '@' + (ctx.picture ? '!' : '') + '[' + hint.value + ']()';
                var inside = ctx.from + text.length - 1;
                writeInto(textarea, ctx.from, scopeTo, text, inside, inside);
                open();
                return;
            }

            /* The closing paren the writer already has is theirs to keep. */
            var to = ctx.to;
            if (textarea.value.charAt(to) === ')') { to += 1; }
            var replacement = '@' + (ctx.picture ? '!' : '') + '[' + ctx.scope + '](' + hint.value + ')';
            writeInto(textarea, ctx.from, to, replacement);
        }

        function render() {
            if (!popup) { return; }
            popup.innerHTML = items.map(function (hint, index) {
                return '<div class="ov-raw-hint' + (index === active ? ' is-active' : '') + '"'
                    + ' role="option" data-index="' + index + '">'
                    + '<span class="ov-raw-hint-label">' + esc(hint.label) + '</span>'
                    + (hint.detail ? '<span class="ov-raw-hint-detail">' + esc(hint.detail) + '</span>' : '')
                    + '</div>';
            }).join('');
            var current = popup.querySelector('.is-active');
            if (current) { current.scrollIntoView({block: 'nearest'}); }
        }

        function place() {
            var caret = caretPosition(textarea);
            var width = popup.offsetWidth;
            var height = popup.offsetHeight;
            var left = Math.min(caret.left, window.innerWidth - width - 8);
            var top = caret.bottom + 4;
            /* Above the line when there is no room under it. */
            if (top + height > window.innerHeight - 8) {
                top = Math.max(8, caret.top - height - 4);
            }
            popup.style.left = Math.max(8, left) + window.pageXOffset + 'px';
            popup.style.top = top + window.pageYOffset + 'px';
        }

        function open() {
            context = readContext();
            if (!context) { close(); return; }
            items = candidates(context);
            if (!items.length) { close(); return; }
            active = 0;
            if (!popup) {
                popup = document.createElement('div');
                popup.className = 'ov-raw-hints';
                popup.setAttribute('role', 'listbox');
                popup.addEventListener('mousedown', function (event) {
                    /* mousedown, not click: the textarea must not lose focus
                       before the pick is applied. */
                    var node = event.target.closest('.ov-raw-hint');
                    if (!node) { return; }
                    event.preventDefault();
                    accept(parseInt(node.getAttribute('data-index'), 10));
                });
                document.body.appendChild(popup);
            }
            render();
            place();
        }

        function close() {
            context = null;
            items = [];
            if (popup) { popup.remove(); popup = null; }
        }

        function isOpen() { return popup !== null; }

        function move(delta) {
            active = (active + delta + items.length) % items.length;
            render();
        }

        /* ── wiring ───────────────────────────────────────────────────── */

        function onKeydown(event) {
            if (isOpen()) {
                if (event.key === 'ArrowDown') { event.preventDefault(); move(1); return; }
                if (event.key === 'ArrowUp') { event.preventDefault(); move(-1); return; }
                if (event.key === 'Enter' || event.key === 'Tab') {
                    event.preventDefault();
                    accept(active);
                    return;
                }
                if (event.key === 'Escape') { event.preventDefault(); close(); return; }
            }

            var mod = event.ctrlKey || event.metaKey;
            if (!mod || event.altKey) { return; }

            if (event.key === ' ' || event.code === 'Space') {
                event.preventDefault();
                open();
                return;
            }
            var shortcut = {b: 'bold', i: 'italic', h: 'heading', m: 'element'};
            var action = shortcut[event.key.toLowerCase()];
            if (action) {
                event.preventDefault();
                apply(action);
            }
        }

        /* Typing re-reads the context, so the list follows what is being
           written and disappears once the caret leaves it. */
        function onInput() {
            if (isOpen()) { open(); }
        }

        function onSelectionChange() {
            if (isOpen() && !readContext()) { close(); }
        }

        function onBlur() {
            closeTimer = window.setTimeout(close, 120);
        }

        /* mousedown rather than click: a button that takes the focus first
           would leave the textarea without the selection to act on. */
        function onToolbar(event) {
            var button = event.target.closest('[data-md-action]');
            if (!button || !toolbar.contains(button)) { return; }
            event.preventDefault();
            apply(button.getAttribute('data-md-action'));
        }

        textarea.addEventListener('keydown', onKeydown);
        textarea.addEventListener('input', onInput);
        textarea.addEventListener('click', onSelectionChange);
        textarea.addEventListener('blur', onBlur);
        var pane = textarea.parentElement;
        if (pane) { pane.addEventListener('scroll', close); }
        if (toolbar) { toolbar.addEventListener('mousedown', onToolbar); }

        return {
            open: open,
            close: close,
            apply: apply,
            destroy: function () {
                window.clearTimeout(closeTimer);
                close();
                textarea.removeEventListener('keydown', onKeydown);
                textarea.removeEventListener('input', onInput);
                textarea.removeEventListener('click', onSelectionChange);
                textarea.removeEventListener('blur', onBlur);
                if (pane) { pane.removeEventListener('scroll', close); }
                if (toolbar) { toolbar.removeEventListener('mousedown', onToolbar); }
            }
        };
    }

    window.MispReportMarkdown = {
        create: function (options) { return new Renderer(options); },
        highlightSource: highlightSource,
        bindSourceHighlight: bindSourceHighlight,
        bindSourceEditing: bindSourceEditing,
        renderingRules: function () { return RENDERING_RULES.slice(); }
    };
})(window, document);
