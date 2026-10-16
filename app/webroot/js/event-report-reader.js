// The Overmind event page's report reader: renders a report (MISP elements,
// template variables, mermaid), draws report openings in the Reports tab's
// cards, and reads any of the event's reports in one modal. A
// [data-report-read="<id>"] element opens it; the one carrying the name and
// sub line the server rendered for that report supplies the header.
(function () {
    'use strict';

    if (window.MispReportReader) return;

    function base() {
        return typeof window.baseurl === 'string' ? window.baseurl : '';
    }

    function modalEl() {
        return document.getElementById('report-reader-modal');
    }

    var reports = {};
    var renderers = {};
    var templateVariables = null;

    function variables() {
        if (templateVariables === null) {
            var modal = modalEl();
            try {
                templateVariables = JSON.parse((modal && modal.getAttribute('data-template-variables')) || '[]');
            } catch (e) {
                templateVariables = [];
            }
        }
        return templateVariables;
    }

    // report: {id, eventId, name, content}
    function seed(report) {
        reports[String(report.id)] = Promise.resolve(report);
    }

    function load(id) {
        id = String(id);
        if (!reports[id]) {
            reports[id] = fetch(base() + '/eventReports/view/' + encodeURIComponent(id) + '.json', {
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' }
            }).then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            }).then(function (data) {
                var report = data.EventReport || {};
                return {
                    id: String(report.id),
                    eventId: String(report.event_id),
                    name: report.name || '',
                    content: report.content || '',
                    org: (data.Event && data.Event.Orgc && data.Event.Orgc.name) || ''
                };
            });
            reports[id].catch(function () { delete reports[id]; });
        }
        return reports[id];
    }

    /* ── mermaid ────────────────────────────────────────────── */
    var mermaidReady = null;

    function loadMermaid() {
        if (window.mermaid) return Promise.resolve(window.mermaid);
        if (mermaidReady) return mermaidReady;
        mermaidReady = new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = base() + '/js/mermaid.js';
            s.onload = function () { window.mermaid ? resolve(window.mermaid) : reject(new Error('mermaid')); };
            s.onerror = reject;
            document.head.appendChild(s);
        });
        return mermaidReady;
    }

    function isMermaid(code) {
        if (code.classList.contains('language-mermaid')) return true;
        var first = (code.textContent || '').trim().split(/\n/)[0].trim();
        return /^(gantt|sequenceDiagram|classDiagram|stateDiagram|erDiagram|journey|pie|mindmap|timeline|flowchart|graph (TB|BT|RL|LR|TD))\b/.test(first);
    }

    var mermaidSeq = 0;
    function drawMermaid(root) {
        var blocks = Array.prototype.filter.call(root.querySelectorAll('pre > code'), isMermaid);
        if (!blocks.length) return Promise.resolve();
        return loadMermaid().then(function (mermaid) {
            var dark = document.documentElement.getAttribute('data-misp-mode') === 'dark';
            mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'neutral' });
            return blocks.reduce(function (chain, code) {
                return chain.then(function () {
                    var id = 'eo-mermaid-' + (++mermaidSeq);
                    return mermaid.mermaidAPI.render(id, code.textContent).then(function (out) {
                        var div = document.createElement('div');
                        div.className = 'mermaid eo-mermaid';
                        div.innerHTML = out.svg;
                        code.parentNode.replaceWith(div);
                    }, function () { /* an unparsable diagram stays as source */ });
                });
            }, Promise.resolve());
        }, function () { /* no mermaid: the source stays readable */ });
    }

    /* ── rendering ──────────────────────────────────────────── */
    // The element lookup behind the pills is per event, so reports of one
    // event share a renderer.
    function rendererFor(report) {
        if (!renderers[report.eventId]) {
            renderers[report.eventId] = window.MispReportMarkdown.create({
                reportId: parseInt(report.id, 10),
                eventId: parseInt(report.eventId, 10),
                templateVariables: variables()
            });
        }
        return renderers[report.eventId];
    }

    function render(report, target) {
        if (!window.MispReportMarkdown) {
            target.textContent = report.content;
            return Promise.resolve();
        }
        var renderer = rendererFor(report);
        return renderer.ready.then(function () {
            renderer.render(report.content, target);
            return drawMermaid(target);
        });
    }

    /* ── the modal ──────────────────────────────────────────── */
    var openToken = 0;

    function trigger(id) {
        return document.querySelector('[data-report-read="' + CSS.escape(String(id)) + '"][data-report-name]');
    }

    function open(id) {
        var modal = modalEl();
        if (!modal || !window.bootstrap) return;
        id = String(id);
        var name = modal.querySelector('[data-reader-name]');
        var sub = modal.querySelector('[data-reader-sub]');
        var page = modal.querySelector('[data-reader-page]');
        var body = modal.querySelector('[data-reader-body]');
        var loader = modal.querySelector('[data-reader-loader]');
        var idChip = modal.querySelector('[data-reader-id]');
        var eventChip = modal.querySelector('[data-reader-event]');
        var from = trigger(id);
        var token = ++openToken;

        name.textContent = from ? from.getAttribute('data-report-name') : '';
        name.title = name.textContent;
        sub.innerHTML = from ? (from.getAttribute('data-report-sub') || '') : '';
        page.href = base() + '/eventReports/view/' + encodeURIComponent(id);
        idChip.textContent = '#' + id;
        eventChip.textContent = '';
        body.textContent = '';
        loader.classList.remove('d-none');
        window.bootstrap.Modal.getOrCreateInstance(modal).show();

        load(id).then(function (report) {
            if (token !== openToken) return null;
            eventChip.textContent = '#' + report.eventId;
            if (!from) {
                name.textContent = report.name;
                name.title = report.name;
                sub.textContent = report.org;
            }
            return render(report, body);
        }).then(function () {
            if (token === openToken) loader.classList.add('d-none');
        }, function () {
            if (token !== openToken) return;
            loader.classList.add('d-none');
            body.innerHTML = '<p class="eo-empty"><i class="fas fa-exclamation-triangle me-1"></i></p>';
            body.firstChild.appendChild(document.createTextNode(modal.getAttribute('data-text-failed') || ''));
        });
    }

    // Fade a clamped preview out; pictures still loading can push it over.
    function fade(holder, clamp) {
        function check() {
            holder.classList.toggle('is-clamped', clamp.scrollHeight > clamp.clientHeight + 4);
        }
        check();
        clamp.querySelectorAll('img').forEach(function (img) {
            if (!img.complete) img.addEventListener('load', check, { once: true });
        });
    }

    /* ── previews ───────────────────────────────────────────── */
    // [data-report-preview] holds the opening of a report; it renders once
    // it is on screen, which also leaves the hidden card view of an index
    // alone until it is switched to.
    var watcher = null;

    function drawPreview(holder) {
        var body = holder.querySelector('[data-report-preview-body]');
        var clamp = holder.querySelector('.eo-report-clamp');
        render({
            id: holder.getAttribute('data-report-preview'),
            eventId: holder.getAttribute('data-report-event'),
            content: holder.getAttribute('data-report-content') || ''
        }, body).then(function () {
            fade(holder, clamp);
        }, function () {
            body.textContent = holder.getAttribute('data-report-content') || '';
        });
    }

    function previews(root) {
        var holders = (root || document).querySelectorAll('[data-report-preview]:not([data-report-watched])');
        if (!holders.length) return;
        if (!watcher) {
            watcher = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (!entry.isIntersecting) return;
                    watcher.unobserve(entry.target);
                    drawPreview(entry.target);
                });
            }, { rootMargin: '200px 0px' });
        }
        holders.forEach(function (holder) {
            holder.setAttribute('data-report-watched', '');
            watcher.observe(holder);
        });
    }

    // A plain click reads in place; a modified or middle click on a link
    // still opens the report page.
    function onClick(e) {
        var el = e.target.closest && e.target.closest('[data-report-read]');
        if (!el || !modalEl()) return;
        if (el.tagName === 'A' && (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0)) return;
        e.preventDefault();
        open(el.getAttribute('data-report-read'));
    }

    document.addEventListener('click', onClick);
    document.addEventListener('misp:container-loaded', function (e) { previews(e.target); });
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { previews(document); });
    } else {
        previews(document);
    }

    window.MispReportReader = {
        seed: seed,
        load: load,
        render: render,
        fade: fade,
        open: open
    };
})();
