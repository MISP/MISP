/*
 * MispQL console: what a grid cell opens in place. Each view is MISP's own
 * (popover.mjs lists them); this module only opens them for the page.
 */

import { objectView, inPlaceViews, membersPageSize } from './popover.mjs';

function toast(text) {
    if (typeof window.showToast === 'function') {
        window.showToast(text, 'danger');
    }
}

function getText(url) {
    return fetch(url, {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html' },
    }).then(function (r) {
        return r.ok && !r.redirected ? r.text() : Promise.reject(new Error('HTTP ' + r.status));
    });
}

// Inserted together with async off, so they run in list order.
function loadScript(src) {
    return new Promise(function (resolve, reject) {
        const script = document.createElement('script');
        script.src = src;
        script.async = false;
        script.onload = function () { resolve(); };
        script.onerror = function () { reject(new Error('Failed to load ' + src)); };
        document.head.appendChild(script);
    });
}

function loadStylesheet(href) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = href;
    document.head.appendChild(link);
}

/**
 * o: {baseurl, client, config: {peeks, valueCard, reportReader: {js, css} | false}}
 * Returns {views, open(link, cell), reset()}: `views` is the grid's `opens`,
 * `open` its onOpen, `reset` forgets what the last result opened.
 */
function createInPlace(o) {
    const config = o.config || {};
    const views = inPlaceViews({
        object: !!window.IntelGraphWorking,
        peeks: !!config.peeks && !!window.bootstrap && !!window.eventIndexCards,
        valueCard: !!config.valueCard && !!window._vpHoverCardBound,
        reportReader: !!config.reportReader && !!document.getElementById('report-reader-modal'),
        baseurl: o.baseurl,
    });
    const objects = new Map();
    const fragments = new Map();
    let reader = null;
    let members = null;

    function caretOf(cell) {
        return cell.querySelector('.cq-open');
    }

    function busy(cell, on) {
        if (on) {
            cell.setAttribute('aria-busy', 'true');
        } else {
            cell.removeAttribute('aria-busy');
        }
    }

    function open(link, cell) {
        if (!link || !cell || !views[link.type]) {
            return;
        }
        const caret = caretOf(cell);
        switch (link.type) {
            case 'Object':
                openObject(link, cell);
                break;
            case 'EventReport':
                openReport(link, cell);
                break;
            case 'Collection':
                openMembers(link, cell);
                break;
            case 'SharingGroup':
                // The badge popover pins on a click on its trigger
                if (caret) {
                    caret.click();
                }
                break;
            default:
                // The event peek and the value card open when their trigger has focus
                if (caret) {
                    caret.focus({ preventScroll: true });
                }
        }
    }

    /* The workspace's object popover, the object read once per result; a second open closes it. */
    function openObject(link, cell) {
        let view = objects.get(link.address);
        if (!view) {
            view = o.client.object(link.address).then(objectView);
            objects.set(link.address, view);
        }
        busy(cell, true);
        view.then(function (v) {
            busy(cell, false);
            if (!v) {
                throw new Error('no object');
            }
            if (document.contains(cell)) {
                window.IntelGraphWorking.openObject(v, cell, null);
            }
        }).catch(function () {
            busy(cell, false);
            objects.delete(link.address);
            toast('The object could not be read: it may be deleted, or not shared with you.');
        });
    }

    /* The event page's report reader, its scripts loaded on the first report opened. */
    function readerReady() {
        if (window.MispReportReader) {
            return Promise.resolve(window.MispReportReader);
        }
        if (!reader) {
            const assets = config.reportReader || {};
            (assets.css || []).forEach(loadStylesheet);
            reader = Promise.all((assets.js || []).map(loadScript)).then(function () {
                if (!window.MispReportReader) {
                    throw new Error('The report reader did not load.');
                }
                return window.MispReportReader;
            });
            reader.catch(function () { reader = null; });
        }
        return reader;
    }

    function openReport(link, cell) {
        busy(cell, true);
        readerReady().then(function (Reader) {
            busy(cell, false);
            const modal = document.getElementById('report-reader-modal');
            modal.addEventListener('hidden.bs.modal', function () {
                if (document.contains(cell)) {
                    cell.focus({ preventScroll: true });
                }
            }, { once: true });
            Reader.open(link.address);
        }, function () {
            busy(cell, false);
            toast('The report reader could not be loaded.');
        });
    }

    /* A collection's members: its page's elements card, read-only, in a popover that never scrolls. */
    function openMembers(link, cell) {
        const caret = caretOf(cell);
        if (!caret) {
            return;
        }
        if (members && members.caret === caret) {
            closeMembers(true);
            return;
        }
        closeMembers(false);
        let html = fragments.get(link.address);
        if (!html) {
            html = getText(views.Collection.url(link));
            fragments.set(link.address, html);
        }
        busy(cell, true);
        html.then(function (text) {
            busy(cell, false);
            if (document.contains(caret)) {
                showMembers(caret, cell, text, membersPageSize(room()), true);
            }
        }).catch(function () {
            busy(cell, false);
            fragments.delete(link.address);
            toast('The collection could not be read: it may be deleted, or not shared with you.');
        });
    }

    function room() {
        return window.innerHeight - 16;
    }

    function showMembers(caret, cell, html, pageSize, refit) {
        const tpl = document.createElement('template');
        tpl.innerHTML = html;
        const card = tpl.content.querySelector('[data-collection-elements]');
        if (!card) {
            throw new Error('not a collection card');
        }
        // The card binds itself from its own script, which innerHTML leaves inert
        const scripts = Array.prototype.filter.call(tpl.content.querySelectorAll('script'), function (s) {
            return !s.type || s.type === 'text/javascript';
        });
        scripts.forEach(function (s) { s.remove(); });
        card.setAttribute('data-page-size', String(pageSize));
        const box = document.createElement('div');
        box.className = 'cq-members';
        box.appendChild(tpl.content);
        const popover = new window.bootstrap.Popover(caret, {
            trigger: 'manual',
            html: true,
            animation: false,
            container: 'body',
            placement: 'right',
            fallbackPlacements: ['left', 'bottom', 'top'],
            customClass: 'cq-members-pop',
            // No header: the card heads itself
            template: '<div class="popover" role="dialog"><div class="popover-arrow"></div><div class="popover-body"></div></div>',
            content: box,
            // Where it fits on no side (a phone), it moves over its anchor rather than off screen
            popperConfig: function (defaults) {
                defaults.modifiers = (defaults.modifiers || []).concat([
                    { name: 'preventOverflow', options: { altAxis: true, padding: 8 } },
                ]);
                return defaults;
            },
        });
        popover.show();
        scripts.forEach(function (s) {
            const run = document.createElement('script');
            run.textContent = s.textContent;
            document.body.appendChild(run);
            run.remove();
        });
        popover.update();
        const tip = popover.tip || box.closest('.popover');
        tip.setAttribute('tabindex', '-1');
        tip.setAttribute('aria-label', caret.getAttribute('aria-label').replace(/^Open /, '').replace(/ here$/, ''));
        caret.setAttribute('aria-expanded', 'true');
        members = {
            caret: caret,
            cell: cell,
            popover: popover,
            tip: tip,
            onKey: function (e) {
                if (e.key === 'Escape' && !document.querySelector('.igw-pop')) {
                    e.preventDefault();
                    e.stopPropagation();
                    closeMembers(true);
                }
            },
            onPointer: function (e) {
                const t = e.target;
                if (tip.contains(t) || caret.contains(t) || (t.closest && t.closest('.igw-pop, .modal'))) {
                    return;
                }
                closeMembers(false);
            },
        };
        window.addEventListener('keydown', members.onKey, true);
        document.addEventListener('pointerdown', members.onPointer, true);
        tip.focus({ preventScroll: true });
        // Drawn from an estimate: when the rows came out taller, drawn again
        // with as many as the measured heights fit (the footer's line counted)
        const list = box.querySelector('[data-ce-list]');
        const rows = list ? list.children.length : 0;
        if (refit && rows > 3 && tip.offsetHeight > room()) {
            const row = list.offsetHeight / rows;
            const chrome = tip.offsetHeight - list.offsetHeight + 40;
            closeMembers(false);
            showMembers(caret, cell, html, membersPageSize(room(), row, chrome), false);
        }
    }

    function closeMembers(refocus) {
        if (!members) {
            return;
        }
        const m = members;
        members = null;
        window.removeEventListener('keydown', m.onKey, true);
        document.removeEventListener('pointerdown', m.onPointer, true);
        m.caret.setAttribute('aria-expanded', 'false');
        m.popover.dispose();
        if (refocus && document.contains(m.cell)) {
            m.cell.focus({ preventScroll: true });
        }
    }

    function reset() {
        objects.clear();
        fragments.clear();
        closeMembers(false);
        if (window.eventIndexCards) {
            window.eventIndexCards.closePop();
        }
    }

    return { views: views, open: open, reset: reset };
}

export { createInPlace };
