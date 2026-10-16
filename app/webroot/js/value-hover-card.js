/*
 * The value hover card.
 *
 * Hovering a value anywhere in MISP fetches the assessment of that
 * value and floats it beside the cursor. Proposal C of
 * `38-hover-card.md`; the markup is `value_hover_card.ctp` and the
 * rules are `value-hover-card.css`.
 *
 * **Its own listener rather than a Bootstrap popover**, for the reason
 * `value_claim_target_card.ctp` states: MISP initialises
 * `[data-bs-toggle]` once at `DOMContentLoaded`, so anything that
 * arrives later — every lazily-loaded attribute table on an event page
 * — would silently never bind. Delegation on `document.body` has no
 * such moment to miss.
 *
 * It deliberately does not reuse the hover-enrichment IIFE in
 * `mispOvermind.js`, which is the same shape but hardcoded to one URL
 * and one data attribute. Folding the two together is worth doing and
 * is not worth doing in the change that introduces the second one.
 */
(function () {
    'use strict';

    if (window._vpHoverCardBound) {
        return;
    }
    window._vpHoverCardBound = true;

    var TRIGGER = '.vp-hc-trigger[data-vp-hc-value]';

    /*
     * Long enough that sweeping a column does not fire fifty requests,
     * short enough that a deliberate hover feels answered. The
     * enrichment popover next door uses 400/250 and this is a cheaper
     * question, so it may be a little quicker to speak.
     */
    var SHOW_DELAY = 320;
    var HIDE_DELAY = 220;

    var host = null;
    var showTimer = null;
    var hideTimer = null;
    var currentValue = null;
    var token = 0;
    var inFlight = null;
    var cache = {};
    var lastHeight = 420;
    var lastEnrichRows = 0;

    /*
     * The enrichment strip is cached apart from the card and only once
     * every module on it has settled. The card's own HTML is cheap to
     * re-render and never changes; a strip is an outbound call per
     * module, so re-hovering a value must not ask a third party again —
     * and a half-answered strip must not be remembered as the answer.
     */
    var enrichCache = {};

    function base() {
        return (typeof baseurl === 'string' ? baseurl : '');
    }

    function element() {
        if (host) {
            return host;
        }
        host = document.createElement('div');
        host.id = 'vpHoverCard';
        host.setAttribute('role', 'tooltip');
        /*
         * Entering the card cancels the hide, so a reader can reach
         * *Open profile* without the thing they are reaching for
         * disappearing on the way.
         */
        host.addEventListener('mouseenter', function () {
            window.clearTimeout(hideTimer);
        });
        host.addEventListener('mouseleave', hide);
        host.addEventListener('click', function (event) {
            var more = event.target.closest('[data-vp-hce-more]');
            if (more) {
                expand(more);
            }
        });
        document.body.appendChild(host);
        return host;
    }

    /**
     * Open or close the rest of one module's answer.
     *
     * @param {Element} button
     */
    function expand(button) {
        var row = button.closest('[data-vp-eb-row]');
        if (!row) {
            return;
        }
        var open = !row.classList.contains('vp-hc-enr-open');
        row.classList.toggle('vp-hc-enr-open', open);
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
        refit();
    }

    /*
     * Grown by the reader, so it stays where it is rather than being
     * re-placed — which, above the anchor, would move the button out
     * from under the pointer — and only moves up as far as it has to
     * to stay on screen.
     */
    function refit() {
        var node = element();
        var margin = 12;
        var box = node.getBoundingClientRect();
        var over = box.bottom - (window.innerHeight - margin);
        if (over > 0) {
            node.style.top = Math.round(Math.max(margin, box.top - over))
                + 'px';
        }
    }

    /*
     * Placed against the anchor and clamped to the viewport: below and
     * left-aligned by default, flipped above when the space below is
     * shorter than the card, and pulled back inside when the anchor is
     * near the right edge. Measured after the markup is in, because a
     * card whose height is not known yet cannot be flipped correctly.
     */
    function place(anchor, reserve) {
        var node = element();
        var rect = anchor.getBoundingClientRect();
        var box = node.getBoundingClientRect();
        var gap = 8;
        var margin = 12;
        var limit = window.innerHeight - margin;
        // Pick the side the card will need, so it does not flip on arrival.
        var need = Math.max(box.height, reserve || 0);

        var top = rect.bottom + gap;
        if (top + need > limit) {
            if (rect.top - gap - need >= margin) {
                top = rect.top - gap - box.height;
            } else if (top + box.height > limit) {
                var above = rect.top - gap - box.height;
                if (above >= margin) {
                    top = above;
                } else {
                    top = Math.max(margin, limit - box.height);
                }
            }
        }

        var left = rect.left;
        if (left + box.width > window.innerWidth - margin) {
            left = window.innerWidth - margin - box.width;
        }
        node.style.top = Math.round(Math.max(margin, top)) + 'px';
        node.style.left = Math.round(Math.max(margin, left)) + 'px';
    }

    /*
     * The card's frame with the value already in it, so the hover is
     * answered at once and the assessment fills in when it lands.
     */
    function loading(anchor, value) {
        var node = element();
        var card = document.createElement('article');
        card.className = 'vp-hc vp-hc-lean-skel vp-hc-loading';
        card.setAttribute('aria-busy', 'true');
        card.innerHTML = '<span class="vp-hc-rail" aria-hidden="true"></span>'
            + '<div class="vp-hc-panel">'
            + '<div class="vp-hc-sec vp-hc-head">'
            + '<div class="vp-hc-value"></div></div>'
            + '<div class="vp-hc-sec vp-hc-wait">'
            + '<div class="misp-loader misp-loader-sm" role="status"></div>'
            + '<span>Loading assessment…</span></div>'
            + '</div>';
        var plain = decode(value);
        var head = card.querySelector('.vp-hc-head');
        if (plain === null) {
            head.remove();
        } else {
            head.firstChild.textContent = plain;
        }
        node.replaceChildren(card);
        node.classList.add('vp-hc-shown');
        place(anchor, lastHeight);
    }

    // The trigger carries the value as ValueUrlTool's URL-safe base64.
    function decode(b64) {
        try {
            var bin = window.atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
            var bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (e) {
            return null;
        }
    }

    function render(anchor, html, value) {
        var node = element();
        node.innerHTML = html;
        node.classList.add('vp-hc-shown');
        hold(node);
        place(anchor);
        if (value !== undefined) {
            lastHeight = node.getBoundingClientRect().height;
        }
        enrich(node, anchor, value);
    }

    /*
     * ------------------------------------------------------------------
     * Enrichment, which the card asks for itself.
     * ------------------------------------------------------------------
     * The card carries a placeholder holding the section open, and
     * the strip is a second request because knowing what a reader could
     * ask costs an outbound call to the modules service — the card's
     * whole cost argument is that a hover is worth one assessment and
     * nothing more.
     *
     * Then the modules that have to be run fill in one at a time, which
     * is the same contract the Overview panel fires under: the plan
     * travels on the markup, five go at a time, each is `mode=auto` at
     * an endpoint that decides the gate and the reuse window again when
     * it lands. What differs is `shape=chip`.
     */

    /**
     * Give the placeholder as many skeleton rows as the last section
     * drew, so the card keeps its height when the answers land.
     *
     * @param {Element} node The card
     */
    function hold(node) {
        var rows = node.querySelector('[data-vp-hc-enrich] .vp-hc-enr-rows');
        if (!rows || !rows.firstElementChild || !lastEnrichRows) {
            return;
        }
        while (rows.children.length > lastEnrichRows) {
            rows.lastElementChild.remove();
        }
        while (rows.children.length < lastEnrichRows) {
            rows.appendChild(rows.firstElementChild.cloneNode(true));
        }
    }

    /**
     * @param {Element} node The card
     * @param {Element} anchor
     * @param {string} value
     */
    function enrich(node, anchor, value) {
        var slot = node.querySelector('[data-vp-hc-enrich]');
        if (!slot) {
            return;
        }
        if (Object.prototype.hasOwnProperty.call(enrichCache, value)) {
            swap(slot, enrichCache[value], anchor);
            return;
        }
        fetch(slot.getAttribute('data-vp-hc-enrich'), {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (res) {
            return res.ok ? res.text() : '';
        }).then(function (html) {
            // The pointer may have moved on while this was in the air.
            if (!slot.isConnected || currentValue !== value) {
                return;
            }
            var strip = swap(slot, html, anchor);
            if (strip) {
                fire(strip, value, anchor);
            }
        }).catch(function () {
            if (slot.isConnected) {
                slot.remove();
            }
        });
    }

    /**
     * Put the strip where the placeholder was, or take the line back.
     *
     * @param {Element} slot
     * @param {string} html
     * @param {Element} anchor
     * @return {Element|null} The strip, where there was one
     */
    function swap(slot, html, anchor) {
        var trimmed = (html || '').trim();
        if (!trimmed) {
            /*
             * An instance with nothing to ask and nothing stored. The
             * line goes rather than standing empty, and the card is
             * re-placed because it just got shorter.
             */
            slot.remove();
            place(anchor);
            return null;
        }
        var holder = document.createElement('div');
        holder.innerHTML = trimmed;
        var strip = holder.firstElementChild;
        if (!strip) {
            slot.remove();
            place(anchor);
            return null;
        }
        slot.replaceWith(strip);
        lastEnrichRows = strip.querySelectorAll('[data-vp-eb-row]').length;
        place(anchor);
        return strip;
    }

    /**
     * Ask the modules the plan names, five lanes at a time.
     *
     * @param {Element} strip
     * @param {string} value
     * @param {Element} anchor
     */
    function fire(strip, value, anchor) {
        var plan;
        try {
            plan = JSON.parse(strip.getAttribute('data-vp-eb-fire') || '[]');
        } catch (e) {
            plan = [];
        }
        if (!Array.isArray(plan) || !plan.length) {
            // Every answer was already stored, so this is the settled one.
            keep(strip, value);
            return;
        }
        var queue = plan.slice();
        var width = parseInt(strip.getAttribute('data-vp-eb-max'), 10) || 5;
        var lanes = Math.min(width, queue.length);
        var running = [];
        var next = function () {
            var one = queue.shift();
            if (!one) {
                return Promise.resolve();
            }
            return ask(strip, one, value, anchor).then(next);
        };
        for (var i = 0; i < lanes; i++) {
            running.push(next());
        }
        Promise.all(running).then(function () {
            keep(strip, value);
        });
    }

    /**
     * Ask one module and put its headline where its spinner was.
     *
     * @param {Element} strip
     * @param {Object} one `module` and `type`
     * @param {string} value
     * @param {Element} anchor
     * @return {Promise}
     */
    function ask(strip, one, value, anchor) {
        var slot = slotFor(strip, one.module);
        if (!slot) {
            return Promise.resolve();
        }
        var body = new URLSearchParams();
        body.set('data[_Token][key]',
            strip.getAttribute('data-vp-eb-token') || '');
        body.set('data[module]', one.module);
        body.set('data[type]', one.type || '');
        body.set('data[mode]', 'auto');
        body.set('data[shape]',
            strip.getAttribute('data-vp-eb-shape') || 'chip');

        return fetch(strip.getAttribute('data-vp-eb-url'), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: body.toString()
        }).then(function (res) {
            return res.ok ? res.text() : '';
        }).then(function (html) {
            settle(slot, html, anchor);
        }).catch(function () {
            settle(slot, '', anchor);
        });
    }

    /**
     * @param {Element} slot
     * @param {string} html Empty where the module could not be asked
     * @param {Element} anchor
     */
    function settle(slot, html, anchor) {
        if (!slot.isConnected) {
            return;
        }
        var trimmed = (html || '').trim();
        slot.innerHTML = trimmed
            ? trimmed
            : '<span class="vp-hc-enr-ans">'
                + '<span class="vp-hce-v vp-hce-fail">no answer</span>'
                + '</span>';
        place(anchor);
    }

    /**
     * Remember a strip once nothing on it is still being asked.
     *
     * @param {Element} strip
     * @param {string} value
     */
    function keep(strip, value) {
        if (!strip.isConnected
            || strip.querySelector('[data-vp-eb-slot] .fa-spin')
            || strip.querySelector('[data-vp-eb-slot] .vp-hce-wait')
        ) {
            /*
             * Still moving. A spinner is this page's own request and
             * will resolve; `vp-hce-wait` is somebody else's, which
             * this page never sees land — so neither is an answer, and
             * remembering either would cache the waiting as the result.
             */
            return;
        }
        var copy = strip.cloneNode(true);
        copy.querySelectorAll('.vp-hc-enr-open').forEach(function (row) {
            row.classList.remove('vp-hc-enr-open');
        });
        copy.querySelectorAll('[data-vp-hce-more]').forEach(function (b) {
            b.setAttribute('aria-expanded', 'false');
        });
        enrichCache[value] = copy.outerHTML;
    }

    /**
     * The slot belonging to one module.
     *
     * Walked rather than selected: a module name is a third party's
     * string and `querySelector` would need it escaped, which is a
     * dependency on `CSS.escape` for nothing.
     *
     * @param {Element} strip
     * @param {string} name
     * @return {Element|null}
     */
    function slotFor(strip, name) {
        var rows = strip.querySelectorAll('[data-vp-eb-row]');
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].getAttribute('data-vp-eb-row') === name) {
                return rows[i].querySelector('[data-vp-eb-slot]');
            }
        }
        return null;
    }

    function hide() {
        window.clearTimeout(showTimer);
        window.clearTimeout(hideTimer);
        currentValue = null;
        if (inFlight) {
            inFlight.abort();
            inFlight = null;
        }
        if (host) {
            host.classList.remove('vp-hc-shown');
        }
    }

    function show(anchor, value) {
        var mine = ++token;
        currentValue = value;

        if (Object.prototype.hasOwnProperty.call(cache, value)) {
            render(anchor, cache[value], value);
            return;
        }

        loading(anchor, value);

        if (window.AbortController) {
            inFlight = new window.AbortController();
        }
        var options = {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        };
        if (inFlight) {
            options.signal = inFlight.signal;
        }

        fetch(
            base() + '/values/viewHoverCard/' + encodeURIComponent(value),
            options
        ).then(function (res) {
            if (!res.ok) {
                throw new Error('HTTP ' + res.status);
            }
            return res.text();
        }).then(function (html) {
            cache[value] = html;
            // The pointer may have moved on while this was in the air.
            if (mine === token && currentValue === value) {
                render(anchor, html, value);
            }
        }).catch(function (err) {
            if (err && err.name === 'AbortError') {
                return;
            }
            if (mine !== token) {
                return;
            }
            render(
                anchor,
                '<div class="vp-hc-error">'
                + 'Could not load this value’s assessment.'
                + '</div>'
            );
        });
    }

    function triggerFor(target) {
        if (!target || !target.closest) {
            return null;
        }
        return target.closest(TRIGGER);
    }

    document.body.addEventListener('mouseover', function (event) {
        var trigger = triggerFor(event.target);
        if (!trigger) {
            return;
        }
        var value = trigger.getAttribute('data-vp-hc-value');
        if (!value) {
            return;
        }
        window.clearTimeout(hideTimer);
        window.clearTimeout(showTimer);
        showTimer = window.setTimeout(function () {
            show(trigger, value);
        }, SHOW_DELAY);
    });

    document.body.addEventListener('mouseout', function (event) {
        if (!triggerFor(event.target)) {
            return;
        }
        window.clearTimeout(showTimer);
        hideTimer = window.setTimeout(hide, HIDE_DELAY);
    });

    /*
     * Keyboard parity. The trigger is focusable, so tabbing onto it
     * shows the card without the delay a pointer needs — a reader who
     * tabbed there has already declared intent.
     */
    document.body.addEventListener('focusin', function (event) {
        var trigger = triggerFor(event.target);
        if (!trigger) {
            return;
        }
        var value = trigger.getAttribute('data-vp-hc-value');
        if (value) {
            show(trigger, value);
        }
    });

    document.body.addEventListener('focusout', function (event) {
        if (triggerFor(event.target)) {
            hideTimer = window.setTimeout(hide, HIDE_DELAY);
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            hide();
        }
    });

    // Capture, so a scroll inside `.table-responsive` counts too.
    window.addEventListener('scroll', hide, true);
    window.addEventListener('resize', hide);
}());
