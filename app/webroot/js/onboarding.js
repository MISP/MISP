/**
 * Overmind onboarding — interactive product tour.
 *
 * The tour walks a user through the application with a spotlight over the
 * real UI (no screenshots, no sandbox) so every step is anchored to the
 * element the user will actually click. Step content is authored server
 * side in app/Lib/Tools/OnboardingTour.php so it stays translatable and
 * ACL-aware; this file only knows how to render and sequence it.
 *
 * Design notes:
 *  - Vanilla JS. BS5 Overmind pages do not load jQuery or misp.js.
 *  - Positioning is hand-rolled: bootstrap.bundle embeds Popper but does
 *    not export it as a global, so there is nothing to reuse.
 *  - Progress lives in sessionStorage, which is what makes a tour able to
 *    span several page loads (e.g. events/index -> events/add -> event view).
 *  - A step whose page the user has not reached yet does not block: the
 *    tour parks itself in a dock and resumes when the page matches.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'mispOnboardingState';
    var SPOTLIGHT_PAD = 6;      // px of breathing room around the anchor
    var POPOVER_GAP = 14;       // px between the anchor and the popover
    var VIEWPORT_MARGIN = 12;   // px the popover keeps from the edges
    var ANCHOR_TIMEOUT = 6000;  // ms to wait for a lazily rendered anchor
    var SETTLE_POLL_MS = 120;   // fallback re-measure when rAF is throttled

    // Above the Bootstrap modal (1055) so the tour can walk into a modal.
    var Z_DOCK = 1070;
    var Z_OVERLAY = 1080;
    var Z_POPOVER = 1085;

    /**
     * Run state. `sections` is the ordered list of section ids for this run,
     * which may be a subset of the catalogue when the user picks one section.
     */
    var run = null;
    var catalogue = null;
    var catalogueRequest = null;

    // Live DOM handles for the current step.
    var nodes = { overlay: null, spotlight: null, popover: null, dock: null };
    var anchorEl = null;
    var anchorClickHandler = null;
    var trackingFrame = null;
    var anchorWaitCancel = null;
    var settleFrame = null;
    var settleTimer = null;
    var settleLast = null;

    var reduceMotion = window.matchMedia
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    /* ----------------------------------------------------------------- */
    /* Utilities                                                          */
    /* ----------------------------------------------------------------- */

    function base() {
        return typeof baseurl === 'string' ? baseurl : '';
    }

    /** Path of the current page with the MISP base path stripped off. */
    function currentPath() {
        var path = window.location.pathname;
        var prefix = base();
        if (prefix && path.indexOf(prefix) === 0) {
            path = path.slice(prefix.length);
        }
        return path || '/';
    }

    function escapeHtml(value) {
        return String(value === null || value === undefined ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function el(tag, className, html) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (html !== undefined) {
            node.innerHTML = html;
        }
        return node;
    }

    function readState() {
        try {
            var raw = window.sessionStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function writeState() {
        try {
            if (run) {
                window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(run));
            } else {
                window.sessionStorage.removeItem(STORAGE_KEY);
            }
        } catch (e) {
            /* Private mode or a full quota — the tour degrades to one page. */
        }
    }

    /* ----------------------------------------------------------------- */
    /* Catalogue                                                          */
    /* ----------------------------------------------------------------- */

    /**
     * Fetch the step catalogue once per page load. The server filters it by
     * the current user's ACL, so a user without `events/add` never sees a
     * step pointing at a button they do not have.
     */
    function loadCatalogue() {
        if (catalogue) {
            return Promise.resolve(catalogue);
        }
        if (!catalogueRequest) {
            catalogueRequest = fetch(base() + '/users/onboarding.json', {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('Onboarding catalogue unavailable');
                    }
                    return response.json();
                })
                .then(function (data) {
                    catalogue = data && data.sections ? data : { sections: [] };
                    return catalogue;
                })
                .catch(function (error) {
                    catalogueRequest = null;
                    throw error;
                });
        }
        return catalogueRequest;
    }

    function findSection(id) {
        var sections = (catalogue && catalogue.sections) || [];
        for (var i = 0; i < sections.length; i++) {
            if (sections[i].id === id) {
                return sections[i];
            }
        }
        return null;
    }

    function currentSection() {
        return run ? findSection(run.sections[run.sectionIndex]) : null;
    }

    function currentStep() {
        var section = currentSection();
        if (!section || !section.steps) {
            return null;
        }
        return section.steps[run.stepIndex] || null;
    }

    /** Total steps across the run, used for the overall progress bar. */
    function runTotals() {
        var done = 0;
        var total = 0;
        if (!run) {
            return { done: 0, total: 0 };
        }
        for (var i = 0; i < run.sections.length; i++) {
            var section = findSection(run.sections[i]);
            var count = section && section.steps ? section.steps.length : 0;
            total += count;
            if (i < run.sectionIndex) {
                done += count;
            } else if (i === run.sectionIndex) {
                done += Math.min(run.stepIndex, count);
            }
        }
        return { done: done, total: total };
    }

    /* ----------------------------------------------------------------- */
    /* Anchor resolution                                                  */
    /* ----------------------------------------------------------------- */

    /**
     * Resolve a selector that may not exist yet — event view tabs load their
     * content over AJAX, and modal bodies are injected after a click. Falls
     * back to null after ANCHOR_TIMEOUT so a stale selector cannot wedge the
     * tour.
     */
    function waitForAnchor(selector) {
        var settled = false;
        var observer = null;
        var timer = null;

        var promise = new Promise(function (resolve) {
            function finish(node) {
                if (settled) {
                    return;
                }
                settled = true;
                if (observer) {
                    observer.disconnect();
                }
                if (timer) {
                    window.clearTimeout(timer);
                }
                resolve(node);
            }

            var existing = document.querySelector(selector);
            if (existing && isVisible(existing)) {
                finish(existing);
                return;
            }

            observer = new MutationObserver(function () {
                var node = document.querySelector(selector);
                if (node && isVisible(node)) {
                    finish(node);
                }
            });
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['class', 'style']
            });

            timer = window.setTimeout(function () {
                finish(null);
            }, ANCHOR_TIMEOUT);

            anchorWaitCancel = function () {
                finish(null);
            };
        });

        return promise;
    }

    function isVisible(node) {
        if (!node) {
            return false;
        }
        var rect = node.getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) {
            return false;
        }
        var style = window.getComputedStyle(node);
        return style.visibility !== 'hidden' && style.display !== 'none';
    }

    /* ----------------------------------------------------------------- */
    /* Chrome construction                                                */
    /* ----------------------------------------------------------------- */

    function ensureChrome() {
        if (nodes.overlay) {
            return;
        }

        nodes.overlay = el('div', 'onboarding-overlay');
        nodes.overlay.style.zIndex = Z_OVERLAY;

        nodes.spotlight = el('div', 'onboarding-spotlight');
        nodes.overlay.appendChild(nodes.spotlight);

        nodes.popover = el('div', 'onboarding-popover');
        nodes.popover.style.zIndex = Z_POPOVER;
        nodes.popover.setAttribute('role', 'dialog');
        nodes.popover.setAttribute('aria-live', 'polite');
        nodes.popover.setAttribute('aria-modal', 'false');
        nodes.popover.setAttribute('tabindex', '-1');

        document.body.appendChild(nodes.overlay);
        document.body.appendChild(nodes.popover);

        document.addEventListener('keydown', onKeydown, true);
        window.addEventListener('resize', scheduleTracking);
        window.addEventListener('scroll', scheduleTracking, true);
    }

    function destroyChrome() {
        stopTracking();
        detachAnchorClick();
        document.removeEventListener('keydown', onKeydown, true);
        window.removeEventListener('resize', scheduleTracking);
        window.removeEventListener('scroll', scheduleTracking, true);

        ['overlay', 'popover', 'dock'].forEach(function (key) {
            if (nodes[key] && nodes[key].parentNode) {
                nodes[key].parentNode.removeChild(nodes[key]);
            }
            nodes[key] = null;
        });
        nodes.spotlight = null;
        document.body.classList.remove('onboarding-active');
    }

    function onKeydown(event) {
        if (!run || !nodes.popover) {
            return;
        }
        if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            stop(true);
            return;
        }
        // Arrow shortcuts must never reach a field the user is filling in —
        // several steps sit on top of forms and spotlight the input itself.
        if (isTextEntry(event.target)) {
            return;
        }
        if (event.key === 'ArrowRight') {
            event.preventDefault();
            next();
        } else if (event.key === 'ArrowLeft') {
            event.preventDefault();
            previous();
        }
    }

    function isTextEntry(node) {
        if (!node || node.nodeType !== 1) {
            return false;
        }
        if (node.isContentEditable) {
            return true;
        }
        var tag = node.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    }

    /* ----------------------------------------------------------------- */
    /* Positioning                                                        */
    /* ----------------------------------------------------------------- */

    function scheduleTracking() {
        if (trackingFrame) {
            return;
        }
        trackingFrame = window.requestAnimationFrame(function () {
            trackingFrame = null;
            positionForAnchor();
        });
    }

    function stopTracking() {
        if (trackingFrame) {
            window.cancelAnimationFrame(trackingFrame);
            trackingFrame = null;
        }
        stopSettle();
    }

    /**
     * Follow the anchor's box for as long as the step is on screen.
     *
     * Scroll and resize listeners are not enough: a step can render while the
     * Bootstrap modal it lives in is still fading in, and that animation moves
     * the anchor ~50px without firing either event — the spotlight would sit
     * where the field *was*. Anything else that reflows after first paint
     * (fonts, images, lazily loaded tab content, a collapsing notice) lands in
     * the same trap.
     *
     * A bounded "settle" window was tried first and is not enough either: the
     * box is briefly stable at render, so the window closes before the modal
     * animation has even started and the drift survives. Hence a plain frame
     * loop, which only writes styles when the box actually moved, so a static
     * step costs one getBoundingClientRect per frame and nothing else.
     */
    function startSettle() {
        stopSettle();
        settleLast = null;
        settleFrame = window.requestAnimationFrame(settleTick);
        // Safety net: requestAnimationFrame is throttled to a standstill in
        // background tabs and in some headless configurations, and the tour
        // must not leave a spotlight stranded when that happens. The interval
        // is deliberately coarse — it only has to catch up, the frame loop is
        // what makes it smooth when it is running.
        settleTimer = window.setInterval(syncSpotlight, SETTLE_POLL_MS);
    }

    function stopSettle() {
        if (settleFrame) {
            window.cancelAnimationFrame(settleFrame);
            settleFrame = null;
        }
        if (settleTimer) {
            window.clearInterval(settleTimer);
            settleTimer = null;
        }
    }

    /** Re-place the chrome only when the anchor's box actually moved. */
    function syncSpotlight() {
        if (!run || !anchorEl || !document.body.contains(anchorEl)) {
            return false;
        }
        var r = anchorEl.getBoundingClientRect();
        var key = [r.top, r.left, r.width, r.height].join(',');
        if (key !== settleLast) {
            settleLast = key;
            positionForAnchor();
        }
        return true;
    }

    function settleTick() {
        settleFrame = null;
        if (!syncSpotlight()) {
            return;
        }
        settleFrame = window.requestAnimationFrame(settleTick);
    }

    function positionForAnchor() {
        if (!nodes.popover || !run) {
            return;
        }
        var step = currentStep();
        if (!step) {
            return;
        }
        if (!anchorEl || !document.body.contains(anchorEl)) {
            centreStep();
            return;
        }

        var rect = anchorEl.getBoundingClientRect();
        var box = {
            top: rect.top - SPOTLIGHT_PAD,
            left: rect.left - SPOTLIGHT_PAD,
            width: rect.width + SPOTLIGHT_PAD * 2,
            height: rect.height + SPOTLIGHT_PAD * 2
        };

        nodes.spotlight.style.display = 'block';
        nodes.spotlight.style.top = box.top + 'px';
        nodes.spotlight.style.left = box.left + 'px';
        nodes.spotlight.style.width = box.width + 'px';
        nodes.spotlight.style.height = box.height + 'px';

        nodes.popover.classList.remove('is-centred');
        placePopover(box, step.placement || 'bottom');
    }

    function centreStep() {
        if (nodes.spotlight) {
            nodes.spotlight.style.display = 'none';
        }
        nodes.popover.classList.add('is-centred');
        nodes.popover.style.top = '';
        nodes.popover.style.left = '';
        setArrow(null);
    }

    /**
     * Place the popover on the requested side, flipping to the opposite side
     * when it would overflow and finally clamping into the viewport. The
     * arrow follows the anchor centre rather than the popover centre, which
     * keeps it pointing at the right thing after clamping.
     */
    function placePopover(box, placement) {
        var pop = nodes.popover;
        pop.style.top = '0px';
        pop.style.left = '0px';

        var width = pop.offsetWidth;
        var height = pop.offsetHeight;
        var vw = document.documentElement.clientWidth;
        var vh = document.documentElement.clientHeight;

        var room = {
            top: box.top,
            bottom: vh - (box.top + box.height),
            left: box.left,
            right: vw - (box.left + box.width)
        };
        var need = {
            top: height + POPOVER_GAP,
            bottom: height + POPOVER_GAP,
            left: width + POPOVER_GAP,
            right: width + POPOVER_GAP
        };

        var order = [placement, opposite(placement), 'bottom', 'top',
            'right', 'left'];
        var side = placement;
        for (var i = 0; i < order.length; i++) {
            if (room[order[i]] >= need[order[i]]) {
                side = order[i];
                break;
            }
        }

        var top;
        var left;
        if (side === 'top' || side === 'bottom') {
            top = side === 'top'
                ? box.top - height - POPOVER_GAP
                : box.top + box.height + POPOVER_GAP;
            left = box.left + (box.width - width) / 2;
        } else {
            left = side === 'left'
                ? box.left - width - POPOVER_GAP
                : box.left + box.width + POPOVER_GAP;
            top = box.top + (box.height - height) / 2;
        }

        left = clamp(left, VIEWPORT_MARGIN, vw - width - VIEWPORT_MARGIN);
        top = clamp(top, VIEWPORT_MARGIN, vh - height - VIEWPORT_MARGIN);

        pop.style.top = Math.round(top) + 'px';
        pop.style.left = Math.round(left) + 'px';

        var anchorCentre = (side === 'top' || side === 'bottom')
            ? box.left + box.width / 2 - left
            : box.top + box.height / 2 - top;
        setArrow(side, anchorCentre);
    }

    function opposite(side) {
        return { top: 'bottom', bottom: 'top', left: 'right', right: 'left' }
            [side] || 'bottom';
    }

    function clamp(value, min, max) {
        if (max < min) {
            return min;
        }
        return Math.min(Math.max(value, min), max);
    }

    function setArrow(side, offset) {
        var arrow = nodes.popover.querySelector('.onboarding-arrow');
        if (!arrow) {
            return;
        }
        arrow.className = 'onboarding-arrow';
        if (!side) {
            arrow.style.display = 'none';
            return;
        }
        arrow.style.display = 'block';
        arrow.classList.add('arrow-' + side);
        var limited = clamp(offset, 18, (side === 'top' || side === 'bottom'
            ? nodes.popover.offsetWidth
            : nodes.popover.offsetHeight) - 18);
        if (side === 'top' || side === 'bottom') {
            arrow.style.left = limited + 'px';
            arrow.style.top = '';
        } else {
            arrow.style.top = limited + 'px';
            arrow.style.left = '';
        }
    }

    /* ----------------------------------------------------------------- */
    /* Step rendering                                                     */
    /* ----------------------------------------------------------------- */

    function renderStep() {
        if (!run) {
            return;
        }
        var section = currentSection();
        if (!section) {
            finish();
            return;
        }
        var step = currentStep();
        if (!step) {
            nextSection();
            return;
        }

        // Running a single sub-section: stop as soon as we walk out of it.
        if (run.onlyGroup && step.groupId !== run.onlyGroup) {
            finish();
            return;
        }

        // A step that is redundant where we already are — "open an event"
        // when the user is on one. Skipped in whichever direction we were
        // travelling, so stepping back through it does not bounce.
        if (step.skipIf && new RegExp(step.skipIf).test(currentPath())) {
            if (run.dir === -1) {
                if (!isFirstOfRun()) {
                    previous();
                    return;
                }
            } else {
                next();
                return;
            }
        }

        // A step can require a page the user is not on. If we know where it
        // lives we navigate; otherwise the step is waiting on something the
        // user must do (submitting a form), so we park in the dock.
        if (step.pageMatch && !new RegExp(step.pageMatch).test(currentPath())) {
            if (step.page && !alreadyTriedNavigating()) {
                navigateTo(step.page);
                return;
            }
            showDock(step);
            return;
        }
        if (step.page && !step.pageMatch && step.page !== currentPath()) {
            if (alreadyTriedNavigating()) {
                // We navigated here for this very step and still landed
                // somewhere else — the target redirected. Navigating again
                // would reload forever, so dock and let the user carry on.
                showDock(step);
                return;
            }
            navigateTo(step.page);
            return;
        }
        run.navFor = null;

        // Some steps point back at the page behind a dialog the tour opened
        // a moment ago. Close it first, and wait for the layout to settle so
        // the spotlight measures the final position.
        if (step.closeModal && closeMainModal(renderStep)) {
            return;
        }

        writeState();
        hideDock();
        ensureChrome();
        applyAccent(section);
        document.body.classList.add('onboarding-active');
        detachAnchorClick();

        if (anchorWaitCancel) {
            anchorWaitCancel();
            anchorWaitCancel = null;
        }

        paintPopover(section, step);

        if (!step.anchor) {
            anchorEl = null;
            centreStep();
            focusPopover();
            return;
        }

        // Show the copy centred straight away and move onto the anchor once
        // it resolves. Lazily loaded tabs and modal bodies can take a moment,
        // and an un-positioned popover would otherwise sit in the top-left
        // corner for the duration.
        anchorEl = null;
        centreStep();

        waitForAnchor(step.anchor).then(function (node) {
            if (!run || currentStep() !== step) {
                return;
            }
            anchorWaitCancel = null;
            if (!node) {
                // The anchor never showed up. An optional step is skipped so
                // the tour keeps moving; otherwise we still show the copy,
                // just without a spotlight.
                if (step.optional) {
                    next();
                    return;
                }
                anchorEl = null;
                centreStep();
                focusPopover();
                return;
            }
            anchorEl = node;
            if (step.scroll !== false) {
                node.scrollIntoView({
                    behavior: reduceMotion ? 'auto' : 'smooth',
                    block: 'center',
                    inline: 'nearest'
                });
            }
            attachAnchorClick(step, node);
            positionForAnchor();
            // Keep measuring until the box stops moving — the scroll above and
            // any modal still fading in both shift it after this point.
            startSettle();
            window.setTimeout(function () {
                if (run && currentStep() === step) {
                    focusPopover();
                }
            }, reduceMotion ? 0 : 260);
        });
    }

    /**
     * Where the given step sits inside its own group, so the counter reads
     * "Step 2 of 6" within the part rather than across a 20-step section.
     */
    function groupPosition(section, index) {
        var step = section.steps[index];
        if (!step || !step.groupId) {
            return {
                title: null,
                pos: index + 1,
                total: section.steps.length,
                isLast: index === section.steps.length - 1
            };
        }
        var pos = 0;
        var total = 0;
        var lastIndex = -1;
        for (var i = 0; i < section.steps.length; i++) {
            if (section.steps[i].groupId !== step.groupId) {
                continue;
            }
            total++;
            lastIndex = i;
            if (i <= index) {
                pos++;
            }
        }
        return {
            title: step.group || null,
            pos: pos,
            total: total,
            isLast: index === lastIndex
        };
    }

    /** Sections carry sub-sections only when the catalogue declared several. */
    function hasParts(section) {
        return !!(section.groups && section.groups.length > 1);
    }

    /**
     * Tint the tour chrome with the running section's colour, so the eyebrow,
     * the progress bar and the spotlight ring all read as belonging to the
     * section you are in. The catalogue names a palette token; onboarding.css
     * owns the mapping, so no colour value passes through here.
     */
    function applyAccent(section) {
        var accent = 'onb-accent-'
            + String((section && section.colour) || 'primary')
                .replace(/[^a-z0-9-]/gi, '');
        ['popover', 'overlay', 'dock'].forEach(function (key) {
            var node = nodes[key];
            if (!node) {
                return;
            }
            node.className = node.className
                .split(/\s+/)
                .filter(function (c) {
                    return c && c.indexOf('onb-accent-') !== 0;
                })
                .concat(accent)
                .join(' ');
        });
    }

    function paintPopover(section, step) {
        var totals = runTotals();
        var percent = totals.total
            ? Math.round((totals.done / totals.total) * 100)
            : 0;
        var group = groupPosition(section, run.stepIndex);
        var parts = hasParts(section) && !run.onlyGroup;
        var isLastStep = run.stepIndex === section.steps.length - 1;
        var isLastSection = run.sectionIndex === run.sections.length - 1;

        var nextLabel;
        if (run.onlyGroup) {
            nextLabel = group.isLast ? i18n('finish') : i18n('next');
        } else if (isLastStep) {
            nextLabel = isLastSection ? i18n('finish') : i18n('nextSection');
        } else if (parts && group.isLast) {
            nextLabel = i18n('nextPart');
        } else {
            nextLabel = i18n('next');
        }

        // Section · part · position. The part is dropped when the section has
        // only one, which would just repeat the section name.
        var eyebrow = '<i class="'
            + escapeHtml(section.icon || 'fas fa-compass') + ' me-1"></i>'
            + escapeHtml(section.title);
        if (group.title && (parts || run.onlyGroup)) {
            eyebrow += ' &middot; ' + escapeHtml(group.title);
        }
        eyebrow += ' &middot; '
            + escapeHtml(i18n('stepOf', group.pos, group.total));

        var skips = '';
        if (parts) {
            skips += '<button type="button" class="btn btn-link btn-sm '
                + 'onboarding-skip-part">' + escapeHtml(i18n('skipPart'))
                + '</button>';
        }
        if (!run.onlyGroup) {
            skips += '<button type="button" class="btn btn-link btn-sm '
                + 'onboarding-skip-section">' + escapeHtml(i18n('skipSection'))
                + '</button>';
        }
        skips += '<button type="button" class="btn btn-link btn-sm '
            + 'onboarding-skip-all">' + escapeHtml(i18n('skipAll'))
            + '</button>';

        nodes.popover.innerHTML = ''
            + '<div class="onboarding-arrow"></div>'
            + '<div class="onboarding-head">'
            + '<span class="onboarding-eyebrow">' + eyebrow + '</span>'
            + '<button type="button" class="onboarding-close" '
            + 'title="' + escapeHtml(i18n('skipAll')) + '" '
            + 'aria-label="' + escapeHtml(i18n('skipAll')) + '">'
            + '<i class="fas fa-xmark"></i></button>'
            + '</div>'
            + '<h5 class="onboarding-title">' + escapeHtml(step.title) + '</h5>'
            + '<div class="onboarding-body">' + (step.body || '') + '</div>'
            + '<div class="onboarding-progress" role="progressbar" '
            + 'aria-valuenow="' + percent + '" aria-valuemin="0" '
            + 'aria-valuemax="100">'
            + '<span style="width:' + percent + '%"></span>'
            + '</div>'
            + '<div class="onboarding-foot">'
            + '<div class="onboarding-foot-left">' + skips + '</div>'
            + '<div class="onboarding-foot-right">'
            + '<button type="button" class="btn btn-outline-secondary btn-sm '
            + 'onboarding-prev"' + (isFirstOfRun() ? ' disabled' : '') + '>'
            + escapeHtml(i18n('back')) + '</button>'
            + '<button type="button" class="btn btn-primary btn-sm '
            + 'onboarding-next">' + escapeHtml(nextLabel) + '</button>'
            + '</div>'
            + '</div>';

        bind('.onboarding-next', next);
        bind('.onboarding-prev', previous);
        bind('.onboarding-skip-part', nextGroup);
        bind('.onboarding-skip-section', nextSection);
        bind('.onboarding-skip-all', function () { stop(true); });
        bind('.onboarding-close', function () { stop(true); });

        // A step that waits for the user's own click hides Next so the only
        // way forward is the real interaction the tutorial is teaching.
        if (step.advance === 'click') {
            var nextBtn = nodes.popover.querySelector('.onboarding-next');
            if (nextBtn) {
                nextBtn.classList.add('is-waiting');
                nextBtn.textContent = i18n('waitingForClick');
                nextBtn.disabled = true;
            }
        }
    }

    function bind(selector, handler) {
        var node = nodes.popover.querySelector(selector);
        if (node) {
            node.addEventListener('click', function (event) {
                event.preventDefault();
                handler();
            });
        }
    }

    function isFirstOfRun() {
        return run.sectionIndex === 0 && run.stepIndex === 0;
    }

    function focusPopover() {
        if (nodes.popover) {
            nodes.popover.focus({ preventScroll: true });
        }
    }

    function attachAnchorClick(step, node) {
        if (step.advance !== 'click') {
            return;
        }
        anchorClickHandler = function () {
            // Advance before the browser acts on the click: if the anchor is
            // a link or a submit button the page is about to unload, and the
            // state we just wrote is what resumes the tour on the next page.
            advanceIndex();
            writeState();
            window.setTimeout(function () {
                if (run) {
                    renderStep();
                }
            }, 0);
        };
        node.addEventListener('click', anchorClickHandler, { once: true });
        anchorEl = node;
    }

    function detachAnchorClick() {
        if (anchorEl && anchorClickHandler) {
            anchorEl.removeEventListener('click', anchorClickHandler);
        }
        anchorClickHandler = null;
    }

    /* ----------------------------------------------------------------- */
    /* Sequencing                                                         */
    /* ----------------------------------------------------------------- */

    function advanceIndex() {
        var section = currentSection();
        var count = section && section.steps ? section.steps.length : 0;
        if (run.stepIndex + 1 < count) {
            run.stepIndex += 1;
        } else {
            run.sectionIndex += 1;
            run.stepIndex = 0;
        }
    }

    function next() {
        if (!run) {
            return;
        }
        run.dir = 1;
        advanceIndex();
        if (run.sectionIndex >= run.sections.length) {
            finish();
            return;
        }
        renderStep();
    }

    function previous() {
        if (!run || isFirstOfRun()) {
            return;
        }
        run.dir = -1;
        if (run.stepIndex > 0) {
            run.stepIndex -= 1;
        } else {
            run.sectionIndex -= 1;
            var section = currentSection();
            run.stepIndex = section && section.steps
                ? Math.max(section.steps.length - 1, 0)
                : 0;
        }
        renderStep();
    }

    /** Jump past the rest of the current sub-section. */
    function nextGroup() {
        if (!run) {
            return;
        }
        var section = currentSection();
        var step = currentStep();
        if (!section || !step || !step.groupId || run.onlyGroup) {
            nextSection();
            return;
        }
        run.dir = 1;
        var i = run.stepIndex;
        while (i < section.steps.length
            && section.steps[i].groupId === step.groupId) {
            i += 1;
        }
        if (i >= section.steps.length) {
            nextSection();
            return;
        }
        run.stepIndex = i;
        renderStep();
    }

    function nextSection() {
        if (!run) {
            return;
        }
        run.dir = 1;
        run.sectionIndex += 1;
        run.stepIndex = 0;
        if (run.sectionIndex >= run.sections.length) {
            finish();
            return;
        }
        renderStep();
    }

    /**
     * True when the last navigation this tour performed was already an
     * attempt to reach the step we are looking at now. Guards against a
     * redirecting target turning the tour into a reload loop.
     */
    function alreadyTriedNavigating() {
        return run.navFor === run.sectionIndex + ':' + run.stepIndex;
    }

    function navigateTo(path) {
        run.navFor = run.sectionIndex + ':' + run.stepIndex;
        writeState();
        window.location.assign(base() + path);
    }

    /* ----------------------------------------------------------------- */
    /* Dock — shown while the tour waits for the user to reach a page      */
    /* ----------------------------------------------------------------- */

    function showDock(step) {
        hideChromeOnly();
        if (!nodes.dock) {
            nodes.dock = el('div', 'onboarding-dock');
            nodes.dock.style.zIndex = Z_DOCK;
            document.body.appendChild(nodes.dock);
        }
        var section = currentSection();
        nodes.dock.innerHTML = ''
            + '<div class="onboarding-dock-body">'
            + '<div class="onboarding-dock-title">'
            + '<i class="fas fa-graduation-cap me-2"></i>'
            + escapeHtml(section ? section.title : i18n('tutorial'))
            + '</div>'
            + '<div class="onboarding-dock-text">'
            + escapeHtml(step.waitingText || i18n('waitingDefault'))
            + '</div>'
            + '</div>'
            + '<div class="onboarding-dock-actions">'
            + '<button type="button" class="btn btn-sm btn-outline-secondary '
            + 'onboarding-dock-skip">' + escapeHtml(i18n('skipSection'))
            + '</button>'
            + '<button type="button" class="btn btn-sm btn-link '
            + 'onboarding-dock-stop">' + escapeHtml(i18n('skipAll'))
            + '</button>'
            + '</div>';

        applyAccent(section);
        nodes.dock.querySelector('.onboarding-dock-skip')
            .addEventListener('click', nextSection);
        nodes.dock.querySelector('.onboarding-dock-stop')
            .addEventListener('click', function () { stop(true); });
        writeState();
    }

    /**
     * Dismiss the shared Overmind modal. Returns true when a hide was
     * actually started, in which case `then` runs once it has finished and
     * the caller should bail out of the current render.
     */
    function closeMainModal(then) {
        var host = document.getElementById('mainModal');
        if (!host || !window.bootstrap || !host.classList.contains('show')) {
            return false;
        }
        var instance = bootstrap.Modal.getInstance(host);
        if (!instance) {
            return false;
        }
        host.addEventListener('hidden.bs.modal', function handler() {
            host.removeEventListener('hidden.bs.modal', handler);
            if (run) {
                then();
            }
        });
        instance.hide();
        return true;
    }

    function hideDock() {
        if (nodes.dock && nodes.dock.parentNode) {
            nodes.dock.parentNode.removeChild(nodes.dock);
        }
        nodes.dock = null;
    }

    /** Drop the spotlight/popover but keep listeners for a docked tour. */
    function hideChromeOnly() {
        stopTracking();
        detachAnchorClick();
        ['overlay', 'popover'].forEach(function (key) {
            if (nodes[key] && nodes[key].parentNode) {
                nodes[key].parentNode.removeChild(nodes[key]);
            }
            nodes[key] = null;
        });
        nodes.spotlight = null;
        document.body.classList.remove('onboarding-active');
    }

    /* ----------------------------------------------------------------- */
    /* Lifecycle                                                          */
    /* ----------------------------------------------------------------- */

    /**
     * @param {Array|null} sectionIds Sections to run; all of them when empty.
     * @param {string} [groupId] Restrict the run to one sub-section.
     */
    function start(sectionIds, groupId) {
        loadCatalogue().then(function (data) {
            var ids = sectionIds && sectionIds.length
                ? sectionIds
                : data.sections.map(function (s) { return s.id; });
            ids = ids.filter(function (id) {
                var section = findSection(id);
                return section && section.steps && section.steps.length;
            });
            if (!ids.length) {
                return;
            }
            run = {
                sections: ids,
                sectionIndex: 0,
                stepIndex: 0,
                dir: 1,
                onlyGroup: groupId || null
            };
            if (groupId) {
                // Jump straight to the requested part.
                var steps = findSection(ids[0]).steps;
                for (var i = 0; i < steps.length; i++) {
                    if (steps[i].groupId === groupId) {
                        run.stepIndex = i;
                        break;
                    }
                }
            }
            markSeen();
            renderStep();
        }).catch(function () {
            /* Catalogue unreachable — stay silent rather than break the page. */
        });
    }

    /**
     * Retire the pending marker the first time a tour is shown to this user.
     *
     * Guarded on the flag the layout sets, so a user replaying the tour from
     * the account menu does not POST on every replay. Fire-and-forget: failing
     * to record it only means the tour is offered once more.
     */
    function markSeen() {
        if (!window.mispOnboardingAutostart) {
            return;
        }
        window.mispOnboardingAutostart = false;
        fetch(base() + '/users/onboardingSeen', {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).catch(function () { /* offered again next login, no worse */ });
    }

    function stop(userInitiated) {
        run = null;
        writeState();
        destroyChrome();
        if (userInitiated && typeof showToast === 'function') {
            showToast(i18n('stopped'), 'secondary');
        }
    }

    function finish() {
        var wasRun = run;
        run = null;
        writeState();
        destroyChrome();
        if (wasRun && typeof showToast === 'function') {
            showToast(i18n('finished'), 'success');
        }
    }

    /* ----------------------------------------------------------------- */
    /* Launcher                                                           */
    /* ----------------------------------------------------------------- */

    function openLauncher() {
        loadCatalogue().then(function (data) {
            var host = document.getElementById('onboardingLauncher');
            if (host) {
                host.parentNode.removeChild(host);
            }
            host = el('div', 'modal fade');
            host.id = 'onboardingLauncher';
            host.tabIndex = -1;

            // One accordion card per section. The header carries the section's
            // identity (icon, name, description, its own colour); the body
            // holds the sub-sections, each independently runnable.
            var cards = data.sections.map(function (section, index) {
                var count = section.steps ? section.steps.length : 0;
                var groups = section.groups || [];
                var bodyId = 'onboarding-part-' + section.id;
                var open = index === 0;
                var meta = escapeHtml(i18n('stepCount', count));
                if (groups.length > 1) {
                    meta += ' &middot; '
                        + escapeHtml(i18n('partCount', groups.length));
                }

                // Replaying just "Classify it" is far more useful than
                // sitting through the whole incident walkthrough again.
                var parts = groups.length > 1
                    ? '<ul class="onboarding-part-list">'
                        + groups.map(function (group, i) {
                            return '<li><button type="button" '
                                + 'class="onboarding-part" '
                                + 'data-section="' + escapeHtml(section.id)
                                + '" data-group="' + escapeHtml(group.id) + '">'
                                + '<span class="onboarding-part-index">'
                                + (i + 1) + '</span>'
                                + '<span class="onboarding-part-label">'
                                + escapeHtml(group.title) + '</span>'
                                + '<span class="onboarding-part-count">'
                                + escapeHtml(i18n('stepCount', group.count))
                                + '</span>'
                                + '<i class="fas fa-play"></i>'
                                + '</button></li>';
                        }).join('')
                        + '</ul>'
                    : '';

                // The catalogue names a palette token; onboarding.css owns
                // the mapping and its fallback, so a colour value never
                // reaches this file. Sanitised anyway — it lands in a class.
                var accent = String(section.colour || 'primary')
                    .replace(/[^a-z0-9-]/gi, '');

                return ''
                    + '<section class="onboarding-acc-item onb-accent-'
                    + accent + (open ? ' is-open' : '') + '">'
                    + '<button type="button" class="onboarding-acc-head" '
                    + 'aria-expanded="' + (open ? 'true' : 'false') + '" '
                    + 'aria-controls="' + escapeHtml(bodyId) + '">'
                    + '<span class="onboarding-acc-icon"><i class="'
                    + escapeHtml(section.icon || 'fas fa-compass')
                    + '"></i></span>'
                    + '<span class="onboarding-acc-text">'
                    + '<span class="onboarding-acc-title">'
                    + escapeHtml(section.title) + '</span>'
                    + '<span class="onboarding-acc-summary">'
                    + escapeHtml(section.summary || '') + '</span>'
                    + '</span>'
                    + '<span class="onboarding-acc-meta">' + meta + '</span>'
                    + '<i class="fas fa-chevron-down '
                    + 'onboarding-acc-chevron"></i>'
                    + '</button>'
                    + '<div class="onboarding-acc-body" id="'
                    + escapeHtml(bodyId) + '">'
                    + '<div class="onboarding-acc-inner">'
                    + '<button type="button" class="onboarding-run-section" '
                    + 'data-section="' + escapeHtml(section.id) + '">'
                    + '<i class="fas fa-play"></i>'
                    + escapeHtml(i18n('startSection'))
                    + '</button>'
                    + parts
                    + '</div>'
                    + '</div>'
                    + '</section>';
            }).join('');

            var totalSteps = data.sections.reduce(function (n, s) {
                return n + (s.steps ? s.steps.length : 0);
            }, 0);

            // Laid out like the Add/Edit Event dialog: a tinted header band
            // with an eyebrow, an icon title and a faded glyph, the content in
            // a container-fluid, and the actions as a row inside the body
            // rather than a Bootstrap .modal-footer.
            host.innerHTML = ''
                + '<div class="modal-dialog modal-dialog-centered modal-lg">'
                + '<div class="modal-content onboarding-launcher">'
                + '<div class="onboarding-launcher-head">'
                + '<div>'
                + '<div class="onboarding-launcher-eyebrow">'
                + escapeHtml(i18n('tutorial')) + '</div>'
                + '<h4 class="onboarding-launcher-title">'
                + '<i class="fas fa-graduation-cap"></i>'
                + escapeHtml(i18n('launcherTitle')) + '</h4>'
                + '<p class="onboarding-launcher-lead">'
                + escapeHtml(i18n('launcherHint')) + '</p>'
                + '</div>'
                + '<span class="onboarding-launcher-glyph">'
                + '<i class="fas fa-graduation-cap"></i></span>'
                + '</div>'
                + '<div class="container-fluid px-4 py-4">'
                + '<div class="onboarding-acc">' + cards + '</div>'
                + '<div class="onboarding-launcher-foot">'
                + '<div class="onboarding-launcher-meta">'
                + escapeHtml(i18n('sectionCount', data.sections.length))
                + ' &middot; ' + escapeHtml(i18n('stepCount', totalSteps))
                + '</div>'
                + '<div class="d-flex gap-2">'
                + '<button type="button" class="btn btn-outline-secondary '
                + 'btn-sm" data-bs-dismiss="modal">'
                + '<i class="fas fa-times me-1"></i>'
                + escapeHtml(i18n('close')) + '</button>'
                + '<button type="button" class="btn btn-primary btn-sm" '
                + 'id="onboardingStartAll">'
                + '<i class="fas fa-play me-1"></i>'
                + escapeHtml(i18n('startAll')) + '</button>'
                + '</div>'
                + '</div>'
                + '</div>'
                + '</div></div>';

            document.body.appendChild(host);
            var modal = new bootstrap.Modal(host);

            // Hand-rolled accordion rather than Bootstrap's: the launcher is
            // built and destroyed on every open, and this avoids depending on
            // Collapse instances that would have to be disposed with it.
            var items = host.querySelectorAll('.onboarding-acc-item');
            items.forEach(function (item) {
                var head = item.querySelector('.onboarding-acc-head');
                head.addEventListener('click', function () {
                    var wasOpen = item.classList.contains('is-open');
                    items.forEach(function (other) {
                        other.classList.remove('is-open');
                        other.querySelector('.onboarding-acc-head')
                            .setAttribute('aria-expanded', 'false');
                    });
                    if (!wasOpen) {
                        item.classList.add('is-open');
                        head.setAttribute('aria-expanded', 'true');
                    }
                });
            });

            host.querySelectorAll('[data-section]').forEach(function (button) {
                button.addEventListener('click', function () {
                    var id = button.getAttribute('data-section');
                    var group = button.getAttribute('data-group');
                    modal.hide();
                    start([id], group || null);
                });
            });
            var startAll = host.querySelector('#onboardingStartAll');
            if (startAll) {
                startAll.addEventListener('click', function () {
                    modal.hide();
                    start(null);
                });
            }
            host.addEventListener('hidden.bs.modal', function () {
                if (host.parentNode) {
                    host.parentNode.removeChild(host);
                }
            });
            modal.show();
        }).catch(function () {
            if (typeof showToast === 'function') {
                showToast(i18n('unavailable'), 'danger');
            }
        });
    }

    /* ----------------------------------------------------------------- */
    /* Strings                                                            */
    /* ----------------------------------------------------------------- */

    /**
     * Translated chrome labels ride along with the catalogue. The English
     * fallbacks keep the engine usable if that request ever comes back thin.
     */
    function i18n(key, a, b) {
        var bundle = (catalogue && catalogue.strings) || {};
        var fallback = {
            next: 'Next',
            back: 'Back',
            finish: 'Finish',
            nextSection: 'Next section',
            skipSection: 'Skip section',
            skipAll: 'Skip tutorial',
            stepOf: 'Step %1 of %2',
            stepCount: '%1 steps',
            waitingForClick: 'Waiting for you…',
            waitingDefault: 'Continue when you are ready — the tutorial will '
                + 'pick up automatically.',
            tutorial: 'Interactive tutorial',
            launcherTitle: 'Choose where to start',
            launcherHint: 'Pick a section, or run the whole tour.',
            sectionCount: '%1 sections',
            startSection: 'Start this section',
            startAll: 'Start the full tour',
            close: 'Close',
            stopped: 'Tutorial closed. You can replay it from your account '
                + 'menu.',
            finished: 'Tutorial complete.',
            unavailable: 'The tutorial could not be loaded.'
        };
        var template = bundle[key] || fallback[key] || key;
        return String(template)
            .replace('%1', a === undefined ? '' : a)
            .replace('%2', b === undefined ? '' : b);
    }

    /* ----------------------------------------------------------------- */
    /* Boot                                                               */
    /* ----------------------------------------------------------------- */

    function boot() {
        document.querySelectorAll('.onboarding-launch').forEach(function (node) {
            node.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                openLauncher();
            });
        });

        var saved = readState();
        if (saved && saved.sections && saved.sections.length) {
            loadCatalogue().then(function () {
                run = saved;
                renderStep();
            }).catch(function () { /* keep the page usable */ });
            return;
        }

        // Fresh login: the layout sets this once, from a one-shot session flag.
        if (window.mispOnboardingAutostart) {
            start(null);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    window.MispOnboarding = {
        start: start,
        stop: stop,
        openLauncher: openLauncher,
        isActive: function () { return !!run; }
    };
}());
