/**
 * Value Intelligence page interactions (/values/view).
 *
 * Everything here works against markup already in the DOM. This pass has
 * no endpoint to filter against and nothing to write, so a type chip
 * narrows rows the page already holds, and a control that would write is
 * stopped before it can look like it did something.
 *
 * Scoped by <body data-controller="values">, which the layout already
 * emits, so nothing here reaches another page.
 */
(function () {
    'use strict';

    // Slug of the type chip currently pressed, or null for no filter.
    var typeFilter = null;

    function onValuePage() {
        return !!document.body
            && document.body.dataset.controller === 'values';
    }

    /**
     * Row visibility in the occurrence table has two independent inputs —
     * the type filter and the soft-deleted toggle — so it is computed in
     * one place rather than by two handlers racing on the same class.
     */
    function refreshOccurrences() {
        var panel = document.querySelector('[data-vp-occurrences]');
        if (!panel) {
            return;
        }
        var toggle = panel.querySelector('#vp-occ-deleted-toggle');
        var includeDeleted = !!(toggle && toggle.checked);
        var shown = 0;
        var eligible = 0;

        panel.querySelectorAll('tbody tr').forEach(function (row) {
            var deleted = row.classList.contains('vp-occ-deleted');
            var counts = includeDeleted || !deleted;
            var matches = !typeFilter
                || row.classList.contains('vp-occ-type-' + typeFilter);
            if (counts) {
                eligible++;
            }
            if (counts && matches) {
                shown++;
            }
            row.classList.toggle('d-none', !(counts && matches));
        });

        updateFilterNote(panel, shown, eligible);
    }

    /**
     * @param {Element} panel
     * @param {number} shown
     * @param {number} eligible Rows the filter chose from, which is not
     *                          the value's occurrence count: rows hidden
     *                          by ACL or by the soft-deleted toggle were
     *                          never candidates.
     */
    function updateFilterNote(panel, shown, eligible) {
        var note = panel.querySelector('[data-vp-filter-note]');
        var empty = panel.querySelector('[data-vp-filter-empty]');
        var table = panel.querySelector('[data-vp-occ-table]');
        var label = activeChipLabel();

        if (note) {
            note.classList.toggle('d-none', !typeFilter);
            setText(note, '[data-vp-filter-type]', label);
            setText(note, '[data-vp-filter-shown]', shown);
            setText(note, '[data-vp-filter-total]', eligible);
        }
        // Filtering to a type whose only rows are hidden is a real
        // answer, and an empty table with a live header does not say it.
        var blank = !!typeFilter && shown === 0;
        if (empty) {
            empty.classList.toggle('d-none', !blank);
            setText(empty, '[data-vp-filter-type]', label);
        }
        if (table) {
            table.classList.toggle('d-none', blank);
        }
    }

    function setText(root, selector, value) {
        var target = root.querySelector(selector);
        if (target) {
            target.textContent = value;
        }
    }

    function activeChipLabel() {
        var chip = document.querySelector('.vp-type-chip.active');
        return chip ? chip.dataset.vpType : '';
    }

    function toggleTypeFilter(chip) {
        var slug = chip.dataset.vpTypeSlug;
        typeFilter = typeFilter === slug ? null : slug;

        document.querySelectorAll('.vp-type-chip').forEach(function (el) {
            var pressed = el.dataset.vpTypeSlug === typeFilter;
            el.classList.toggle('active', pressed);
            el.setAttribute('aria-pressed', pressed ? 'true' : 'false');
        });

        // The table the chip filters lives in the Overview tab, so
        // filtering from anywhere else goes there rather than quietly
        // narrowing a table nobody is looking at.
        if (typeFilter && window.location.hash !== '#tab-general') {
            window.location.hash = '#tab-general';
        }
        refreshOccurrences();
    }

    /**
     * Which named threats the rail's card shows.
     *
     * Three views, and the card opens on the first: `top` is the eight
     * it is capped at, `all` is every one of them, and a kind is every
     * cluster of that kind. Picking a kind is the whole point of the
     * counts being pills rather than a sentence — *63 malware* that
     * cannot be looked at is a fact with nowhere to go.
     *
     * Everything is already in the fragment, so this hides rather than
     * fetches: the fold costs one class and the card's own stylesheet
     * caps the list's height once it is no longer showing the opening
     * cut, because filtering to 63 rows would otherwise run the rail
     * past the tables beside it.
     *
     * @param {Element} card A [data-vp-threats]
     * @param {string} view `top`, `all`, or a kind
     */
    function filterThreats(card, view) {
        if (!card) {
            return;
        }
        card.dataset.vpThreatView = view;
        card.classList.toggle(
            'vp-threats-filtered',
            view !== 'top' && view !== 'all'
        );
        card.querySelectorAll('[data-vp-threat-filter]')
            .forEach(function (pill) {
                // `all` is the expanded form of `All`, so the pill the
                // reader pressed to get there stays the lit one.
                var on = pill.dataset.vpThreatFilter === view
                    || (view === 'all'
                        && pill.dataset.vpThreatFilter === 'top');
                pill.classList.toggle('active', on);
                pill.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
        card.querySelectorAll('.vp-threat').forEach(function (row) {
            var show;
            if (view === 'top') {
                show = !row.classList.contains('vp-threat-folded');
            } else if (view === 'all') {
                show = true;
            } else {
                show = row.dataset.vpThreatKind === view;
            }
            row.classList.toggle('vp-threat-off', !show);
        });
        var more = card.querySelector('[data-vp-threat-expand]');
        if (more) {
            more.classList.toggle('d-none', view !== 'top');
        }
    }

    /**
     * Put a named-threat hover card where the viewport can hold it.
     *
     * The card is `position: fixed` for one reason: filtering the list
     * to a kind makes it scroll, and an `overflow` ancestor clips
     * absolutely-positioned descendants, so the card was whole until
     * anyone used a pill and cut off afterwards. Fixed takes it out of
     * that box, at the price of needing coordinates — which is this.
     *
     * Opens to the left of its trigger, because the card lives in a
     * 340px rail against the page's right edge. Clamped to the
     * viewport at both ends, so a row near the bottom of a long
     * filtered list still shows a whole card rather than one running
     * off the fold.
     *
     * @param {Element} wrap A .vp-claim-tipwrap inside a .vp-threat
     */
    function placeThreatTip(wrap) {
        var tip = wrap.querySelector('.vp-claim-tip');
        if (!tip) {
            return;
        }
        /*
         * Only the scrolling views need this, and only there is the
         * card `fixed`. In the opening view it is `absolute` against
         * this wrapper and the stylesheet has already placed it —
         * writing viewport coordinates onto it would move it away
         * from the row it belongs to.
         */
        var card = wrap.closest('[data-vp-threats]');
        if (!card || card.dataset.vpThreatView === 'top') {
            tip.style.removeProperty('top');
            tip.style.removeProperty('right');
            return;
        }
        var at = wrap.getBoundingClientRect();
        tip.style.right = (window.innerWidth - at.left + 9) + 'px';
        /*
         * Measured while still hidden — `visibility` keeps layout, so
         * the height is real before the card is shown, and reading it
         * after would be a frame late.
         */
        var height = tip.offsetHeight;
        var margin = 8;
        var top = at.top - 10;
        if (top + height > window.innerHeight - margin) {
            top = window.innerHeight - height - margin;
        }
        tip.style.top = Math.max(margin, top) + 'px';
    }

    /**
     * Bootstrap only takes the pointer away from a disabled control, so
     * its title — the whole explanation of why it is disabled — cannot be
     * read. The stylesheet gives the pointer back; this stops the
     * activation that comes with it, for the mouse and for the keyboard,
     * and states the condition for assistive technology.
     *
     * @param {Element|Document} root
     */
    function markDisabled(root) {
        root.querySelectorAll('a.disabled').forEach(function (link) {
            link.setAttribute('aria-disabled', 'true');
        });
    }

    /* ==============================================================
     * Faceted lists
     * --------------------------------------------------------------
     * One shared control for every panel that narrows a list by
     * counted facets and pages what survives — the Occurrences rail
     * and the Relationships co-occurrence pane both are one.
     *
     * A panel opts in with `data-vp-list` on the region that owns the
     * rows, and the markup carries the rest:
     *
     *   [data-vp-list]              the region
     *     [data-vp-list-rows]         the row host; rows are its
     *                                 tbody > tr, or [data-vp-list-row]
     *     tr[data-vp-facet]           space-separated `key:value`
     *                                 tokens; a row may carry several
     *                                 values for one key
     *     tr[data-vp-hidden]         a token that keeps the row out
     *                                 until something reveals it
     *     input[data-vp-facet-key]   a facet checkbox
     *     input[data-vp-reveal]      reveals rows hidden by that token
     *     tr[data-vp-time]           the row's own `YmdHi` digits
     *     [data-vp-filter-from|-to]  period bounds against that time
     *     tr[data-vp-times]          `key:YmdHi` pairs, for a panel that
     *                                cuts on more than one date
     *     [data-vp-range-from|-to]   bounds against one of those keys,
     *                                named by the attribute's value
     *                                (a panel may show one key at a
     *                                time — see `switchTimeScope`)
     *     [data-vp-pager]            page control, data-vp-page-size
     *     [data-vp-list-empty]       shown when a filter empties the list
     *
     * Within one key the checked values are alternatives; across keys
     * they all have to hold. That is what a reader means by ticking
     * `ip-dst` and `ip-src` under Type and `Org A` under Organisation.
     *
     * Soft-deleted rows are not a facet value: they are excluded
     * until revealed, because filtering *to* deleted rows and
     * including them alongside the rest are different questions.
     *
     * Lists nest. A `[data-vp-list]` inside another owns its rows, its
     * pager, its range and its narrowing controls, and the outer one
     * leaves them alone — the Relationships tab's object-siblings
     * section pages and narrows separately from the ranked table under
     * it. Reading a control therefore goes through `ownNodes` for the
     * same reason paging does: an unscoped query would let the ranked
     * table's facet bar filter rows it does not describe, and its
     * `Reset` clear ticks the reader never made there.
     * ============================================================== */

    // Current page per list, keyed by the element so several lists on
    // one page keep their own place.
    var listPages = new WeakMap();

    /**
     * The nodes a list owns, which is not the same as the nodes inside
     * it. A panel may hold a second `[data-vp-list]` — the
     * Relationships tab's object-siblings section pages independently
     * of the ranked table below it — and an unscoped query would let
     * the outer control page the inner section's rows and print a
     * range that belongs to neither.
     *
     * @param {Element} list
     * @param {string} selector
     * @return {Array<Element>}
     */
    function ownNodes(list, selector) {
        return ownedBy(list, list.querySelectorAll(selector));
    }

    /**
     * @param {Element} list
     * @param {NodeList} nodes
     * @return {Array<Element>}
     */
    function ownedBy(list, nodes) {
        return Array.prototype.slice.call(nodes).filter(function (node) {
            return node.closest('[data-vp-list]') === list;
        });
    }

    /**
     * @param {Element} list
     * @param {string} selector
     * @return {?Element}
     */
    function ownNode(list, selector) {
        return ownNodes(list, selector)[0] || null;
    }

    /**
     * @param {Element} list
     * @param {string} selector
     * @param {number|string} value
     */
    function setOwnText(list, selector, value) {
        var target = ownNode(list, selector);
        if (target) {
            target.textContent = value;
        }
    }

    /**
     * @param {Element} list
     * @return {Array<Element>}
     */
    function listRows(list) {
        var host = ownNode(list, '[data-vp-list-rows]') || list;
        var explicit = ownedBy(
            list,
            host.querySelectorAll('[data-vp-list-row]')
        );
        if (explicit.length) {
            return explicit;
        }
        return ownedBy(list, host.querySelectorAll('tbody tr'));
    }

    /**
     * Whether a control narrows the roll-up that is on screen.
     *
     * The co-occurrence panel says this in words the moment the reader
     * switches — *narrowing applies to the value roll-up* — and says it
     * in markup by keeping its whole narrowing block inside the value
     * pane's `[data-vp-group-only]`. It has to say it in the filter as
     * well: an event row carries no `type:` token of its own, so a
     * facet left ticked across the switch would not narrow the event
     * roll-up but empty it, under a note promising it did not apply.
     *
     * The fold agrees — it narrows the value roll-up and rolls events
     * and objects up over the whole neighbourhood — so this is the
     * client saying the same thing about the same rows.
     *
     * A control outside any such wrapper, which is every control on
     * every other panel, always applies.
     *
     * @param {Element} list
     * @param {Element} control
     * @return {boolean}
     */
    function controlNarrows(list, control) {
        var group = list.dataset.vpGroupActive;
        if (!group) {
            return true;
        }
        var scope = control.closest('[data-vp-group-only]');
        return !scope || scope.dataset.vpGroupOnly === group;
    }

    /**
     * Checked facets, grouped by key. A key absent from the result
     * places no constraint — an unticked group is not an empty one.
     *
     * @param {Element} list
     * @return {Object}
     */
    function activeFacets(list) {
        var active = {};
        ownNodes(list, 'input[data-vp-facet-key]').forEach(function (box) {
            if (!box.checked || !controlNarrows(list, box)) {
                return;
            }
            var key = box.dataset.vpFacetKey;
            if (!active[key]) {
                active[key] = [];
            }
            active[key].push(box.value);
        });
        return active;
    }

    /**
     * The filter row's constraints, which are conjunctive where the
     * facet groups are disjunctive.
     *
     * A select and a facet group can name the same key — `Any type`
     * beside a counted `Type` dropdown is exactly the pane the graft
     * asks for. Ticking `domain` and `sha256` in the dropdown means
     * *either*; picking `domain` in the select on top of it means
     * *and also*. Merging the two into one bucket would turn the second
     * control into a third value of the first, which is not what
     * anybody reading the row means by it.
     *
     * @param {Element} list
     * @return {Object} key => token, one per set control
     */
    function activeSelects(list) {
        var active = {};
        list.querySelectorAll('select[data-vp-filter-key]')
            .forEach(function (select) {
                if (select.value === ''
                    || !controlNarrows(list, select)
                ) {
                    return;
                }
                active[select.dataset.vpFilterKey] = select.value;
            });
        return active;
    }

    /**
     * The free-text box, matched against the row's own `data-vp-text`
     * rather than its rendered cells: a cell can carry a badge, a bar
     * and a truncation, and searching what the reader sees would then
     * mean searching an ellipsis.
     *
     * @param {Element} list
     * @return {string}
     */
    function activeText(list) {
        var input = list.querySelector('[data-vp-filter-text]');
        if (!input || !controlNarrows(list, input)) {
            return '';
        }
        return input.value.trim().toLowerCase();
    }

    /**
     * The numeric thresholds — `Shared events ≥`, `Similarity ≥`. A
     * threshold at its floor places no constraint and is not counted
     * as a set filter, so the panel does not claim a filter is applied
     * when the control is where it started.
     *
     * @param {Element} list
     * @return {Object} key => minimum
     */
    function activeMinimums(list) {
        var active = {};
        list.querySelectorAll('[data-vp-filter-min]').forEach(function (input) {
            var value = parseFloat(input.value);
            var floor = parseFloat(input.min);
            if (isNaN(value) || (!isNaN(floor) && value <= floor)
                || !controlNarrows(list, input)
            ) {
                return;
            }
            active[input.dataset.vpFilterMin] = value;
        });
        return active;
    }

    /**
     * The period bounds, as the same `YmdHi` integer the rows carry.
     *
     * Digits of the printed wall clock rather than epochs: a row's time
     * is rendered server-side, so comparing epochs would hand a reader
     * in another timezone a different set of rows for the period they
     * picked than the times on those rows say it holds.
     *
     * @param {Element} list
     * @return {{from: number|null, to: number|null}}
     */
    function activePeriod(list) {
        return {
            from: periodBound(list, '[data-vp-filter-from]', '0000'),
            to: periodBound(list, '[data-vp-filter-to]', '2359')
        };
    }

    /**
     * The same thing again, but named, for a panel that filters on more
     * than one date at once — the Occurrences rail cuts on when an
     * attribute was last modified *and* on when its event was published,
     * and those are two independent questions about one row.
     *
     * Named rather than a second unnamed pair because there is no limit
     * on how many dates a row can carry, and separate from `activePeriod`
     * rather than a generalisation of it because the unnamed period has a
     * caller already (`value_history`'s audit rail) whose behaviour must
     * not change to add this.
     *
     * @param {Element} list
     * @return {Object} key => {from, to}
     */
    function activeRanges(list) {
        var active = {};
        var read = function (selector, edge, fill) {
            list.querySelectorAll(selector).forEach(function (input) {
                var key = input.dataset[
                    edge === 'from' ? 'vpRangeFrom' : 'vpRangeTo'
                ];
                if (!key) {
                    return;
                }
                var at = boundDigits(input.value, fill);
                if (at === null) {
                    return;
                }
                if (!active[key]) {
                    active[key] = {from: null, to: null};
                }
                active[key][edge] = at;
            });
        };
        read('[data-vp-range-from]', 'from', '0000');
        read('[data-vp-range-to]', 'to', '2359');
        return active;
    }

    /**
     * @param {Element} list
     * @param {string} selector
     * @param {string} fill Clock digits for a bound given as a date
     * @return {number|null}
     */
    function periodBound(list, selector, fill) {
        var input = list.querySelector(selector);
        return input ? boundDigits(input.value, fill) : null;
    }

    /**
     * One date or datetime control's value as the `YmdHi` integer the
     * rows carry, or null when it places no bound. A `type="date"` input
     * gives eight digits and is filled out to the start or end of that
     * day, so a one-day range holds the whole day.
     *
     * @param {string} value
     * @param {string} fill Clock digits for a bound given as a date
     * @return {number|null}
     */
    function boundDigits(value, fill) {
        if (value === '' || value === undefined || value === null) {
            return null;
        }
        var digits = String(value).replace(/\D/g, '');
        if (digits.length < 8) {
            return null;
        }
        if (digits.length < 12) {
            digits = digits.slice(0, 8) + fill;
        }
        return parseInt(digits.slice(0, 12), 10);
    }

    /**
     * A row carrying no time is dropped once a bound is set, for the
     * reason a thresholded row without a number is: the control is
     * asking something that row cannot answer, and keeping it would
     * make the period look like it did nothing.
     *
     * @param {Element} row
     * @param {Object} period
     * @return {boolean}
     */
    function rowMatchesPeriod(row, period) {
        if (period.from === null && period.to === null) {
            return true;
        }
        var at = parseInt(row.dataset.vpTime || '', 10);
        if (isNaN(at)) {
            return false;
        }
        return (period.from === null || at >= period.from)
            && (period.to === null || at <= period.to);
    }

    /**
     * @param {Element} row
     * @param {string} key
     * @return {number|null}
     */
    function rowNumber(row, key) {
        var match = (row.dataset.vpNum || '')
            .match(new RegExp('(?:^|\\s)' + key + ':(-?\\d+(?:\\.\\d+)?)'));
        return match ? parseFloat(match[1]) : null;
    }

    /**
     * @param {Element} list
     * @return {Array<string>} Tokens whose hidden rows are revealed.
     */
    function revealedTokens(list) {
        var tokens = [];
        list.querySelectorAll('input[data-vp-reveal]').forEach(function (box) {
            if (box.checked) {
                tokens.push(box.dataset.vpReveal);
            }
        });
        return tokens;
    }

    /**
     * @param {Element} row
     * @param {Object} active
     * @return {boolean}
     */
    function rowMatches(row, active) {
        var tokens = (row.dataset.vpFacet || '').split(/\s+/);
        return Object.keys(active).every(function (key) {
            return active[key].some(function (value) {
                return tokens.indexOf(key + ':' + value) !== -1;
            });
        });
    }

    /**
     * The one place a faceted list's row visibility is decided, so the
     * facets, the reveal switches and the page control cannot each
     * hold a different opinion about which rows are showing.
     *
     * @param {Element} list
     */
    function refreshList(list) {
        var active = activeFacets(list);
        var selects = activeSelects(list);
        var minimums = activeMinimums(list);
        var text = activeText(list);
        var period = activePeriod(list);
        var ranges = activeRanges(list);
        var revealed = revealedTokens(list);
        // A roll-up the reader is not looking at is excluded before
        // anything else: its rows are a different kind of row, and
        // paging them alongside the visible ones would give the page
        // control a count nothing on screen agrees with.
        var group = list.dataset.vpGroupActive || null;
        var filtered = [];

        listRows(list).forEach(function (row) {
            var hidden = row.dataset.vpHidden;
            var keep = !(!!hidden && revealed.indexOf(hidden) === -1);
            if (keep && group && row.dataset.vpGroup) {
                keep = row.dataset.vpGroup === group;
            }
            if (keep) {
                keep = rowMatches(row, active)
                    && rowMatchesSelects(row, selects)
                    && rowMatchesMinimums(row, minimums)
                    && rowMatchesPeriod(row, period)
                    && rowMatchesRanges(row, ranges)
                    && rowMatchesText(row, text);
            }
            if (keep) {
                filtered.push(row);
            } else {
                row.classList.add('d-none');
            }
        });

        var activeCount = Object.keys(active).reduce(function (sum, key) {
            return sum + active[key].length;
        }, 0)
            + Object.keys(selects).length
            + Object.keys(minimums).length
            + (period.from === null ? 0 : 1)
            + (period.to === null ? 0 : 1)
            + Object.keys(ranges).reduce(function (sum, key) {
                return sum + (ranges[key].from === null ? 0 : 1)
                    + (ranges[key].to === null ? 0 : 1);
            }, 0)
            + (text === '' ? 0 : 1);

        sortRows(list, filtered);
        // The History tab pages inside each section instead of over
        // the union of them; everything before this point is shared.
        if (list.hasAttribute('data-vp-audit')) {
            paginateAuditSections(list, filtered, activeCount);
            // Both read the period rather than the filtered set, so
            // they run here and not inside the pager: the brush shows
            // where the period is and the rail counts what is in it,
            // whatever else is ticked.
            retallyAuditFacets(list, period);
            paintAuditBrush(list);
        } else {
            paginate(list, filtered);
        }
        // A span strip draws every row the section holds, not the page,
        // so it follows the narrowing rather than the pager — and it
        // runs for any list that has one rather than for a named panel.
        paintSpanStrips(list, filtered);
        updateListNotes(list, filtered.length, activeCount);
    }

    /**
     * Dim the spans of rows a filter has removed.
     *
     * **Dimmed and not removed**, which is the strip's whole claim on
     * the panel: the axis is the period the *section* covers, so a
     * narrowing that drops the oldest resolution must not shorten the
     * axis under the reader — the gap it left is the reading. A redrawn
     * strip would rescale, and the dormant-then-reactivated shape §25.1
     * is about would silently become continuously-live.
     *
     * The lane count goes to what survived, with the total kept beneath
     * it, because a lane still showing 46 over three visible spans is
     * the one number on the panel nothing on screen agrees with.
     *
     * @param {Element} list
     * @param {Array<Element>} filtered Rows that survived
     */
    function paintSpanStrips(list, filtered) {
        var strips = ownNodes(list, '[data-vp-span-strip]');
        if (!strips.length) {
            return;
        }
        var kept = {};
        filtered.forEach(function (row) {
            if (row.dataset.vpSpanKey) {
                kept[row.dataset.vpSpanKey] = true;
            }
        });
        strips.forEach(function (strip) {
            var lanes = {};
            strip.querySelectorAll('[data-vp-span-row]').forEach(
                function (span) {
                    var on = !!kept[span.dataset.vpSpanRow];
                    span.classList.toggle('vp-lane-span-off', !on);
                    var lane = span.closest('[data-vp-span-lane]');
                    if (!lane) {
                        return;
                    }
                    var key = lane.dataset.vpSpanLane;
                    if (lanes[key] === undefined) {
                        lanes[key] = 0;
                    }
                    if (on) {
                        lanes[key]++;
                    }
                }
            );
            Object.keys(lanes).forEach(function (key) {
                var cell = strip.querySelector(
                    '[data-vp-span-count="' + key + '"]'
                );
                if (!cell) {
                    return;
                }
                var total = parseInt(cell.dataset.vpSpanTotal || '', 10);
                cell.textContent = String(lanes[key]);
                var note = cell.parentNode
                    ? cell.parentNode.querySelector('[data-vp-span-of]')
                    : null;
                if (note) {
                    note.hidden = isNaN(total) || lanes[key] === total;
                }
            });
        });
    }

    /**
     * @param {Element} row
     * @param {Object} selects
     * @return {boolean}
     */
    function rowMatchesSelects(row, selects) {
        var tokens = (row.dataset.vpFacet || '').split(/\s+/);
        return Object.keys(selects).every(function (key) {
            return tokens.indexOf(key + ':' + selects[key]) !== -1;
        });
    }

    /**
     * A row with no number for a key it is being thresholded on is
     * dropped rather than kept: the control is asking a question that
     * row cannot answer, and keeping it would make the threshold look
     * like it did nothing.
     *
     * @param {Element} row
     * @param {Object} minimums
     * @return {boolean}
     */
    function rowMatchesMinimums(row, minimums) {
        return Object.keys(minimums).every(function (key) {
            var value = rowNumber(row, key);
            return value !== null && value >= minimums[key];
        });
    }

    /**
     * A row against every named date range that is set.
     *
     * A row carrying no date under a key the reader has cut on is
     * dropped, not kept — the same call `rowMatchesPeriod` makes, and for
     * the same reason: "I do not know when this happened" is not evidence
     * that it happened inside the window. How many rows that is belongs
     * beside the control, which is why the rail counts them.
     *
     * @param {Element} row
     * @param {Object} ranges key => {from, to}
     * @return {boolean}
     */
    function rowMatchesRanges(row, ranges) {
        return Object.keys(ranges).every(function (key) {
            var range = ranges[key];
            if (range.from === null && range.to === null) {
                return true;
            }
            return rowOverlaps(row, key, range.from, range.to);
        });
    }

    /**
     * Whether a row's time under `key` touches a range. A row may carry
     * a window rather than a moment — a resolution was current from its
     * first sighting to its last — and a window matches when any part
     * of it falls inside.
     *
     * @param {Element} row
     * @param {string} key
     * @param {number|null} from `YmdHi`
     * @param {number|null} to `YmdHi`
     * @return {boolean}
     */
    function rowOverlaps(row, key, from, to) {
        var span = rowTime(row, key);
        if (span === null) {
            return false;
        }
        return (from === null || span.to >= from)
            && (to === null || span.from <= to);
    }

    /**
     * @param {Element} row
     * @param {string} key
     * @return {{from: number, to: number}|null} `YmdHi`, equal for a
     *     row that carries a moment
     */
    function rowTime(row, key) {
        var match = (row.dataset.vpTimes || '').match(new RegExp(
            '(?:^|\\s)' + key + ':(\\d{12})(?:-(\\d{12}))?'
        ));
        if (!match) {
            return null;
        }
        var from = parseInt(match[1], 10);
        return {
            from: from,
            to: match[2] ? parseInt(match[2], 10) : from
        };
    }

    /**
     * @param {Element} row
     * @param {string} needle
     * @return {boolean}
     */
    function rowMatchesText(row, needle) {
        if (needle === '') {
            return true;
        }
        return (row.dataset.vpText || '').indexOf(needle) !== -1;
    }

    /**
     * Reorder the surviving rows, descending, on whichever number the
     * rank select names.
     *
     * Done in the DOM rather than by re-rendering, because the rows are
     * already here: this pass pages over what the fragment carries, and
     * a sort that re-queried would be the one control on the tab that
     * did. Rows are re-appended to their own host, so the three
     * roll-ups cannot end up interleaved.
     *
     * @param {Element} list
     * @param {Array<Element>} filtered
     */
    function sortRows(list, filtered) {
        if (filtered.length < 2) {
            return;
        }
        /*
         * A column heading the reader has clicked wins over the panel's
         * own select, and there is no panel with both.
         *
         * `vp-sorted-col` on the list, not `vp-sort-col`: the headings
         * carry the latter, and writing the state under the same name
         * would put it on the list element too — where a
         * `[data-vp-sort-col="x"]` lookup finds the container before the
         * button it was looking for.
         */
        if (list.dataset.vpSortedCol) {
            sortByColumn(list, filtered, list.dataset.vpSortedCol,
                list.dataset.vpSortedDir === 'desc' ? -1 : 1);
            return;
        }
        /*
         * No column sort. A panel that also carries a select is asking
         * for that select's order — the Relationships pane offers both,
         * and reading the columns first would leave `Most recent first`
         * set and doing nothing the moment its headings became
         * clickable.
         */
        var select = ownNode(list, '[data-vp-sort]');
        /*
         * No select either, but a table that offers column sorting has
         * already had its rows moved by an earlier click — reordering is
         * destructive, so "unsorted" has to be restored rather than
         * merely stopped. Each row carries its server position for
         * exactly this.
         */
        if (!select) {
            if (ownNode(list, '[data-vp-sort-col]')) {
                sortByColumn(list, filtered, 'default', 1);
            }
            return;
        }
        var key = controlValue(select);
        var ordered = filtered.slice().sort(function (a, b) {
            var diff = (rowNumber(b, key) || 0) - (rowNumber(a, key) || 0);
            if (diff !== 0) {
                return diff;
            }
            /*
             * Ties fall back to the order the model sent, which makes
             * this a total order rather than merely a stable one. Once
             * the headings sort, that is what lets the third click put
             * the table back: most of the ranked table shares one
             * weight, and a stable sort over equal keys would keep
             * whatever order the previous click left behind and call it
             * the default. Rows with no position tie as they did.
             */
            var x = a.dataset.vpSortDefault || '';
            var y = b.dataset.vpSortDefault || '';
            return x === y ? 0 : (x < y ? -1 : 1);
        });
        ordered.forEach(function (row) {
            if (row.parentNode) {
                row.parentNode.appendChild(row);
            }
        });
        // `filtered` is what paginate() slices, so it has to end up in
        // the order the reader is about to see rather than the order
        // the server happened to render.
        filtered.length = 0;
        Array.prototype.push.apply(filtered, ordered);
    }

    /**
     * Order rows by the column the reader clicked.
     *
     * Compares `data-vp-sort-<column>`, which the template builds to sort
     * lexicographically — zero-padded numbers, `YmdHi` dates, lowercased
     * text — so one comparison serves every column and the script needs
     * no knowledge of what any of them holds.
     *
     * **An empty token sorts last in both directions.** It means the row
     * has no value for that column, and "no last-seen date" is not
     * earlier than every date; putting it at the top of an ascending sort
     * would bury the rows the reader asked to see.
     *
     * @param {Element} list
     * @param {Array<Element>} filtered
     * @param {string} column Column key, or `default` for server order
     * @param {number} sign 1 ascending, -1 descending
     */
    /*
     * The three containers on this page that own a sortable table. The
     * occurrence list is faceted and paginated, the sightings list is
     * driven by the chart's brush, and the standing ledger is neither,
     * but all three cycle their headings the same way — so every lookup
     * that has to find a heading's own container knows all three.
     */
    var SORT_LIST_SELECTOR =
        '[data-vp-list], [data-vp-sight-list], [data-vp-a-ledger]';

    function sortByColumn(list, filtered, column, sign) {
        var key = 'vpSort' + column.replace(
            /-([a-z])/g,
            function (m, c) { return c.toUpperCase(); }
        ).replace(/^([a-z])/, function (m, c) { return c.toUpperCase(); });
        var ordered = filtered.slice().sort(function (a, b) {
            var x = a.dataset[key] || '';
            var y = b.dataset[key] || '';
            if (x === y) {
                return 0;
            }
            if (x === '') {
                return 1;
            }
            if (y === '') {
                return -1;
            }
            return x < y ? -sign : sign;
        });
        ordered.forEach(function (row) {
            if (row.parentNode) {
                row.parentNode.appendChild(row);
            }
        });
        filtered.length = 0;
        Array.prototype.push.apply(filtered, ordered);
    }

    /**
     * Reorder the standing panel's ledger.
     *
     * No facets and no pages — the panel is bounded by the number of
     * organisations on the instance — so this is `sortByColumn` and
     * nothing else. Its rows are `display: contents` wrappers, so
     * moving one moves the five cells it owns and the grid re-flows
     * them; the header cells are never moved, and `appendChild` puts
     * every row after them.
     *
     * @param {Element} list A [data-vp-a-ledger]
     */
    function sortLedger(list) {
        var rows = Array.prototype.slice.call(
            list.querySelectorAll('.vpa-row')
        );
        if (rows.length < 2) {
            return;
        }
        sortByColumn(
            list,
            rows,
            list.dataset.vpSortedCol || 'default',
            list.dataset.vpSortedDir === 'desc' ? -1 : 1
        );
    }

    /**
     * Cycle one column heading: ascending, descending, then back to the
     * order the server sent.
     *
     * Three states rather than the two MISP's paginated headings offer,
     * because this table's default order is itself meaningful — most
     * recently modified first — and `Attribute.timestamp` is not one of
     * the twelve columns, so without a way back the reader could not
     * return to it.
     *
     * @param {Element} button A [data-vp-sort-col]
     */
    function toggleColumnSort(button) {
        var list = button.closest(SORT_LIST_SELECTOR);
        if (!list) {
            return;
        }
        var column = button.dataset.vpSortCol;
        if (list.dataset.vpSortedCol !== column) {
            list.dataset.vpSortedCol = column;
            list.dataset.vpSortedDir = 'asc';
        } else if (list.dataset.vpSortedDir === 'asc') {
            list.dataset.vpSortedDir = 'desc';
        } else {
            delete list.dataset.vpSortedCol;
            delete list.dataset.vpSortedDir;
        }
        markSortedColumn(list);
        /*
         * The standing ledger has neither facets nor pages, so there is
         * nothing to refresh around the reorder.
         */
        if (list.hasAttribute('data-vp-a-ledger')) {
            sortLedger(list);
            return;
        }
        /*
         * The sightings list is not a faceted list: it pages off `load
         * the rest` rather than a page control, and its rows are chosen
         * by the chart's brush. The state above and the comparison below
         * it are the same; only who redraws differs.
         *
         * Nothing to reset there, either — unexpanded it shows the first
         * ten of whatever order is current, which after a reorder is
         * exactly what the reader asked for.
         */
        if (list.hasAttribute('data-vp-sight-list')) {
            refreshSightList();
            return;
        }
        // A reorder does not change how many rows there are, but page
        // three of a new order is not the rows the reader was looking at.
        listPages.set(list, 1);
        refreshList(list);
    }

    /**
     * `aria-sort` on the sorted heading and nowhere else — the attribute
     * a screen reader announces, and the hook the caret styling keys off,
     * so there is one source of truth for which column is ordered.
     *
     * @param {Element} list
     */
    function markSortedColumn(list) {
        var column = list.dataset.vpSortedCol || null;
        var direction = list.dataset.vpSortedDir === 'desc'
            ? 'descending'
            : 'ascending';
        /*
         * Scoped: the sibling section's headings belong to its own list,
         * and the ranked table clearing them would take the caret off a
         * column the reader had just sorted.
         *
         * Scoped against `SORT_LIST_SELECTOR` rather than through
         * `ownNodes`, which tests `closest('[data-vp-list]')` only. The
         * sightings list carries `data-vp-sight-list` and no
         * `data-vp-list`, so every one of its headings failed that test
         * and its caret never lit however the rows were ordered.
         */
        Array.prototype.slice.call(
            list.querySelectorAll('[data-vp-sort-col]')
        ).filter(function (button) {
            return button.closest(SORT_LIST_SELECTOR) === list;
        }).forEach(function (button) {
            // A `th` in the two tables; in the ledger, the grid's own
            // header cell, which has no table row to hang it on.
            var cell = button.closest('th') || button.parentElement;
            if (!cell) {
                return;
            }
            if (button.dataset.vpSortCol === column) {
                cell.setAttribute('aria-sort', direction);
            } else {
                cell.removeAttribute('aria-sort');
            }
        });
    }

    /* ==================================================================
     * The occurrence rail's time brushes
     * ------------------------------------------------------------------
     * Two small brushable strips — one per date the rail cuts on —
     * sharing the brush primitive with the History chart and the
     * Sightings navigator. What they do not share is a canvas: these are
     * CSS bars a third the height of History's chart, because they sit
     * in a `col-lg-3` rail beside eight other facet groups.
     *
     * The gesture writes the two date inputs and lets their own `change`
     * do the filtering, so there is one filter path whether the reader
     * brushed or typed — the same decision the History chart made, for
     * the same reason.
     *
     * Bounds are applied on `settle` rather than on every pointer move.
     * History repaints its own chart as the drag goes; here a move would
     * re-filter and repage up to three hundred rows, sixty times a
     * second. The window still paints live; only the filter waits for
     * the pointer to come up.
     * ================================================================== */

    // Pending selection per strip while a drag is in flight.
    var timeBrushDrag = new WeakMap();

    // The period a row-counting strip is set to, as `[from, to]` labels.
    var timeBrushPeriod = new WeakMap();

    /**
     * @param {Element|Document} root
     */
    function initTimeBrushes(root) {
        (root || document).querySelectorAll('[data-vp-timebrush]')
            .forEach(initTimeBrush);
    }

    /**
     * @param {Element} strip A [data-vp-timebrush]
     * @return {Array<Element>} Its bars, in order
     */
    function timeBrushBars(strip) {
        return Array.prototype.slice.call(
            strip.querySelectorAll('[data-vp-bucket-from]')
        );
    }

    /**
     * Wire one strip. Drag picks a range, click clears it.
     *
     * @param {Element} strip A [data-vp-timebrush]
     */
    function initTimeBrush(strip) {
        if (strip.dataset.vpTimebrushReady) {
            return;
        }
        strip.dataset.vpTimebrushReady = '1';
        var key = strip.dataset.vpTimebrush;

        window.MispBrush.attach(strip.querySelector('[data-misp-brush]'), {
            count: function () {
                return timeBrushBars(strip).length;
            },
            range: function (from, to) {
                timeBrushDrag.set(strip, { from: from, to: to });
                window.MispBrush.paint(
                    strip,
                    { from: from, to: to },
                    timeBrushBars(strip).length
                );
                captionBucket(strip, from, to);
            },
            settle: function () {
                var bounds = timeBrushDrag.get(strip);
                if (bounds) {
                    writeTimeBrush(strip, key, bounds.from, bounds.to);
                }
                timeBrushDrag.delete(strip);
            },
            clear: function () {
                timeBrushDrag.delete(strip);
                clearTimeBrush(strip, key);
            },
        });

        /*
         * A three-pixel bar is not self-describing, and the brush layer
         * covers the bars so their own `title` never reaches the reader.
         * The caption under the inputs names whatever is under the
         * pointer instead, and goes back to stating the grain on the way
         * out.
         */
        strip.addEventListener('pointermove', function (event) {
            if (timeBrushDrag.has(strip)) {
                lightBar(strip, null);
                return;
            }
            var bars = timeBrushBars(strip);
            if (!bars.length) {
                return;
            }
            var box = strip.getBoundingClientRect();
            var at = Math.floor(
                ((event.clientX - box.left) / box.width) * bars.length
            );
            at = Math.max(0, Math.min(bars.length - 1, at));
            lightBar(strip, bars[at]);
            var caption = timeBrushCaption(strip);
            if (caption && bars[at].dataset.vpTip) {
                caption.textContent = bars[at].dataset.vpTip;
            } else {
                captionBucket(strip, at, at);
            }
        });

        strip.addEventListener('pointerleave', function () {
            lightBar(strip, null);
            if (!timeBrushDrag.has(strip)) {
                captionDefault(strip);
            }
        });
    }

    /**
     * Mark the bar the caption is naming, so the two can be matched.
     *
     * @param {Element} strip
     * @param {Element|null} bar
     */
    function lightBar(strip, bar) {
        strip.querySelectorAll('.vp-spark-bar-lit').forEach(function (lit) {
            if (lit !== bar) {
                lit.classList.remove('vp-spark-bar-lit');
            }
        });
        if (bar) {
            bar.classList.add('vp-spark-bar-lit');
        }
    }

    /**
     * @param {Element} strip
     * @return {Element|null} The strip's caption
     */
    function timeBrushCaption(strip) {
        var list = strip.closest('[data-vp-list]') || document;
        return list.querySelector(
            '[data-vp-timebrush-caption="' + strip.dataset.vpTimebrush + '"]'
        );
    }

    /**
     * Name the bucket, or the span of buckets, under the pointer.
     *
     * @param {Element} strip
     * @param {number} from Bar index
     * @param {number} to Bar index
     */
    function captionBucket(strip, from, to) {
        var caption = timeBrushCaption(strip);
        var bars = timeBrushBars(strip);
        if (!caption || !bars[from] || !bars[to]) {
            return;
        }
        var total = 0;
        if (strip.dataset.vpTimebrushCount === 'rows') {
            total = timeBrushRows(strip, bars[from], bars[to]);
        } else {
            for (var i = from; i <= to; i++) {
                total += parseInt(bars[i].dataset.vpBucketCount, 10) || 0;
            }
        }
        caption.textContent = bucketSpan(bars[from], bars[to]) + ' · ' + total;
    }

    /**
     * A week's label is itself a range, so a run of weeks is named by
     * its first and last day rather than by joining two labels.
     *
     * @param {Element} first Bar
     * @param {Element} last Bar
     * @return {string}
     */
    function bucketSpan(first, last) {
        if (first === last) {
            return first.dataset.vpBucketLabel;
        }
        if (/–/.test(first.dataset.vpBucketLabel)) {
            return first.dataset.vpBucketFrom + ' – '
                + last.dataset.vpBucketTo;
        }
        return first.dataset.vpBucketLabel + ' – '
            + last.dataset.vpBucketLabel;
    }

    /**
     * How many rows a period from one bar to another would keep. Summing
     * the bars counts a row once per bucket it spans, which is right for
     * events and wrong for a resolution current across three months.
     *
     * @param {Element} strip
     * @param {Element} first Bar
     * @param {Element} last Bar
     * @return {number}
     */
    function timeBrushRows(strip, first, last) {
        var list = strip.closest('[data-vp-list]');
        if (!list) {
            return 0;
        }
        var key = strip.dataset.vpTimebrush;
        var from = boundDigits(first.dataset.vpBucketFrom, '0000');
        var to = boundDigits(last.dataset.vpBucketTo, '2359');
        return listRows(list).filter(function (row) {
            return rowOverlaps(row, key, from, to);
        }).length;
    }

    /**
     * @param {Element} strip
     */
    function captionDefault(strip) {
        var caption = timeBrushCaption(strip);
        if (!caption) {
            return;
        }
        /*
         * A strip whose date inputs are hidden names the period it is
         * set to at rest. The count stays with the list's own *N of M
         * shown*.
         */
        caption.textContent = timeBrushPeriod.get(strip)
            || caption.dataset.vpCaptionDefault || '';
    }

    /**
     * Write a brushed range into the strip's two date inputs.
     *
     * @param {Element} strip
     * @param {string} key The range's name
     * @param {number} from Bar index
     * @param {number} to Bar index
     */
    function writeTimeBrush(strip, key, from, to) {
        var list = strip.closest('[data-vp-list]');
        var bars = timeBrushBars(strip);
        if (!list || !bars[from] || !bars[to]) {
            return;
        }
        var pairs = [
            ['[data-vp-range-from="' + key + '"]',
                bars[from].dataset.vpBucketFrom],
            ['[data-vp-range-to="' + key + '"]',
                bars[to].dataset.vpBucketTo],
        ];
        pairs.forEach(function (pair) {
            var input = list.querySelector(pair[0]);
            if (input) {
                input.value = pair[1];
            }
        });
        listPages.set(list, 1);
        refreshList(list);
    }

    /**
     * @param {Element} strip
     * @param {string} key
     */
    function clearTimeBrush(strip, key) {
        var list = strip.closest('[data-vp-list]');
        if (!list) {
            return;
        }
        list.querySelectorAll(
            '[data-vp-range-from="' + key + '"],'
            + ' [data-vp-range-to="' + key + '"]'
        ).forEach(function (input) {
            input.value = '';
        });
        listPages.set(list, 1);
        refreshList(list);
    }

    /**
     * Swap which date the occurrence rail's one time control cuts on.
     *
     * The three scopes each keep their own strip, their own two inputs
     * and their own span, because a bucket of `timestamp` is not a
     * bucket of `publish_timestamp` and the bars carry the dates they
     * were rendered with. What the dropdown does is choose which of
     * those panes is on screen.
     *
     * **The panes it hides give up their bounds.** They are still in the
     * DOM and `activeRanges` still reads them, so a range left behind
     * would go on filtering the table from a control the reader can no
     * longer see — and the rail's summary would count a filter with
     * nothing on screen to explain it. Only the visible scope can hold
     * a bound, which is what makes the dropdown a scope switch rather
     * than a third filter.
     *
     * @param {Element} select A [data-vp-time-scope]
     */
    function switchTimeScope(select) {
        var group = select.closest('.vp-facetgrp');
        if (!group) {
            return;
        }
        var chosen = select.value;
        var dropped = false;
        group.querySelectorAll('[data-vp-time-pane]').forEach(
            function (pane) {
                var showing = pane.dataset.vpTimePane === chosen;
                pane.classList.toggle('d-none', !showing);
                if (showing) {
                    return;
                }
                pane.querySelectorAll(
                    '[data-vp-range-from], [data-vp-range-to]'
                ).forEach(function (input) {
                    if (input.value !== '') {
                        input.value = '';
                        dropped = true;
                    }
                });
            }
        );
        var list = select.closest('[data-vp-list]');
        // Only when something was actually cleared: switching between
        // two unbounded scopes changes what is on screen and not which
        // rows are, and a refresh would send the reader back to page one
        // for nothing.
        if (list && dropped) {
            narrowList(list);
        }
    }

    /**
     * Paint every strip in a list from what its inputs currently say, so
     * the window follows a typed date and a cleared one as well as a
     * brushed one. The bounds are the buckets the dates fall in, which
     * is the coarsest honest reading of a date the strip can draw.
     *
     * @param {Element} list
     */
    function paintTimeBrushes(list) {
        list.querySelectorAll('[data-vp-timebrush]').forEach(
            function (strip) {
                var key = strip.dataset.vpTimebrush;
                var bars = timeBrushBars(strip);
                if (!bars.length) {
                    return;
                }
                var from = list.querySelector(
                    '[data-vp-range-from="' + key + '"]'
                );
                var to = list.querySelector(
                    '[data-vp-range-to="' + key + '"]'
                );
                var lower = from && from.value ? from.value : null;
                var upper = to && to.value ? to.value : null;
                if (lower === null && upper === null) {
                    // `clear`, not `paint(…, null, …)`: the two states
                    // read the same and mean opposite things, and this
                    // is the one the strip is in almost all the time it
                    // is on screen.
                    timeBrushPeriod.delete(strip);
                    window.MispBrush.clear(strip);
                    captionDefault(strip);
                    return;
                }
                var first = bars.length - 1;
                var last = 0;
                bars.forEach(function (bar, index) {
                    var start = bar.dataset.vpBucketFrom;
                    var stop = bar.dataset.vpBucketTo;
                    // Any overlap between the bucket and the window.
                    if ((upper === null || start <= upper)
                        && (lower === null || stop >= lower)
                    ) {
                        first = Math.min(first, index);
                        last = Math.max(last, index);
                    }
                });
                window.MispBrush.paint(
                    strip,
                    first <= last ? { from: first, to: last } : null,
                    bars.length
                );
                if (strip.dataset.vpTimebrushCount === 'rows'
                    && from && from.type === 'hidden'
                    && first <= last
                ) {
                    timeBrushPeriod.set(
                        strip,
                        bucketSpan(bars[first], bars[last])
                    );
                    captionDefault(strip);
                }
            }
        );
    }

    /**
     * Repage what is already on screen at a size the reader picked.
     *
     * @param {Element} select A [data-vp-page-size-pick]
     */
    function changePageSize(select) {
        var list = select.closest('[data-vp-list]');
        if (!list) {
            return;
        }
        var pager = ownNode(list, '[data-vp-pager]');
        if (!pager) {
            return;
        }
        pager.dataset.vpPageSize = select.value;
        // Page four of sixty-row pages is not page four of twenty-five.
        listPages.set(list, 1);
        refreshList(list);
    }

    /**
     * What a chooser is currently set to, whether it is a `<select>` or
     * a pill group. The two carry the same `data-vp-sort` /
     * `data-vp-group` hook so a caller never has to know which it got.
     *
     * @param {Element} control
     * @return {string}
     */
    function controlValue(control) {
        return control.tagName === 'SELECT'
            ? control.value
            : (control.dataset.vpValue || '');
    }

    /**
     * Move a pill group to the option that was clicked, then tell the
     * list the same thing a `change` on a select would have.
     *
     * @param {Element} button A [data-vp-pill]
     */
    function pickPill(button) {
        var group = button.closest('[data-vp-sort], [data-vp-group]');
        if (!group || button.dataset.vpPill === group.dataset.vpValue) {
            return;
        }
        group.dataset.vpValue = button.dataset.vpPill;
        group.querySelectorAll('[data-vp-pill]').forEach(function (pill) {
            var on = pill === button;
            pill.classList.toggle('active', on);
            pill.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        if (group.hasAttribute('data-vp-group')) {
            switchGroup(group);
            return;
        }
        var list = group.closest('[data-vp-list]');
        if (list) {
            // A reorder does not change how many rows there are, but
            // page three of a new order is not the rows the reader was
            // looking at either.
            listPages.set(list, 1);
            /*
             * And where rows were cut, it changes which rows there
             * are. `Most recent` over the hundred already chosen by
             * shared events is the most recent of that hundred, which
             * is not what the control says — the neighbourhood's most
             * recent value usually shares one event and never ranked
             * near the top.
             */
            if (list.dataset.vpNarrowUrl && list.dataset.vpNarrowCut
                && narrowRemotely(list)
            ) {
                return;
            }
            refreshList(list);
        }
    }

    /**
     * Switch which roll-up is on screen.
     *
     * The narrowing controls belong to the value roll-up and are put
     * away with it: a facet like Type is a property of a correlated
     * value, and an event row is not a value. Anything set is cleared
     * on the way out rather than left applying invisibly.
     *
     * @param {Element} control A [data-vp-group] select or pill group
     */
    function switchGroup(control) {
        var list = control.closest('[data-vp-list]');
        if (!list) {
            return;
        }
        var group = controlValue(control);
        list.dataset.vpGroupActive = group;
        list.querySelectorAll('[data-vp-group-pane]').forEach(function (pane) {
            pane.classList.toggle('d-none',
                pane.dataset.vpGroupPane !== group);
        });
        list.querySelectorAll('[data-vp-group-only]').forEach(function (el) {
            el.classList.toggle('d-none', el.dataset.vpGroupOnly !== group);
        });
        list.querySelectorAll('[data-vp-group-not]').forEach(function (el) {
            el.classList.toggle('d-none', el.dataset.vpGroupNot === group);
        });
        /*
         * Clearing on the way out assumes the rows can be un-narrowed
         * without asking anyone, which holds only while the browser did
         * the narrowing. Where the fold did it, the rows on screen are
         * the narrowed ones until a request says otherwise — so the
         * controls keep saying so, and Reset is what undoes it.
         */
        if (!list.dataset.vpNarrowActive) {
            clearListFilters(list);
        }
        listPages.set(list, 1);
        refreshList(list);
    }

    /**
     * Put every narrowing control in this list back where it started.
     *
     * Scoped to the controls this list owns. `Reset` under the ranked
     * table must not silently untick the sibling section's facets: the
     * two sections narrow different row sets, and a reader who cleared
     * one has said nothing about the other.
     *
     * @param {Element} list
     */
    function clearListFilters(list) {
        ownNodes(list, 'input[data-vp-facet-key]:checked')
            .forEach(function (box) {
                box.checked = false;
            });
        ownNodes(list, 'select[data-vp-filter-key]')
            .forEach(function (select) {
                select.value = '';
            });
        ownNodes(list, '[data-vp-filter-text]')
            .forEach(function (input) {
                input.value = '';
            });
        ownNodes(list, '[data-vp-filter-min]')
            .forEach(function (input) {
                input.value = input.min === '' ? '0' : input.min;
            });
        ownNodes(list, '[data-vp-filter-from], [data-vp-filter-to],'
            + ' [data-vp-range-from], [data-vp-range-to]')
            .forEach(function (input) {
                input.value = '';
            });
    }

    /**
     * Whether this markup can answer the narrowing the reader set.
     *
     * A served list carries the top `row_cap` rows of a neighbourhood
     * that can run to five figures, so a filter applied here reaches
     * only what survived that cut — and a facet counted over the whole
     * neighbourhood then empties a table it was just counted in.
     *
     * Two cases stay local, and they are the common ones: nothing was
     * cut, or the entry's whole count is present in the rows the panel
     * holds, which the fold marks with `data-vp-complete`. Because the
     * client holds every row carrying such a token, it also holds every
     * subset of them — so a combination of complete entries is itself
     * complete, whether the boxes are read as *either* or as *and*.
     *
     * The search box and the threshold range over values the panel
     * never received, so neither can be proven complete here.
     *
     * **A page the fold narrowed can only ever be narrowed further.**
     * Its rows are the top of the *filter's* matches and not of the
     * neighbourhood, so there is nothing in the markup to widen back
     * out to: untick the warninglist that produced this page and the
     * rows still on screen are its 21 hits, which is not what *no
     * filter* means — and the panel would say `No filter applied` over
     * them. A state naming at least one complete entry is still
     * answerable, because every row carrying that token is here
     * whichever filter fetched it; an unconstrained one has to go back
     * to the fold.
     *
     * @param {Element} list
     * @return {boolean}
     */
    function narrowingIsLocal(list) {
        if (!list.dataset.vpNarrowUrl || !list.dataset.vpNarrowCut) {
            return true;
        }
        var text = ownNode(list, '[data-vp-filter-text]');
        if (text && text.value.trim() !== '') {
            return false;
        }
        var min = ownNode(list, '[data-vp-filter-min]');
        if (min && parseInt(min.value, 10) > 1) {
            return false;
        }
        var local = true;
        var proven = 0;
        ownNodes(list, 'input[data-vp-facet-key]:checked')
            .forEach(function (box) {
                if (box.dataset.vpComplete) {
                    proven++;
                } else {
                    local = false;
                }
            });
        ownNodes(list, 'select[data-vp-filter-key]').forEach(function (sel) {
            if (sel.value === '') {
                return;
            }
            var option = sel.options[sel.selectedIndex];
            if (option && option.dataset.vpComplete) {
                proven++;
            } else {
                local = false;
            }
        });
        if (proven === 0 && list.dataset.vpNarrowActive) {
            return false;
        }
        return local;
    }

    /**
     * The narrowing, as the panel's own endpoint takes it.
     *
     * `select` is kept apart from the facet arrays because the panel
     * means them differently — two ticks in a dropdown are *either*, a
     * select on top of them is *and also* — and the fold reads the two
     * shapes the same way this does.
     *
     * @param {Element} list
     * @return {string}
     */
    function narrowUrl(list, fresh) {
        var params = [];
        if (fresh) {
            // Skips the held scan on the way in and rewrites it on the
            // way out, so one press lands on new rows rather than on an
            // empty cache.
            params.push('fresh=1');
        }
        ownNodes(list, 'input[data-vp-facet-key]:checked')
            .forEach(function (box) {
                params.push('f[' + box.dataset.vpFacetKey + '][]='
                    + encodeURIComponent(box.value));
            });
        ownNodes(list, 'select[data-vp-filter-key]').forEach(function (sel) {
            if (sel.value === '') {
                return;
            }
            params.push('f[select][' + sel.dataset.vpFilterKey + ']='
                + encodeURIComponent(sel.value));
        });
        var text = ownNode(list, '[data-vp-filter-text]');
        if (text && text.value.trim() !== '') {
            params.push('f[text]=' + encodeURIComponent(text.value.trim()));
        }
        var min = ownNode(list, '[data-vp-filter-min]');
        if (min && parseInt(min.value, 10) > 1) {
            params.push('f[min_shared]=' + parseInt(min.value, 10));
        }
        var sort = ownNode(list, '[data-vp-sort]');
        if (sort && controlValue(sort) !== '' && controlValue(sort)
            !== 'shared'
        ) {
            params.push('f[rank]=' + encodeURIComponent(controlValue(sort)));
        }
        return list.dataset.vpNarrowUrl
            + (params.length ? '?' + params.join('&') : '');
    }

    var narrowTimers = new WeakMap();

    /**
     * Ask the fold for what this markup cannot answer.
     *
     * Debounced, because ticking three boxes is one question and not
     * three, and the fold behind this costs a scan.
     *
     * @param {Element} list
     * @return {boolean} Whether the request could be made
     */
    function narrowRemotely(list, fresh) {
        var container = list.closest('.ajax-tab-content, .ajax-card');
        if (!container || typeof window.reloadAjaxTabIndex !== 'function') {
            return false;
        }
        list.classList.add('vp-narrowing');
        window.clearTimeout(narrowTimers.get(list));
        narrowTimers.set(list, window.setTimeout(function () {
            window.reloadAjaxTabIndex(container, narrowUrl(list, fresh));
        }, fresh ? 0 : 300));
        return true;
    }

    /**
     * One entry for every narrowing control, wherever it lives.
     *
     * @param {Element} list
     */
    function narrowList(list) {
        // Narrowing changes how many pages there are, so page three of
        // the old set is not a page to stay on.
        listPages.set(list, 1);
        resetAuditPages(list);
        if (!narrowingIsLocal(list) && narrowRemotely(list)) {
            return;
        }
        refreshList(list);
    }

    /**
     * Show one page of the rows a filter left, and redraw the control
     * so its page count matches. Nothing re-queries: the pages are
     * slices of rows the fragment already carries.
     *
     * @param {Element} list
     * @param {Array<Element>} filtered
     */
    function paginate(list, filtered) {
        var pager = ownNode(list, '[data-vp-pager]');
        var size = pager ? parseInt(pager.dataset.vpPageSize, 10) : 0;

        if (!pager || !size || size < 1) {
            filtered.forEach(function (row) {
                row.classList.remove('d-none');
            });
            setListRange(list, filtered.length ? 1 : 0, filtered.length,
                filtered.length);
            return;
        }

        var pages = Math.max(1, Math.ceil(filtered.length / size));
        var page = Math.min(listPages.get(list) || 1, pages);
        listPages.set(list, page);

        var from = (page - 1) * size;
        var to = Math.min(from + size, filtered.length);
        filtered.forEach(function (row, index) {
            row.classList.toggle('d-none', index < from || index >= to);
        });

        setListRange(list, filtered.length ? from + 1 : 0, to,
            filtered.length);
        renderPager(pager, page, pages);
    }

    /**
     * Bootstrap pagination markup, arrows dead at the ends rather than
     * present and inert.
     *
     * @param {Element} pager
     * @param {number} page
     * @param {number} pages
     */
    function renderPager(pager, page, pages) {
        var list = pager.querySelector('ul.pagination');
        if (!list) {
            return;
        }
        var items = [];
        items.push(pageItem('«', page - 1, page === 1, false));
        pageWindow(page, pages).forEach(function (n) {
            items.push(n === null
                ? '<li class="page-item disabled vp-page-gap">'
                    + '<span class="page-link">…</span></li>'
                : pageItem(String(n), n, false, n === page));
        });
        items.push(pageItem('»', page + 1, page === pages, false));
        list.innerHTML = items.join('');
        // A single page is not a choice, so the control says nothing.
        pager.classList.toggle('d-none', pages < 2);
    }

    /**
     * The page numbers to draw, null for a gap. Always seven slots once
     * there are more than seven pages, so the control keeps one width
     * while the reader moves through it. `value_pager.ctp` draws the
     * first page with the same rule.
     *
     * @param {number} page
     * @param {number} pages
     * @return {Array<number|null>}
     */
    function pageWindow(page, pages) {
        var out = [];
        var n;
        if (pages <= 7) {
            for (n = 1; n <= pages; n++) {
                out.push(n);
            }
            return out;
        }
        if (page <= 4) {
            for (n = 1; n <= 5; n++) {
                out.push(n);
            }
            return out.concat([null, pages]);
        }
        if (page >= pages - 3) {
            out = [1, null];
            for (n = pages - 4; n <= pages; n++) {
                out.push(n);
            }
            return out;
        }
        return [1, null, page - 1, page, page + 1, null, pages];
    }

    /**
     * @param {string} label
     * @param {number} target
     * @param {boolean} disabled
     * @param {boolean} current
     * @return {string}
     */
    function pageItem(label, target, disabled, current) {
        var classes = ['page-item'];
        if (disabled) {
            classes.push('disabled');
        }
        if (current) {
            classes.push('active');
        }
        return '<li class="' + classes.join(' ') + '">'
            + '<button type="button" class="page-link"'
            + ' data-vp-page="' + target + '"'
            + (disabled ? ' disabled' : '')
            + (current ? ' aria-current="page"' : '')
            + '>' + label + '</button></li>';
    }

    /**
     * @param {Element} list
     * @param {number} from
     * @param {number} to
     * @param {number} of
     */
    function setListRange(list, from, to, of) {
        setOwnText(list, '[data-vp-page-from]', from);
        setOwnText(list, '[data-vp-page-to]', to);
        setOwnText(list, '[data-vp-page-of]', of);
        setOwnPlural(list, 'pager', of);
    }

    /**
     * A counted noun, in the form its number asks for.
     *
     * Both forms are rendered by the template so they come from
     * `__()`, and a translation is free to disagree with English about
     * where the boundary falls.
     *
     * @param {Element} list
     * @param {string} key
     * @param {number} n
     */
    function setOwnPlural(list, key, n) {
        ownNodes(list, '[data-vp-plural="' + key + '"]')
            .forEach(function (el) {
                el.textContent = n === 1
                    ? (el.dataset.vpOne || el.textContent)
                    : (el.dataset.vpMany || el.textContent);
            });
    }

    /**
     * The lines that say what the reader is looking at. `shown` is the
     * rows the filter left; the list's total is left alone, because it
     * is what the value has and not what this panel is displaying —
     * conflating them is how a filtered table starts claiming the
     * value has fewer occurrences than it does.
     *
     * @param {Element} list
     * @param {number} shown
     * @param {number} activeCount
     */
    function updateListNotes(list, shown, activeCount) {
        setOwnText(list, '[data-vp-list-shown]', shown);
        setOwnText(list, '[data-vp-facet-rows]', shown);
        setOwnText(list, '[data-vp-facet-count-active]', activeCount);
        setOwnPlural(list, 'rows', shown);
        setOwnPlural(list, 'filters', activeCount);

        var summary = ownNode(list, '[data-vp-facet-summary]');
        if (summary) {
            summary.classList.toggle('vp-facet-summary-on', activeCount > 0);
        }

        var clear = ownNode(list, '[data-vp-facet-clear]');
        if (clear) {
            clear.disabled = activeCount === 0;
        }

        var empty = ownNode(list, '[data-vp-list-empty]');
        // Only a filter can produce this: a list that was empty to
        // begin with has its own empty state from the template, and
        // saying "no rows match" over it would be a different claim.
        var blank = activeCount > 0 && shown === 0;
        if (empty) {
            empty.classList.toggle('d-none', !blank);
        }
        var rows = ownNode(list, '[data-vp-list-rows]');
        if (rows && empty) {
            rows.classList.toggle('d-none', blank);
        }
        // The brush windows are a second reading of the same two dates,
        // so they are repainted wherever those can have changed —
        // brushed, typed or cleared — rather than only where they were.
        if (ownNode(list, '[data-vp-timebrush]')) {
            paintTimeBrushes(list);
        }
    }

    function refreshAllLists(root) {
        (root || document).querySelectorAll('[data-vp-list]')
            .forEach(function (list) {
                refreshList(list);
            });
    }

    /**
     * A long tail is cut visibly: the group renders its top ten and an
     * `n more` that reveals the rest in place.
     *
     * @param {Element} button
     */
    function expandFacetGroup(button) {
        var group = button.closest('.vp-facetgrp');
        if (!group) {
            return;
        }
        group.querySelectorAll('[data-vp-facet-overflow]')
            .forEach(function (row) {
                row.classList.remove('d-none');
            });
        button.classList.add('d-none');
    }

    /**
     * Past ~50 values a group is a search box rather than a list, and
     * the box narrows the group's own rows — not the table's.
     *
     * @param {Element} input
     */
    function filterFacetGroup(input) {
        var group = input.closest('.vp-facetgrp');
        if (!group) {
            return;
        }
        var needle = input.value.trim().toLowerCase();
        group.querySelectorAll('.vp-facet').forEach(function (row) {
            var label = row.querySelector('.vp-facet-label');
            var text = (label ? label.textContent : '').toLowerCase();
            row.classList.toggle('d-none',
                needle !== '' && text.indexOf(needle) === -1);
        });
    }

    /* ==============================================================
     * The Occurrences tab's table
     * --------------------------------------------------------------
     * Two controls the faceted list does not own: which columns are
     * showing, and what the current selection spans.
     * ============================================================== */

    /**
     * Twelve columns, nine of them shown, and the panel header states
     * the ratio — so a toggle has to move the heading with the cells
     * and correct the ratio, or the table quietly stops matching the
     * number above it.
     *
     * @param {Element} box A [data-vp-col] checkbox
     */
    function toggleColumn(box) {
        var panel = box.closest('.vp-panel');
        if (!panel) {
            return;
        }
        panel.querySelectorAll('.' + box.dataset.vpCol)
            .forEach(function (cell) {
                cell.classList.toggle('d-none', !box.checked);
            });
        setText(panel, '[data-vp-col-shown]',
            panel.querySelectorAll('[data-vp-col]:checked').length);
    }



    /* ==================================================================
     * Charts
     * ------------------------------------------------------------------
     * A canvas cannot inherit a CSS variable, so a chart's colours are
     * resolved against the canvas at init and resolved again whenever
     * the theme flips. Two panels draw charts and both need exactly
     * this, so it lives here rather than in whichever fragment happened
     * to want it first.
     * ================================================================== */

    /**
     * One `var()` reference, fallback chain and all.
     *
     * The chain is the point. A config writing `var(--a, var(--b))` —
     * the form a stylesheet would use — used to miss the pattern and
     * reach Chart.js as its own source text, which Chart.js cannot
     * parse and silently draws in black. On the light theme that is a
     * visible line and nobody notices; on the dark one it is black on
     * `#212529`, 1.36:1. The shelf life curve shipped that way.
     *
     * An unset variable with no fallback still returns the source text,
     * so a genuine typo stays as loud as it was.
     *
     * @param {string} value
     * @param {Element} el
     * @return {string}
     */
    function resolveVar(value, el) {
        var match = value.match(/^var\(\s*(--[\w-]+)\s*(?:,([\s\S]*))?\)$/);
        if (!match) {
            return value;
        }
        var resolved = getComputedStyle(el)
            .getPropertyValue(match[1]).trim();
        if (resolved) {
            return resolved;
        }
        var fallback = (match[2] || '').trim();
        return fallback ? resolveVar(fallback, el) : value;
    }

    /**
     * Turn every `var(--x)` in a config into the value that variable
     * has on `el`.
     *
     * Walks the whole config rather than a list of known keys: colours
     * turn up in scales, plugins and datasets alike, and a config is
     * plain data by the time it gets here.
     *
     * @param {*} node
     * @param {Element} el
     * @return {*}
     */
    function resolveChartColours(node, el) {
        if (typeof node === 'string') {
            return resolveVar(node, el);
        }
        if (Array.isArray(node)) {
            return node.map(function (item) {
                return resolveChartColours(item, el);
            });
        }
        if (node && typeof node === 'object') {
            var out = {};
            Object.keys(node).forEach(function (key) {
                out[key] = resolveChartColours(node[key], el);
            });
            return out;
        }
        return node;
    }

    /**
     * Build a chart once Chart.js has arrived, and rebuild it on demand
     * or whenever the theme changes.
     *
     * Safe inside a lazily-injected fragment: the global is polled for
     * rather than assumed, since a fragment cannot know it is the first
     * one to land.
     *
     * @param {string} id Canvas id, namespaced by the caller
     * @param {function(Element): Object} build Returns a Chart
     * @return {{refresh: function}} A handle the caller redraws through
     */
    function bootChart(id, build) {
        var chart = null;

        function make() {
            var el = document.getElementById(id);
            if (!el || typeof Chart === 'undefined') {
                return false;
            }
            if (chart) {
                chart.destroy();
            }
            /*
             * A fragment that is re-fetched brings a new canvas under
             * the same id, and the previous boot's theme observer is
             * still watching it. Whatever is attached to the element
             * goes first, or Chart.js refuses the second instance.
             */
            if (typeof Chart.getChart === 'function') {
                var attached = Chart.getChart(el);
                if (attached) {
                    attached.destroy();
                }
            }
            chart = build(el);
            return true;
        }

        function boot() {
            if (typeof Chart === 'undefined') {
                setTimeout(boot, 100);
                return;
            }
            if (!make()) {
                return;
            }
            // The observer stops itself once the canvas is gone — a
            // reloaded fragment brings its own script with it.
            var observer = new MutationObserver(function () {
                if (!document.getElementById(id)) {
                    observer.disconnect();
                    return;
                }
                make();
            });
            observer.observe(document.documentElement, {
                attributes: true,
                attributeFilter: ['data-misp-mode'],
            });
        }

        boot();
        return { refresh: make };
    }

    window.VP = window.VP || {};
    window.VP.chart = { resolve: resolveChartColours, boot: bootChart };

    /* ==================================================================
     * The zoom
     * ------------------------------------------------------------------
     * Narrow what the chart shows, which is a different question from
     * the brush's *what do I want to filter by* (§13.3). Both gestures
     * live on the same strip, so they are kept apart by having only one
     * of them be a drag: the drag still selects, and zoom is four
     * buttons.
     *
     * Zoom and the bucket unit are one mechanism seen twice (§13.2). A
     * span of a fortnight has no business being drawn as one monthly
     * bar, and a span of fourteen months has no business being drawn as
     * 437 daily ones — §12.5.5 measured the second of those at 0.68px a
     * bar. So the unit follows from the visible span, by a rule the
     * caller owns: the History chart draws its whole span monthly and
     * the Timeline draws every span monthly, and one shared rule could
     * not do both.
     *
     * No fetch, at any zoom level. §13.1 measured the whole span at
     * every grain at about a kilobyte of counts and a dozen of labels,
     * so the server ships all of it once and this is arithmetic. Which
     * is also why the labels are not derived here — they arrive from
     * `ValueIntelligenceBuckets::plan()` already written, so there is one
     * formatter rather than two that have to agree.
     * ================================================================== */

    /*
     * How few bars the chart may be zoomed down to.
     *
     * A chart of two bars is not a chart, and the floor has to be in
     * bars rather than in days because the Timeline's finest unit is a
     * month: four is a readable span of days and a readable span of
     * months, and the same number therefore serves both.
     */
    var ZOOM_MIN_BUCKETS = 4;

    /**
     * @param {string} ymd `Y-m-d`
     * @return {number} Days since the epoch, UTC
     */
    function zoomEpochDay(ymd) {
        var parts = ymd.split('-');
        return Math.round(Date.UTC(
            Number(parts[0]),
            Number(parts[1]) - 1,
            Number(parts[2])
        ) / 86400000);
    }

    /**
     * @param {number} day Days since the epoch, UTC
     * @return {string} `Y-m-d`
     */
    function zoomYmd(day) {
        return new Date(day * 86400000).toISOString().slice(0, 10);
    }

    /*
     * PHP's `date()` is not locale-aware — `M` is always `Jan`..`Dec`,
     * whatever the instance's language — so this table reproduces
     * `ValueIntelligenceBuckets::describe()` exactly rather than
     * approximating it. `toLocaleString` would not: it would render the
     * day grain's bars in the browser's language and the week grain's,
     * which the server still writes, in English.
     */
    var ZOOM_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    /**
     * The bar label for one day, as `describe()` writes it: `j M`.
     *
     * The day grain ships no labels — bucket `i` is the day `from + i`
     * and can be nothing else, so 1,095 of these were 26.7 KB of
     * payload restating the arithmetic this file already does.
     * `ValueIntelligenceBuckets::plan` documents the other half.
     *
     * @param {number} day Days since the epoch, UTC
     * @return {string}
     */
    function zoomDayLabel(day) {
        var at = new Date(day * 86400000);
        return at.getUTCDate() + ' ' + ZOOM_MONTHS[at.getUTCMonth()];
    }

    /**
     * The tooltip for one day, as `describe()` writes it: `j M Y`.
     * A day bucket starts and ends on the same date, so it is the
     * single-date branch there and never the range one.
     *
     * @param {number} day Days since the epoch, UTC
     * @return {string}
     */
    function zoomDayTitle(day) {
        return zoomDayLabel(day) + ' ' + new Date(day * 86400000)
            .getUTCFullYear();
    }

    /**
     * The unit a span of this many days is drawn at.
     *
     * A mirror of `ValueIntelligenceBuckets::unitForSpan()`, and the only
     * one this file keeps: the rule itself is shipped rather than
     * restated, so what is duplicated is the walk over it and not the
     * thresholds.
     *
     * @param {Array} rule `days` and `unit`, first match wins
     * @param {number} days
     * @return {string}
     */
    function zoomUnitFor(rule, days) {
        for (var i = 0; i < rule.length; i += 1) {
            if (rule[i].days === null || days <= rule[i].days) {
                return rule[i].unit;
            }
        }
        return rule[rule.length - 1].unit;
    }

    /**
     * A zoom over one chart's plan.
     *
     * The state is a visible span in day offsets from the plan's start,
     * plus the unit that span is drawn at. The unit is stored rather
     * than re-derived on read, because every transition snaps the span
     * outwards to whole buckets *of the unit the requested span asked
     * for* — deriving it again from the snapped span could pick a
     * different one and the pair would never settle.
     *
     * `selection` is how the zoom offers *look inside what I have
     * already picked* without knowing what a selection is on the
     * caller's tab — a filtered period on the History rail, a brushed
     * window on the Sightings navigator. A callback rather than a
     * value, for the reason phase 20 made the brush's bucket count
     * one: the answer changes under the control, and the control is
     * wired once.
     *
     * @param {Object} plan `from`, `to`, `days`, `rule`, `grains`
     * @param {Function|null} selection Returns `{from, to}` or null
     * @return {Object}
     */
    function makeZoom(plan, selection) {
        var epoch = zoomEpochDay(plan.from);
        var last = plan.days - 1;
        var ranges = {};
        var view = { from: 0, to: last };
        var unit = zoomUnitFor(plan.rule, plan.days);

        /**
         * One grain's bar label, whether the server wrote it or this
         * side derives it.
         *
         * `plan.last_label` replaces the final bar's own label — the
         * navigator's right-hand column reads `today` at every grain —
         * and it is applied here rather than server-side because it is
         * a translated word and the day grain's labels no longer exist
         * for it to be written into.
         *
         * @param {string} which Unit
         * @param {number} index Bar's place in the grain
         * @return {string}
         */
        function labelOf(which, index) {
            var grain = plan.grains[which];
            if (plan.last_label && index === grainCount(which) - 1) {
                return plan.last_label;
            }
            return grain.label
                ? grain.label[index]
                : zoomDayLabel(epoch + index);
        }

        /**
         * The same for a bar's tooltip. No `last_label` here: the end
         * bar is labelled `today` and still titled with its own date,
         * which is what makes the label a relabelling rather than a
         * claim that the bucket is now.
         *
         * @param {string} which Unit
         * @param {number} index
         * @return {string}
         */
        function titleOf(which, index) {
            var grain = plan.grains[which];
            return grain.title
                ? grain.title[index]
                : zoomDayTitle(epoch + index);
        }

        /**
         * How many bars a grain has. `count` is on every grain, so a
         * grain whose label array is gone still knows its own length.
         *
         * @param {string} which
         * @return {number}
         */
        function grainCount(which) {
            var grain = plan.grains[which];
            if (!grain) {
                return 0;
            }
            return grain.count === undefined
                ? grain.label.length
                : grain.count;
        }

        /**
         * Each bucket of a grain as a pair of day offsets, worked out
         * once per grain and kept.
         *
         * The server ships the starts and not the ends, because a
         * bucket ends where the next one begins and the last ends with
         * the span — so the ends are arithmetic, and arithmetic is this
         * side's half of the split `plan()` documents. A `starts` of
         * null is the identity, which is what a daily grain always is.
         *
         * @param {string} which
         * @return {Array}
         */
        function offsets(which) {
            if (!ranges[which]) {
                var grain = plan.grains[which];
                var count = grainCount(which);
                var starts = grain && grain.starts;
                var spans = [];
                for (var i = 0; i < count; i += 1) {
                    var from = starts ? starts[i] : i;
                    var next = i + 1 < count
                        ? (starts ? starts[i + 1] : i + 1)
                        : last + 1;
                    spans.push({ from: from, to: next - 1 });
                }
                ranges[which] = spans;
            }
            return ranges[which];
        }

        /**
         * One drawn bar: the label and title the server wrote, and the
         * dates this side worked out.
         *
         * The dates are clipped to the visible span, which does two
         * jobs. The month grain's first bucket is a whole calendar
         * month and so may begin before the log's first day — a bar the
         * reader may brush, but not one they may filter to days the log
         * does not cover. And where the visible span is a *named* one
         * rather than a zoomed one, its edge bars are clipped to it
         * exactly as the server used to clip them: a range called
         * `last 365 days` covers 365 days, so its first weekly bar is
         * however much of that week falls inside.
         *
         * `index` is the bar's place in the grain rather than in the
         * drawn window, because a caller whose data is parallel arrays
         * — one per organisation, on the Sightings navigator — indexes
         * them by that and not by what happens to be on screen.
         *
         * @param {string} which
         * @param {number} index
         * @param {{from: number, to: number}} span Day offsets
         * @return {Object}
         */
        function describe(which, index, span) {
            var lo = Math.max(Math.max(0, view.from), span.from);
            var hi = Math.min(Math.min(last, view.to), span.to);
            return {
                bucket: {
                    label: labelOf(which, index),
                    title: titleOf(which, index),
                    from: zoomYmd(epoch + lo),
                    to: zoomYmd(epoch + hi),
                },
                index: index,
                from: lo,
                to: hi,
            };
        }

        /**
         * Widen `from`..`to` to the whole buckets of `which` it touches.
         *
         * Outwards and never inwards, so a bar is always the whole
         * bucket the server labelled: §12.4 refused a month bucket
         * starting mid-month on the grounds that it would be a bar
         * labelled `Mar` that is not March, and an edge left where a
         * halving put it would be exactly that.
         *
         * @param {string} which
         * @param {number} from Day offset
         * @param {number} to Day offset
         * @return {{from: number, to: number}}
         */
        function snap(which, from, to) {
            var spans = offsets(which);
            var lo = null;
            var hi = null;
            spans.forEach(function (span) {
                if (span.to >= from && span.from <= to) {
                    if (lo === null) {
                        lo = span.from;
                    }
                    hi = span.to;
                }
            });
            if (lo === null) {
                return { from: 0, to: last };
            }
            return {
                from: Math.max(0, lo),
                to: Math.min(last, hi),
            };
        }

        /**
         * Move to a requested span: pick the unit it asks for, then
         * either snap to that unit's buckets or take the span as given.
         *
         * The two callers want different things and the difference is
         * not a detail. A zoom step has no span to honour — it halves
         * what is on screen — so its edges are arbitrary and snapping
         * them out to whole buckets is what keeps a bar labelled `Mar`
         * from being part of March. A *named* span is the opposite: the
         * reader picked `last 365 days`, so its edges are the point and
         * widening them to 371 would make the label wrong. Its edge
         * bars are clipped instead, which is what the server did when
         * it built those ranges itself.
         *
         * @param {number} from Day offset
         * @param {number} to Day offset
         * @param {boolean} exact Take the span as given
         */
        function settle(from, to, exact) {
            var lo = Math.max(0, Math.min(from, last));
            var hi = Math.min(last, Math.max(to, 0));
            var wanted = zoomUnitFor(plan.rule, hi - lo + 1);
            unit = wanted;
            view = exact ? { from: lo, to: hi } : snap(wanted, lo, hi);
        }

        /**
         * The buckets currently drawn, each with the day offsets it
         * covers so the caller can reduce its own data over them.
         *
         * @return {Array} `bucket`, `from`, `to`
         */
        function drawn() {
            var spans = offsets(unit);
            var out = [];
            spans.forEach(function (span, index) {
                if (span.to >= view.from && span.from <= view.to) {
                    out.push(describe(unit, index, span));
                }
            });
            return out;
        }

        /**
         * What halving the visible span would land on, as a span.
         *
         * Around the centre, because there is no pointer to zoom
         * towards — the gesture is a button, not a wheel over a bar.
         *
         * @param {number} factor 0.5 to zoom in, 2 to zoom out
         * @return {{from: number, to: number}}
         */
        function scaled(factor) {
            var days = view.to - view.from + 1;
            var wanted = Math.max(1, Math.round(days * factor));
            var centre = (view.from + view.to) / 2;
            return {
                from: Math.round(centre - (wanted - 1) / 2),
                to: Math.round(centre + (wanted - 1) / 2),
            };
        }

        /**
         * Whether zooming in would leave a chart worth drawing.
         *
         * Measured on what the step would actually produce rather than
         * on the day count, because snapping can widen it back: at
         * monthly bars a halving that lands inside one month snaps out
         * to that month and the step would do nothing.
         *
         * @return {boolean}
         */
        function canIn() {
            var want = scaled(0.5);
            var wanted = zoomUnitFor(plan.rule, want.to - want.from + 1);
            var bounds = snap(wanted, Math.max(0, want.from),
                Math.min(last, want.to));
            var spans = offsets(wanted);
            var count = 0;
            spans.forEach(function (span) {
                if (span.to >= bounds.from && span.from <= bounds.to) {
                    count += 1;
                }
            });
            if (count < ZOOM_MIN_BUCKETS) {
                return false;
            }
            return bounds.from > view.from || bounds.to < view.to;
        }

        return {
            /** @return {string} */
            unit: function () {
                return unit;
            },
            /** @return {Array} */
            window: function () {
                return drawn();
            },
            /** @return {number} */
            count: function () {
                return drawn().length;
            },
            /** @return {boolean} Whether the whole span is showing */
            whole: function () {
                return view.from === 0 && view.to === last;
            },
            /**
             * The two ends of the visible span, in words.
             *
             * Off the daily grain's titles, indexed by day offset,
             * rather than off the first and last drawn buckets': a
             * weekly bucket's own title is a range — `19 Aug – 25 Aug
             * 2024` — so a caption built from two of them reads as four
             * dates with three dashes. A daily title is one date, which
             * is the whole reason for reaching past the drawn bars.
             *
             * A caller whose rule has no daily grain falls back to the
             * bucket titles, which for a monthly grain are single
             * tokens and read correctly.
             *
             * @return {{from: string, to: string}|null}
             */
            spanText: function () {
                var shown = drawn();
                if (!shown.length) {
                    return null;
                }
                var first = shown[0];
                var final = shown[shown.length - 1];
                var day = plan.grains.day;
                if (day && !day.starts) {
                    return {
                        from: titleOf('day', first.from),
                        to: titleOf('day', final.to),
                    };
                }
                return {
                    from: first.bucket.title,
                    to: final.bucket.title,
                };
            },
            /** @return {{from: string, to: string}} `Y-m-d` bounds */
            span: function () {
                var shown = drawn();
                if (!shown.length) {
                    return { from: plan.from, to: plan.to };
                }
                return {
                    from: shown[0].bucket.from,
                    to: shown[shown.length - 1].bucket.to,
                };
            },
            /**
             * The title of the bucket of `which` that holds `ymd`,
             * whether or not it is on screen.
             *
             * For a caller that wants to name a date in the same words
             * a bar names it — the History tab puts a day inside its
             * month — without keeping its own copy of the grain's
             * shape.
             *
             * @param {string} which Unit
             * @param {string} ymd `Y-m-d`
             * @return {string|null}
             */
            titleAt: function (which, ymd) {
                if (!plan.grains[which]) {
                    return null;
                }
                var wanted = zoomEpochDay(ymd) - epoch;
                var found = null;
                offsets(which).forEach(function (span, index) {
                    if (wanted >= span.from && wanted <= span.to) {
                        found = titleOf(which, index);
                    }
                });
                return found;
            },
            /**
             * Whether looking inside the selection would show anything
             * different from what is on screen.
             *
             * False when there is no selection, when it is not in the
             * plan at all, and when it already *is* the visible span —
             * a button that redraws the same chart is one the reader
             * learns to distrust.
             *
             * @return {boolean}
             */
            canSelection: function () {
                if (!selection) {
                    return false;
                }
                var picked = selection();
                if (!picked || !picked.from || !picked.to) {
                    return false;
                }
                var lo = zoomEpochDay(picked.from) - epoch;
                var hi = zoomEpochDay(picked.to) - epoch;
                if (hi < 0 || lo > last || hi < lo) {
                    return false;
                }
                return Math.max(0, lo) > view.from
                    || Math.min(last, hi) < view.to;
            },
            /**
             * Show the selection. Exact, like a preset: the reader
             * picked these two dates, so widening them to whole buckets
             * would show them a span they did not ask for.
             */
            stepSelection: function () {
                if (!selection) {
                    return;
                }
                var picked = selection();
                if (!picked || !picked.from || !picked.to) {
                    return;
                }
                settle(
                    zoomEpochDay(picked.from) - epoch,
                    zoomEpochDay(picked.to) - epoch,
                    true
                );
            },
            /** @return {boolean} */
            canIn: canIn,
            /** @return {boolean} */
            canOut: function () {
                return !(view.from === 0 && view.to === last);
            },
            /** @return {boolean} */
            canLeft: function () {
                return view.from > 0;
            },
            /** @return {boolean} */
            canRight: function () {
                return view.to < last;
            },
            stepIn: function () {
                var want = scaled(0.5);
                settle(want.from, want.to);
            },
            stepOut: function () {
                var want = scaled(2);
                settle(want.from, want.to);
            },
            /**
             * Sideways by half a window, and never off the end: a pan
             * that ran out of span would otherwise shrink the view.
             *
             * @param {number} direction -1 or 1
             * @param {number} scale Half-windows to move, default 1
             */
            step: function (direction, scale) {
                var days = view.to - view.from + 1;
                var by = direction * Math.max(1,
                    Math.round(days / 2 * (scale || 1)));
                var from = view.from + by;
                var to = view.to + by;
                if (from < 0) {
                    to -= from;
                    from = 0;
                }
                if (to > last) {
                    from -= to - last;
                    to = last;
                }
                settle(from, to);
            },
            /**
             * Show a named date range: one of a caller's presets, or
             * the range a reader has already brushed and wants to look
             * inside. Taken exactly, per `settle`.
             *
             * @param {string} from `Y-m-d`
             * @param {string} to `Y-m-d`
             */
            to: function (from, to) {
                settle(
                    zoomEpochDay(from) - epoch,
                    zoomEpochDay(to) - epoch,
                    true
                );
            },
            reset: function () {
                view = { from: 0, to: last };
                unit = zoomUnitFor(plan.rule, plan.days);
            },
        };
    }

    /**
     * Wire one zoom control's buttons.
     *
     * @param {Element|null} root The control
     * @param {Object} zoom From `makeZoom`
     * @param {Function} changed Called after any step
     */
    function wireZoom(root, zoom, changed) {
        if (!root) {
            return;
        }
        var steps = {
            in: function () {
                zoom.stepIn();
            },
            out: function () {
                zoom.stepOut();
            },
            left: function () {
                zoom.step(-1);
            },
            right: function () {
                zoom.step(1);
            },
            reset: function () {
                zoom.reset();
            },
            selection: function () {
                zoom.stepSelection();
            },
        };
        root.querySelectorAll('[data-vp-zoom-step]').forEach(
            function (button) {
                button.addEventListener('click', function (event) {
                    event.preventDefault();
                    if (button.vpHeld) {
                        button.vpHeld = false;
                        return;
                    }
                    var step = steps[button.dataset.vpZoomStep];
                    if (step) {
                        step();
                        changed();
                    }
                });
            }
        );
        root.querySelectorAll('[data-vp-zoom-step="left"],'
            + ' [data-vp-zoom-step="right"]').forEach(function (button) {
            holdToPan(button, zoom, changed);
        });
    }

    /*
     * Holding a pan button keeps panning, and faster the longer it is
     * held: at five daily bars one click moves three days, so crossing
     * a year is a hold rather than a hundred clicks.
     */
    var ZOOM_HOLD_DELAY = 350;
    var ZOOM_HOLD_EVERY = 110;
    var ZOOM_HOLD_RAMP = 5;
    var ZOOM_HOLD_MAX_SCALE = 8;

    /**
     * @param {Element} button A `left` or `right` step
     * @param {Object} zoom From `makeZoom`
     * @param {Function} changed Called after each step
     */
    function holdToPan(button, zoom, changed) {
        var direction = button.dataset.vpZoomStep === 'left' ? -1 : 1;
        var delay = null;
        var repeat = null;

        function stop() {
            clearTimeout(delay);
            clearInterval(repeat);
            delay = null;
            repeat = null;
        }

        button.addEventListener('pointerdown', function (event) {
            if (event.button !== 0 || button.disabled) {
                return;
            }
            stop();
            button.vpHeld = false;
            // A redraw can move the button from under the pointer, which
            // would otherwise read as the reader letting go.
            button.setPointerCapture(event.pointerId);
            var ticks = 0;
            delay = setTimeout(function () {
                button.vpHeld = true;
                repeat = setInterval(function () {
                    var canMove = direction < 0
                        ? zoom.canLeft()
                        : zoom.canRight();
                    if (!canMove) {
                        stop();
                        return;
                    }
                    var scale = Math.min(ZOOM_HOLD_MAX_SCALE,
                        Math.pow(2, Math.floor(ticks / ZOOM_HOLD_RAMP)));
                    ticks += 1;
                    zoom.step(direction, scale);
                    changed();
                }, ZOOM_HOLD_EVERY);
            }, ZOOM_HOLD_DELAY);
        });
        ['pointerup', 'pointercancel', 'lostpointercapture'].forEach(
            function (name) {
                button.addEventListener(name, stop);
            }
        );
    }

    /**
     * Show where the zoom is: which buttons can still do something,
     * what span is on screen and what a bar is worth.
     *
     * Both halves of the caption are the server's own strings — the
     * first and last drawn buckets' titles, and the grain wording the
     * caller shipped — so a reader is never told `Mar` by one formatter
     * and `March` by another.
     *
     * A caller may pass a `note`, which is the one thing about a
     * zoomed chart this layer cannot know: whether what the reader has
     * selected is still on screen. A fully dimmed strip is the truthful
     * painting of *nothing here is in your range*, and it is also
     * indistinguishable from an undimmed one, because a uniform dim has
     * nothing to contrast against — so the fact has to be said in words
     * or not at all.
     *
     * @param {Element|null} root The control
     * @param {Object} zoom From `makeZoom`
     * @param {Object} labels `grain` keyed by unit
     * @param {string|null} note Optional, shown beside the grain
     */
    function paintZoom(root, zoom, labels, note) {
        if (!root) {
            return;
        }
        var can = {
            in: zoom.canIn(),
            out: zoom.canOut(),
            left: zoom.canLeft(),
            right: zoom.canRight(),
            reset: !zoom.whole(),
            selection: zoom.canSelection(),
        };
        root.querySelectorAll('[data-vp-zoom-step]').forEach(
            function (button) {
                button.disabled = !can[button.dataset.vpZoomStep];
            }
        );
        var range = root.querySelector('[data-vp-zoom-range]');
        if (range) {
            var ends = zoom.spanText();
            if (ends === null) {
                range.textContent = '';
            } else if (ends.from === ends.to) {
                range.textContent = ends.from;
            } else {
                range.textContent = ends.from + ' → ' + ends.to;
            }
        }
        var grain = root.querySelector('[data-vp-zoom-grain]');
        if (grain && labels && labels.grain) {
            grain.textContent = labels.grain[zoom.unit()] || '';
        }
        var aside = root.querySelector('[data-vp-zoom-note]');
        if (aside) {
            aside.textContent = note || '';
            aside.hidden = !note;
        }
        root.classList.toggle('vp-zoom-on', !zoom.whole());
    }

    window.VP.zoom = {
        make: makeZoom,
        wire: wireZoom,
        paint: paintZoom,
    };

    /* ==================================================================
     * Sightings tab
     * ------------------------------------------------------------------
     * One overlay and one brush. The chart and the list arrive as two
     * fragments in whichever order the network decides, so the state
     * lives here and each fragment applies it when it lands rather than
     * one of them reaching into the other.
     *
     * Everything is client-side against data the fragments already
     * carry: the span presets and the zoom both re-aggregate one daily
     * tally, and dragging the brush hides table rows. Nothing
     * re-queries, and nothing writes.
     *
     * Phase 21 replaced three precomputed ranges with that one tally.
     * The tab reads its bars, its stacks and its curves through
     * `sightRange()` and always did, so the conversion is behind that
     * one function: what changed is that it derives the range from the
     * visible span rather than looking one up.
     * ================================================================== */

    var sight = {
        data: null,
        rangeKey: null,
        // Which of the three types are drawn. A type with no rows at
        // all is disabled in the markup and never reaches this.
        shown: { sighting: true, fp: true, expiration: true },
        // Organisations the legend has switched off, by their index in
        // `data.orgs`. Keyed by index rather than held as a list of the
        // survivors so that a colour never moves: the ramp is read off
        // this index and a filter must not repaint what it left alone.
        // The chart only — the table below answers to the brush, which
        // is the gesture that has a date range in it.
        hiddenOrgs: {},
        // Bucket index bounds of the brush, or null while it covers the
        // whole range.
        brush: null,
        expanded: false,
        main: null,
        nav: null,
        // The visible span, which the presets and the four buttons both
        // set. Null until the panel has a plan.
        zoom: null,
        labels: null,
        // `sightRange()`'s answer, and the zoom state it was computed
        // for. Rebuilt on a change rather than on every read: a repaint
        // asks for it from the chart, the navigator, the legend and the
        // list, and summing 23 organisations' worth of days four times
        // over is work nobody asked for.
        range: null,
        rangeAt: null,
    };

    var SIGHT_ORG_COLOURS = 6;
    var SIGHT_CURVE_COLOURS = 2;

    /*
     * The three kinds of report, bottom of the stack upwards, and the
     * only place their order is written down. Every series on the count
     * axis is one of these for one organisation — a sighting is not
     * attributed while a false positive is pooled, which is what this
     * tab used to do.
     */
    var SIGHT_KINDS = ['sighting', 'fp', 'expiration'];

    /**
     * Turn the sparse per-day tallies into dense arrays, once.
     *
     * The wire format is sparse because these series are — twenty-three
     * organisations over fourteen months, a few hundred reports between
     * them — and the runtime format is dense because everything above
     * it sums slices, which wants a plain array. Only the wire differs.
     *
     * @param {Object} data The payload
     */
    function sightInflate(data) {
        var days = data.plan.days;

        function dense(at) {
            var counts = new Array(days);
            var i;
            for (i = 0; i < days; i += 1) {
                counts[i] = 0;
            }
            Object.keys(at || {}).forEach(function (offset) {
                var slot = Number(offset);
                if (slot >= 0 && slot < days) {
                    counts[slot] = at[offset];
                }
            });
            return counts;
        }

        SIGHT_KINDS.forEach(function (kind) {
            var series = data.daily[kind] || {};
            data.daily[kind] = Object.keys(series).map(function (key) {
                return dense(series[key]);
            });
        });
    }

    /**
     * Sum one daily series over the days a bar covers.
     *
     * @param {Array} counts One count per day of the plan's span
     * @param {{from: number, to: number}} bar Day offsets
     * @return {number}
     */
    function sightSum(counts, bar) {
        var total = 0;
        for (var i = bar.from; i <= bar.to; i += 1) {
            total += counts[i] || 0;
        }
        return total;
    }

    /**
     * The range the chart is drawing: one entry per visible bar, in the
     * shape every consumer on this tab already read.
     *
     * Built rather than looked up, which is the whole of phase 21 on
     * this tab. The three precomputed ranges were three aggregations of
     * the same rows, so the browser can make any of them — and any span
     * between them — by summing a slice of the daily tally per bar.
     *
     * The curves are sampled, not summed. A count is additive and a
     * a shelf life is not: it is the value as of a date, so a bar that
     * covers a week takes the sample at the end of that week, which is
     * where the per-range curves used to be sampled.
     *
     * @return {Object|null}
     */
    function sightRange() {
        if (!sight.data || !sight.zoom) {
            return null;
        }
        var span = sight.zoom.span();
        var stamp = span.from + '/' + span.to + '/' + sight.zoom.unit();
        if (sight.range !== null && sight.rangeAt === stamp) {
            return sight.range;
        }
        var bars = sight.zoom.window();
        var daily = sight.data.daily;
        function total(series) {
            return series.reduce(function (a, b) {
                return a + b;
            }, 0);
        }
        /*
         * Three tallies per organisation, each summed per drawn bar.
         * `kinds[kind][org]` is one array per bar, which is the shape
         * Chart.js wants a dataset in and the shape the readout groups
         * by — the only reshaping left is choosing which of them are
         * currently drawn.
         */
        var kinds = {};
        var kindCounts = {};
        SIGHT_KINDS.forEach(function (kind) {
            kinds[kind] = (daily[kind] || []).map(function (counts) {
                return bars.map(function (bar) {
                    return sightSum(counts, bar);
                });
            });
            kindCounts[kind] = total(kinds[kind].map(total));
        });
        /*
         * An organisation's count is every report it filed in the
         * range, of any type, which is what the Reporters card counts
         * and what the legend's own heading promises. A per-kind
         * breakdown rides along so the key can say which of the three
         * the number is made of.
         */
        var orgCounts = sight.data.orgs.map(function (name, i) {
            return SIGHT_KINDS.reduce(function (sum, kind) {
                return sum + total(kinds[kind][i] || []);
            }, 0);
        });
        var orgByKind = sight.data.orgs.map(function (name, i) {
            var per = {};
            SIGHT_KINDS.forEach(function (kind) {
                per[kind] = total(kinds[kind][i] || []);
            });
            return per;
        });
        sight.range = {
            unit: sight.zoom.unit(),
            unitLabel: sight.data.labels.perColumn[sight.zoom.unit()],
            from: span.from,
            to: span.to,
            labels: bars.map(function (bar) {
                return bar.bucket.label;
            }),
            starts: bars.map(function (bar) {
                return bar.bucket.from;
            }),
            ends: bars.map(function (bar) {
                return bar.bucket.to;
            }),
            kinds: kinds,
            kindCounts: kindCounts,
            orgCounts: orgCounts,
            orgByKind: orgByKind,
            curves: sight.data.curves.map(function (curve) {
                return {
                    model: curve.model,
                    threshold: curve.threshold,
                    points: bars.map(function (bar) {
                        return curve.points[bar.to];
                    }),
                };
            }),
        };
        sight.rangeAt = stamp;
        return sight.range;
    }

    /**
     * Throw away the derived range, so the next read rebuilds it.
     */
    function sightInvalidate() {
        sight.range = null;
        sight.rangeAt = null;
    }

    /**
     * A categorical colour by position, cycling once the palette runs
     * out. Named variables rather than literals: the canvas resolves
     * them against the page, so the ramp follows the theme.
     *
     * @param {number} index
     * @param {number} count How many the palette defines
     * @param {string} name `org` or `curve`
     * @return {string}
     */
    function sightHue(index, count, name) {
        return 'var(--vp-sight-' + name + '-' + ((index % count) + 1) + ')';
    }

    /* ------------------------------------------------------------------
     * The readout
     * ------------------------------------------------------------------
     * Chart.js draws one list, and this chart hovers two scales at
     * once. A column over a busy week listed nine organisations, a
     * false positive, an expiration, two model scores and two model
     * thresholds as thirteen interchangeable rows of `name: number` —
     * so the count and the score, whose only relationship is the
     * argument the panel exists to make, looked like members of one
     * series.
     *
     * So the canvas tooltip is off and this one is HTML: two sections
     * with a rule between them, the reports totalled in their heading,
     * and the number ahead of the name in every row because the reader
     * arrived already knowing which series they are pointing at. The
     * keys are strokes rather than blocks — at this density a filled
     * swatch is data-weight ink doing a label's job.
     * ------------------------------------------------------------------ */

    /**
     * The node, made once per chart and reused. It lives inside the
     * chart's own relatively-positioned box, so placing it is arithmetic
     * on the caret rather than on the page.
     *
     * @param {Element} host The canvas's parent
     * @return {Element}
     */
    function sightTipNode(host) {
        var node = host.querySelector('[data-vp-sight-tip]');
        if (!node) {
            node = document.createElement('div');
            node.className = 'vp-tip';
            node.setAttribute('data-vp-sight-tip', '');
            node.setAttribute('aria-hidden', 'true');
            host.appendChild(node);
        }
        return node;
    }

    /**
     * @param {Element} node
     * @param {string} title
     * @param {?number} total Rendered beside the heading when given
     * @return {Element} The section to append rows to
     */
    function sightTipSection(node, title, total) {
        var section = document.createElement('div');
        var head = document.createElement('div');
        var name = document.createElement('span');
        section.className = 'vp-tip-sec';
        head.className = 'vp-tip-sec-head';
        name.textContent = title;
        head.appendChild(name);
        if (total !== null) {
            var count = document.createElement('b');
            count.textContent = total;
            head.appendChild(count);
        }
        section.appendChild(head);
        node.appendChild(section);
        return section;
    }

    /**
     * One row. `textContent` throughout: an organisation name is
     * whatever a remote instance called itself.
     *
     * @param {Element} section
     * @param {string} colour Already resolved off the canvas
     * @param {number} value
     * @param {string} name
     */
    function sightTipRow(section, colour, value, name) {
        var row = document.createElement('div');
        var key = document.createElement('i');
        var num = document.createElement('b');
        var label = document.createElement('span');
        row.className = 'vp-tip-row';
        key.className = 'vp-tip-key';
        key.style.background = colour;
        num.textContent = value;
        label.textContent = name;
        row.appendChild(key);
        row.appendChild(num);
        row.appendChild(label);
        section.appendChild(row);
        return row;
    }

    /**
     * Chart.js hands the whole tooltip model here on every move.
     *
     * @param {Object} context `{chart, tooltip}`
     */
    function sightTip(context) {
        var chart = context.chart;
        var model = context.tooltip;
        var node = sightTipNode(chart.canvas.parentNode);

        if (!model || model.opacity === 0
            || !(model.dataPoints || []).length
        ) {
            node.classList.remove('vp-tip-on');
            return;
        }

        var labels = (sight.data && sight.data.labels) || {};
        var kindLabels = labels.kinds || {};
        var points = model.dataPoints || [];
        var at = points.length ? points[0].dataIndex : null;

        node.textContent = '';
        var head = document.createElement('div');
        head.className = 'vp-tip-head';
        head.textContent = model.title.length ? model.title[0] : '';
        node.appendChild(head);

        /*
         * One section per kind of report, so that every row in the
         * readout says the same thing — a count and the organisation
         * that filed it — and the heading says which kind. A single
         * `Reports` list could not: the reporter was the row label for
         * a sighting and there was no row label left for a false
         * positive but the words `False positive` themselves.
         *
         * A kind with nothing in this column is not a section. Its
         * heading totals the column rather than its own rows, because
         * the rows are filtered — an organisation reporting nothing
         * this week is not a row.
         *
         * Magnitudes throughout. The two contradicting kinds are
         * plotted negative so they hang below the axis, and `-2
         * expirations` is a direction printed as though it were a
         * quantity.
         */
        SIGHT_KINDS.forEach(function (kind) {
            var rows = points.filter(function (point) {
                return point.dataset.vpKind === kind;
            });
            var total = 0;
            if (at !== null) {
                chart.data.datasets.forEach(function (set) {
                    if (set.vpKind === kind) {
                        total += Math.abs(set.data[at] || 0);
                    }
                });
            }
            if (total === 0) {
                return;
            }
            var section = sightTipSection(
                node,
                kindLabels[kind] || '',
                total
            );
            rows.forEach(function (point) {
                sightTipRow(
                    section,
                    point.dataset.backgroundColor,
                    Math.abs(point.parsed.y),
                    point.dataset.label
                );
            });
        });

        var lines = points.filter(function (point) {
            return point.dataset.type === 'line';
        });
        if (lines.length) {
            var scores = sightTipSection(node, labels.score || '', null);
            lines.forEach(function (point) {
                sightTipRow(
                    scores,
                    point.dataset.borderColor,
                    point.parsed.y,
                    point.dataset.label
                );
            });
        }

        node.classList.add('vp-tip-on');
        var left = model.caretX + 14;
        if (left + node.offsetWidth > chart.width) {
            left = model.caretX - node.offsetWidth - 14;
        }
        var top = model.caretY - (node.offsetHeight / 2);
        node.style.left = Math.max(0, Math.min(
            left,
            chart.width - node.offsetWidth
        )) + 'px';
        node.style.top = Math.max(0, Math.min(
            top,
            chart.height - node.offsetHeight
        )) + 'px';
    }

    /**
     * Which way a kind of report is drawn. A sighting supports the
     * value and goes up; a false positive and an expiration argue
     * against it and go down.
     *
     * This is the panel's argument moved out of the colour channel and
     * into the geometry. All three used to stack upwards in one column,
     * so `a contradiction was filed` was a hue among six organisation
     * hues that cycle — the two marks the panel exists to make visible
     * were the two hardest to find in a stack of six reporters.
     * Direction cannot be crowded out: whatever is below the line
     * argues against the value, at any grain, in either theme, and in
     * greyscale.
     *
     * @param {string} kind One of SIGHT_KINDS
     * @return {number} 1 above the line, -1 below it
     */
    function sightKindSign(kind) {
        return kind === 'sighting' ? 1 : -1;
    }

    /**
     * The colour a segment of one kind takes.
     *
     * Colour is identity here and direction is meaning, so a sighting
     * is the organisation's own hue. The two contradicting kinds keep a
     * colour of their own because the axis can only say `argues
     * against` and there are two ways of doing that — and below the
     * line they never touch an organisation hue, which is what retires
     * the collision that used to matter most: the benign green against
     * a brown organisation at ΔE 4.1, and the red that replaced it at
     * 9.3, were both pairs that can no longer meet.
     *
     * @param {string} kind One of SIGHT_KINDS
     * @param {number} i Position in `data.orgs`
     * @return {string}
     */
    function sightKindHue(kind, i) {
        if (kind === 'fp') {
            return 'var(--vp-sight-fp)';
        }
        if (kind === 'expiration') {
            return 'var(--vp-sight-exp)';
        }
        return sightHue(i, SIGHT_ORG_COLOURS, 'org');
    }

    /**
     * How far the count axis reaches each way, over the drawn range and
     * over the kinds currently switched on.
     *
     * Computed here rather than left to Chart.js because the score axis
     * has to be told where this one's zero landed. A score is 0–100 and
     * a count is now signed, so the two axes only share a zero if the
     * score scale is given the same negative share of its own height —
     * otherwise a model at 0 draws a line through the middle of the
     * contradictions, which is exactly the region it is supposed to be
     * read against.
     *
     * @param {Object} range From sightRange
     * @return {{up: number, down: number}} Both positive magnitudes
     */
    function sightBounds(range) {
        var up = 0;
        var down = 0;
        range.labels.forEach(function (label, at) {
            var above = 0;
            var below = 0;
            SIGHT_KINDS.forEach(function (kind) {
                if (!sight.shown[kind]) {
                    return;
                }
                range.kinds[kind].forEach(function (counts, i) {
                    if (sight.hiddenOrgs[i]) {
                        return;
                    }
                    if (sightKindSign(kind) > 0) {
                        above += counts[at];
                    } else {
                        below += counts[at];
                    }
                });
            });
            up = Math.max(up, above);
            down = Math.max(down, below);
        });
        /*
         * At least one unit of headroom above the line even when
         * nothing supports the value, because the overlay is drawn in
         * that band and a value nobody has ever sighted still has a
         * shelf life. Without it, a value with false positives and no
         * sighting would give the line no height to live in.
         */
        return { up: Math.max(1, up), down: down };
    }

    /**
     * The overlay itself: one stacked bar dataset per organisation per
     * kind of report on the count axis, and the value's remaining shelf
     * life on the right-hand axis.
     *
     * Three datasets per organisation rather than one each plus two
     * pooled ones. Pooling meant a sighting had a reporter and a
     * contradiction had none — the legend filed `False positive` under
     * `Reported by` as though it were an organisation, and the readout
     * listed it beside real ones. Now every count on this axis belongs
     * to somebody, which is also what makes switching an organisation
     * off take its contradictions with it.
     *
     * The kinds go in whole: every organisation's sightings, then every
     * organisation's false positives, then the expirations. So the
     * stack reads as three coloured blocks rather than interleaving red
     * through the organisation hues.
     *
     * The thresholds used to be here too, as a dotted dataset each plus
     * an inline plugin that chipped their value over the plot. They are
     * gone twice over: a threshold was a constant drawn per model and
     * listed again in the readout at every column, and since phase 5
     * there is no model and no threshold — expiry is the line reaching
     * the axis.
     *
     * An organisation the legend has switched off is skipped rather
     * than emptied, and the colour still comes from its position in
     * `data.orgs` — filtering the series must not repaint the ones that
     * stayed.
     *
     * @param {Element} el
     * @return {Object}
     */
    function buildSightMain(el) {
        var data = sight.data;
        var range = sightRange();
        var datasets = [];

        /*
         * A hairline of the page's own ground between stacked segments.
         * Without it a stack of three organisations with counts 1, 1, 1
         * is one bar in three tones, and the tones are what the reader
         * is being asked to count. It matters more now that two
         * organisations' false positives sit on each other in the same
         * red.
         *
         * The hairline goes on the side away from the axis, which is
         * the top of a bar that grows up and the bottom of one that
         * grows down.
         */
        function segment(sign, extra) {
            return Object.assign({
                type: 'bar',
                stack: 'reports',
                yAxisID: 'y',
                order: 3,
                borderColor: 'var(--bs-body-bg)',
                borderWidth: sign > 0
                    ? { top: 1, right: 0, bottom: 0, left: 0 }
                    : { top: 0, right: 0, bottom: 1, left: 0 },
                borderSkipped: false,
            }, extra);
        }

        /*
         * Three kinds by however many organisations is a lot of series
         * that are entirely zero — twenty-three organisations would be
         * sixty-nine datasets with perhaps twenty carrying anything, and
         * most organisations never file a contradiction at all. A
         * series with nothing in the drawn range is left out: it paints
         * no pixel and, being filtered out of the readout anyway,
         * contributes nothing but a dataset for Chart.js to walk. The
         * bar hue is read off `i` rather than off the dataset's
         * position, so leaving one out never moves a colour.
         */
        SIGHT_KINDS.forEach(function (kind) {
            if (!sight.shown[kind]) {
                return;
            }
            var sign = sightKindSign(kind);
            range.kinds[kind].forEach(function (counts, i) {
                if (sight.hiddenOrgs[i] || !counts.some(Boolean)) {
                    return;
                }
                datasets.push(segment(sign, {
                    label: data.orgs[i],
                    vpKind: kind,
                    // Signed for the plot only. `range.kinds` stays
                    // counts, so the navigator, the legend and the
                    // readout keep summing magnitudes.
                    data: sign > 0 ? counts : counts.map(function (n) {
                        return -n;
                    }),
                    backgroundColor: sightKindHue(kind, i),
                }));
            });
        });

        range.curves.forEach(function (curve, i) {
            var colour = sightHue(i, SIGHT_CURVE_COLOURS, 'curve');
            datasets.push({
                type: 'line',
                label: curve.model,
                data: curve.points,
                borderColor: colour,
                backgroundColor: colour,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 3,
                tension: 0.25,
                spanGaps: false,
                yAxisID: 'score',
                order: 1,
            });
        });

        /*
         * Both axes are pinned rather than left to Chart.js, so that
         * one pixel row means zero on both of them. The score keeps its
         * 0–100 over the band above the line and is given the same
         * negative share below it, where it has nothing to draw — so a
         * model sitting at 0 rests exactly on the count axis's zero
         * instead of cutting through the contradictions underneath.
         */
        var bounds = sightBounds(range);
        var scoreFloor = -100 * (bounds.down / bounds.up);

        var config = window.VP.chart.resolve({
            data: { labels: range.labels, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        border: { color: 'var(--bs-border-color)' },
                        ticks: {
                            color: 'var(--bs-secondary-color)',
                            maxRotation: 0,
                            autoSkipPadding: 24,
                            font: { size: 10 },
                        },
                    },
                    y: {
                        stacked: true,
                        min: -bounds.down,
                        max: bounds.up,
                        border: { display: false },
                        grid: {
                            color: 'var(--bs-border-color)',
                            /*
                             * The zero is the whole encoding, so it is
                             * drawn as a line and not as another
                             * gridline. Everything below it argues
                             * against the value.
                             */
                            lineWidth: function (context) {
                                return context.tick && context.tick.value === 0
                                    ? 2
                                    : 1;
                            },
                        },
                        ticks: {
                            color: 'var(--bs-secondary-color)',
                            precision: 0,
                            font: { size: 10 },
                            // A count, never a negative number: the
                            // direction is what the sign is saying and
                            // `-2 reports` is not a quantity.
                            callback: function (value) {
                                return Math.abs(value);
                            },
                        },
                    },
                    score: {
                        display: range.curves.length > 0,
                        position: 'right',
                        min: scoreFloor,
                        max: 100,
                        border: { display: false },
                        grid: { drawOnChartArea: false },
                        ticks: {
                            color: 'var(--bs-secondary-color)',
                            stepSize: 25,
                            font: { size: 10 },
                            // The band below zero exists to hold the
                            // two scales' zeroes together, and a score
                            // never reaches it. Labelling it would
                            // claim a scale of negative scores.
                            callback: function (value) {
                                return value < 0 ? '' : value;
                            },
                        },
                    },
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        // A stack of ten one-report bars would otherwise
                        // list ten organisations reporting zero.
                        filter: function (item) {
                            return item.parsed.y !== 0
                                || item.dataset.type === 'line';
                        },
                        // The reports first, the scores after, whatever
                        // order the datasets went in — the readout is
                        // grouped and the groups have to stay whole.
                        itemSort: function (a, b) {
                            var rank = function (item) {
                                return item.dataset.type === 'line' ? 1 : 0;
                            };
                            return rank(a) - rank(b)
                                || a.datasetIndex - b.datasetIndex;
                        },
                        enabled: false,
                        external: sightTip,
                    },
                },
            },
        }, el);

        config.type = 'bar';
        return new Chart(el, config);
    }

    /**
     * The navigator: every report in the range as one bar per bucket,
     * with no axes, so the brush above it can be positioned as a plain
     * fraction of the strip's width.
     *
     * @param {Element} el
     * @return {Object}
     */
    function buildSightNav(el) {
        var range = sightRange();
        // Every report of every kind, whatever the chart above is
        // currently drawing: the navigator is the range, not the view.
        var totals = range.labels.map(function (label, i) {
            var sum = 0;
            SIGHT_KINDS.forEach(function (kind) {
                range.kinds[kind].forEach(function (counts) {
                    sum += counts[i];
                });
            });
            return sum;
        });
        var config = window.VP.chart.resolve({
            type: 'bar',
            data: {
                labels: range.labels,
                datasets: [{
                    data: totals,
                    backgroundColor: 'var(--vp-sight-nav)',
                    barPercentage: 1,
                    categoryPercentage: 1,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                layout: { padding: 0 },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true },
                },
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false },
                },
            },
        }, el);
        return new Chart(el, config);
    }

    /**
     * @param {Element} panel
     */
    function updateSightLegend(panel) {
        var range = sightRange();
        var labels = sight.data.labels;
        panel.querySelectorAll('[data-vp-sight-key-org]')
            .forEach(function (key) {
                var i = parseInt(key.dataset.vpSightKeyOrg, 10);
                setText(key, '[data-vp-sight-key-count]', range.orgCounts[i]);
                /*
                 * Every report the organisation filed in the range, of
                 * any kind — the heading over these keys says `Reported
                 * by` and a contradiction is a report. The `title`
                 * carries the split, because the swatch is only the
                 * colour of the sightings among them.
                 */
                var per = range.orgByKind[i];
                var counted = labels.kindCounted || {};
                key.title = SIGHT_KINDS.filter(function (kind) {
                    return per[kind] > 0;
                }).map(function (kind) {
                    var forms = counted[kind] || [kind, kind];
                    return per[kind] + ' '
                        + forms[per[kind] === 1 ? 0 : 1];
                }).join(' · ');
                /*
                 * The count is the range's and stays put whether or not
                 * the bars are drawn: switching an organisation off asks
                 * the chart a question, not the data.
                 */
                key.setAttribute(
                    'aria-pressed',
                    sight.hiddenOrgs[i] ? 'false' : 'true'
                );
                // Nothing left to take out while every kind is switched
                // off above.
                key.disabled = !SIGHT_KINDS.some(function (kind) {
                    return sight.shown[kind];
                });
            });
        setText(panel, '[data-vp-sight-key-fp]', range.kindCounts.fp);
        setText(panel, '[data-vp-sight-key-exp]', range.kindCounts.expiration);

        var axis = panel.querySelector('[data-vp-sight-axis-left]');
        if (axis) {
            axis.textContent = labels.perUnit[range.unit];
        }
    }

    /**
     * Where the brush currently sits, as dates.
     *
     * @return {{from: string, to: string, whole: boolean}}
     */
    function sightWindow() {
        var range = sightRange();
        var last = range.labels.length - 1;
        var from = sight.brush ? sight.brush.from : 0;
        var to = sight.brush ? sight.brush.to : last;
        return {
            from: range.starts[from],
            to: range.ends[to],
            whole: from === 0 && to === last,
        };
    }

    /**
     * @param {Element} panel
     */
    function paintSightBrush(panel) {
        var count = sightRange().labels.length;
        window.MispBrush.paint(
            panel,
            sight.brush || { from: 0, to: count - 1 },
            count
        );

        var window_ = sightWindow();
        var label = panel.querySelector('[data-vp-sight-window]');
        if (label) {
            label.textContent = window_.from + ' → ' + window_.to;
        }
        // The brush *is* this tab's selection, so the step that looks
        // inside it goes live and dead with the drag.
        paintSightZoom(panel);
    }

    /**
     * Put the sightings list in the order its sorted heading names, and
     * only when that is not the order the rows are already in.
     *
     * The guard is what makes a sortable heading affordable on this
     * panel. `refreshSightList` runs on every frame of a brush drag, and
     * reordering is an `appendChild` per row — free to skip, and not
     * free to repeat a few hundred times a second.
     *
     * Every row and not the brushed ones, because the brush is a
     * visibility filter over a fixed set: leaving the rows outside it
     * where they were would put the DOM in an order that widening the
     * brush could not recover.
     *
     * @param {Element} list
     */
    function applySightOrder(list) {
        var column = list.dataset.vpSortedCol || 'default';
        var sign = list.dataset.vpSortedDir === 'desc' ? -1 : 1;
        var wanted = column + ':' + sign;
        if (list.dataset.vpSightOrder === wanted) {
            return;
        }
        sortByColumn(
            list,
            Array.prototype.slice.call(list.querySelectorAll('tbody tr')),
            column,
            sign
        );
        list.dataset.vpSightOrder = wanted;
    }

    /**
     * Row visibility in the sightings list, decided in one place: the
     * brush chooses which rows are candidates and `load the rest`
     * chooses how many of them are on screen.
     */
    function refreshSightList() {
        var list = document.querySelector('[data-vp-sight-list]');
        if (!list) {
            return;
        }
        var size = parseInt(list.dataset.vpSightPageSize, 10) || 10;
        var window_ = sight.data ? sightWindow() : null;
        var matched = [];

        // Before the rows are collected, so `matched` comes out in the
        // order the reader is about to see rather than in the order the
        // model happened to send.
        applySightOrder(list);

        list.querySelectorAll('tbody tr').forEach(function (row) {
            var day = row.dataset.vpSightDate;
            var keep = !window_
                || (day >= window_.from && day <= window_.to);
            if (keep) {
                matched.push(row);
            }
            row.classList.add('d-none');
        });

        var limit = sight.expanded
            ? matched.length
            : Math.min(size, matched.length);
        matched.slice(0, limit).forEach(function (row) {
            row.classList.remove('d-none');
        });

        setText(list, '[data-vp-sight-in-range]', matched.length);
        setText(list, '[data-vp-sight-range-shown]', matched.length);
        setText(list, '[data-vp-sight-shown]', limit);
        setText(list, '[data-vp-sight-of]', matched.length);

        var note = list.querySelector('[data-vp-sight-range-note]');
        if (note) {
            // The note is the brush's, not the range select's: the
            // select says what it selected in its own label, and a note
            // repeating it would be noise on every page load.
            var narrowed = !!window_ && !window_.whole;
            note.classList.toggle('d-none', !narrowed);
            if (narrowed) {
                setText(note, '[data-vp-sight-range-from]', window_.from);
                setText(note, '[data-vp-sight-range-to]', window_.to);
            }
        }

        var more = list.querySelector('[data-vp-sight-more]');
        if (more) {
            more.hidden = limit >= matched.length;
        }

        // Only a brush can empty this list. A value with no sightings
        // has its own empty state from the template, and "none in this
        // range" over it would be a different and false claim.
        var empty = list.querySelector('[data-vp-sight-empty]');
        var rows = list.querySelector('[data-vp-sight-rows]');
        var blank = matched.length === 0;
        if (empty) {
            empty.classList.toggle('d-none', !blank);
        }
        if (rows) {
            rows.classList.toggle('d-none', blank);
        }
        var foot = list.querySelector('.vp-sight-foot');
        if (foot) {
            foot.classList.toggle('d-none', blank);
        }
    }

    /**
     * Redraw everything the chart panel owns, then hand the window to
     * the list.
     *
     * @param {Element} panel
     */
    function refreshSight(panel) {
        if (sight.main) {
            sight.main.refresh();
        }
        if (sight.nav) {
            sight.nav.refresh();
        }
        paintSightZoom(panel);
        updateSightLegend(panel);
        paintSightBrush(panel);
        refreshSightList();
    }

    /**
     * Drag on the navigator strip. A click clears the brush — the same
     * gesture the `Clear` button offers, for a reader who never found
     * it.
     *
     * The count is a callback because the range select changes it: 90
     * daily buckets become 43 weekly ones without the brush being
     * rewired.
     *
     * @param {Element} panel
     */
    function wireSightBrush(panel) {
        window.MispBrush.attach(panel.querySelector('[data-misp-brush]'), {
            count: function () {
                return sightRange().labels.length;
            },
            range: function (from, to) {
                sight.brush = { from: from, to: to };
                sight.expanded = false;
                paintSightBrush(panel);
                refreshSightList();
            },
            clear: function () {
                sight.brush = null;
                sight.expanded = false;
                paintSightBrush(panel);
                refreshSightList();
            },
        });
    }

    /**
     * Show one of the presets the select offers.
     *
     * @param {string} key `90`, `365` or `all`
     */
    function sightToSpan(key) {
        if (!sight.zoom || !sight.data) {
            return;
        }
        var wanted = null;
        sight.data.spans.forEach(function (span) {
            if (span.key === key) {
                wanted = span;
            }
        });
        if (wanted === null) {
            sight.zoom.reset();
        } else {
            sight.zoom.to(wanted.from, wanted.to);
        }
        sightInvalidate();
    }

    /**
     * Move the preset select onto whichever preset the drawn span is,
     * or onto `Custom span` when it is none of them, so the select
     * never names a range the chart is no longer drawing.
     *
     * @param {Element} panel
     */
    function syncSightPreset(panel) {
        var select = panel.querySelector('[data-vp-sight-range]');
        if (!select || !sight.zoom || !sight.data) {
            return;
        }
        var custom = select.querySelector('[data-vp-sight-range-custom]');
        var span = sight.zoom.span();
        var matched = null;
        sight.data.spans.forEach(function (preset) {
            if (preset.from === span.from && preset.to === span.to) {
                matched = preset.key;
            }
        });
        if (custom) {
            custom.hidden = matched !== null;
        }
        if (matched !== null) {
            select.value = matched;
            sight.rangeKey = matched;
        } else if (custom) {
            custom.selected = true;
        }
    }

    /**
     * Paint the zoom control, and say when the brushed range has gone
     * off screen — which on this tab means the list below is filtered
     * to something the chart is no longer showing.
     *
     * @param {Element} panel
     */
    function paintSightZoom(panel) {
        var zoom = panel.querySelector('[data-vp-zoom]');
        if (!zoom || !sight.zoom) {
            return;
        }
        var labels = sight.labels || {};
        window.VP.zoom.paint(zoom, sight.zoom, labels, null);
    }

    /**
     * @param {Element} root Either the whole page or a fragment
     */
    function initSightings(root) {
        var panel = (root || document).querySelector('[data-vp-sight]');
        if (panel) {
            var payload = panel.querySelector('[data-vp-sight-data]');
            if (!payload) {
                return;
            }
            sight.data = JSON.parse(payload.textContent);
            sightInflate(sight.data);
            sight.rangeKey = sight.data['default'];
            sight.brush = null;
            sight.expanded = false;
            sight.zoom = window.VP.zoom.make(
                sight.data.plan,
                // The brushed window, and only when it is a brush: the
                // window covers the whole visible span when nothing is
                // brushed, and `look inside all of it` is not a step.
                function () {
                    if (!sight.brush) {
                        return null;
                    }
                    var picked = sightWindow();
                    return { from: picked.from, to: picked.to };
                }
            );
            sightInvalidate();
            // The default preset is the narrowest span holding every
            // sighting, and it is what the select is rendered on, so
            // the chart has to land on the same one.
            sightToSpan(sight.rangeKey);
            sight.shown = { sighting: true, fp: true, expiration: true };
            sight.hiddenOrgs = {};
            panel.querySelectorAll('[data-vp-sight-type]')
                .forEach(function (button) {
                    if (button.disabled) {
                        sight.shown[button.dataset.vpSightType] = false;
                    }
                });
            sight.main = window.VP.chart.boot('vp-sight-main', buildSightMain);
            sight.nav = window.VP.chart.boot('vp-sight-nav', buildSightNav);
            wireSightBrush(panel);
            var zoom = panel.querySelector('[data-vp-zoom]');
            if (zoom) {
                var spec = zoom.querySelector('[data-vp-zoom-labels]');
                sight.labels = spec ? JSON.parse(spec.textContent) : null;
                zoom.hidden = false;
                window.VP.zoom.wire(zoom, sight.zoom, function () {
                    // A zoom is a different set of bars, so a brush
                    // drawn over the old ones points at nothing the
                    // reader chose — the same reason a preset clears it.
                    sight.brush = null;
                    sight.expanded = false;
                    syncSightPreset(panel);
                    refreshSight(panel);
                });
            }
            updateSightLegend(panel);
            paintSightBrush(panel);
            paintSightZoom(panel);
        }
        // The list can land before or after the chart, so it is caught
        // here either way: with the chart's state if there is one, and
        // with its own untouched rows if there is not yet.
        refreshSightList();
    }

    /**
     * @param {Event} event
     * @return {boolean} Whether the event was a sightings control
     */
    function onSightClick(event) {
        var panel = document.querySelector('[data-vp-sight]');

        var toggle = event.target.closest('[data-vp-sight-type]');
        if (toggle && !toggle.disabled && panel) {
            var key = toggle.dataset.vpSightType;
            sight.shown[key] = !sight.shown[key];
            toggle.setAttribute('aria-pressed', String(sight.shown[key]));
            refreshSight(panel);
            return true;
        }

        /*
         * The legend as a filter. A stack of a dozen organisations is
         * a wall at the one bar the reader cares about, and until now
         * the only way to thin it was the three type toggles, which
         * cannot say `just this one`.
         */
        var org = event.target.closest('[data-vp-sight-key-org]');
        if (org && !org.disabled && panel) {
            var at = parseInt(org.dataset.vpSightKeyOrg, 10);
            if (sight.hiddenOrgs[at]) {
                delete sight.hiddenOrgs[at];
            } else {
                sight.hiddenOrgs[at] = true;
            }
            refreshSight(panel);
            return true;
        }

        if (event.target.closest('[data-vp-sight-clear]')) {
            sight.brush = null;
            sight.expanded = false;
            if (panel) {
                paintSightBrush(panel);
            }
            refreshSightList();
            return true;
        }

        var more = event.target.closest('[data-vp-sight-more]');
        if (more) {
            sight.expanded = true;
            refreshSightList();
            return true;
        }

        return false;
    }

    /**
     * Enrichment tab
     * ------------------------------------------------------------
     * Everything here is a class change over markup the endpoint
     * already sent. That is not an implementation shortcut: running a
     * module spends quota and tells whoever operates it that you are
     * looking at this value, so picking one to read must not be
     * capable of querying anything. The tab's one behavioural
     * promise is that no request leaves the browser — on load, on tab
     * switch, or on selecting a module — and rendering every pane up
     * front is what makes that promise keepable rather than merely
     * intended.
     */

    /**
     * Swap which module the pane is showing.
     *
     * @param {Element} panel
     * @param {string} key Module name, or `__all` for the merged pane
     */
    function pickEnrichModule(panel, key) {
        panel.querySelectorAll('[data-vp-e-pane]').forEach(function (pane) {
            pane.classList.toggle('d-none', pane.dataset.vpEPane !== key);
        });
        panel.querySelectorAll('[data-vp-e-row]').forEach(function (row) {
            var on = row.dataset.vpERow === key;
            row.classList.toggle('vp-e-railrow-on', on);
            var body = row.querySelector('[data-vp-e-pick]');
            if (body) {
                body.setAttribute('aria-pressed', on ? 'true' : 'false');
            }
        });
    }

    /**
     * How a run's outcome reads on the rail.
     *
     * Six states and six wordings, and none of them collapses into
     * another. *Silent* is the one worth guarding: a module that
     * answered with nothing did its job and reported no knowledge of
     * this value, which a reader acts on differently from a module
     * that errored and differently again from one nobody asked.
     */
    var ENRICH_STATES = {
        ok: {dot: 'vp-e-dot-ok', cls: 'vp-e-status-ok',
            label: 'Answered'},
        silent: {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
            label: 'Nothing back'},
        error: {dot: 'vp-e-dot-err', cls: 'vp-e-status-timeout',
            label: 'Module error'},
        timeout: {dot: 'vp-e-dot-timeout', cls: 'vp-e-status-timeout',
            label: 'Timed out'},
        refused: {dot: 'vp-e-dot-err', cls: 'vp-e-status-timeout',
            label: 'Not sent'},
        unreachable: {dot: 'vp-e-dot-err', cls: 'vp-e-status-timeout',
            label: 'No service'},
        ineligible: {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
            label: 'Not offered'},
        running: {dot: 'vp-e-dot-run', cls: 'vp-e-status-none',
            label: 'Asking…'},
        /*
         * The reader's own declaration, and it was missing: a `never`
         * module refused at the endpoint painted `Unknown` on its row
         * while the pane beside it explained the refusal.
         */
        profile_refused: {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
            label: 'Blocked by you'},
        /*
         * Phase 11. Neither is a failure of the module: the instance
         * declined to run it unasked, or the kept answer has aged out
         * of the store. Both are worth a second press and neither
         * deserves a red dot.
         */
        auto_not_allowed: {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
            label: 'Not run on its own'},
        expired: {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
            label: 'No longer kept'}
    };

    /*
     * What a row says about a state this script does not know.
     *
     * **Not `ok`.** It was, and that is how a timed-out module came to
     * paint a green dot and the word *Answered* on its row while the
     * pane beside it said the module had run out of time — the one
     * distinction the state list exists to keep. A row that cannot
     * name what happened must not claim the best of the seven things
     * it might have been.
     */
    var ENRICH_UNKNOWN = {dot: 'vp-e-dot-none', cls: 'vp-e-status-none',
        label: 'Unknown'};

    var ENRICH_DOTS = 'vp-e-dot-ok vp-e-dot-err vp-e-dot-run '
        + 'vp-e-dot-none vp-e-dot-timeout';
    var ENRICH_CLS = 'vp-e-status-ok vp-e-status-none '
        + 'vp-e-status-timeout';

    /**
     * How much a module sent back, said on its own row.
     *
     * `Answered` is the same word for two elements and for two
     * hundred, and reading the modules against each other is what the
     * rail is for. A capped answer says both numbers, because the one
     * that is rendered is not the one that came back.
     *
     * @param {Element} panel
     * @param {Element} row
     * @param {string} state
     * @param {Element} result The answer, where there is one
     */
    function setEnrichCount(panel, row, state, result) {
        var out = row.querySelector('[data-vp-e-count]');
        if (!out) {
            return;
        }
        var shown = result ? Number(result.dataset.vpEShown) : 0;
        var total = result ? Number(result.dataset.vpETotal) : 0;
        if (state !== 'ok' || !shown) {
            out.textContent = '';
            out.classList.add('d-none');
            return;
        }
        var data = panel.dataset;
        if (total > shown) {
            out.textContent = (data.vpENCapped || '%1$s of %2$s')
                .replace('%1$s', shown)
                .replace('%2$s', total);
        } else {
            out.textContent = (shown === 1
                ? (data.vpENOne || '%s element')
                : (data.vpENMany || '%s elements')
            ).replace('%s', shown);
        }
        out.classList.remove('d-none');
    }

    /**
     * Paint one rail row with what happened to it.
     *
     * @param {Element} panel
     * @param {string} name Module name
     * @param {string} state
     * @param {Element} result The answer, where there is one
     */
    function setEnrichState(panel, name, state, result) {
        var row = panel.querySelector(
            '[data-vp-e-row="' + cssEscape(name) + '"]'
        );
        if (!row) {
            return;
        }
        var spec = ENRICH_STATES[state] || ENRICH_UNKNOWN;
        setEnrichCount(panel, row, state, result);

        var dot = row.querySelector('[data-vp-e-dot]');
        if (dot) {
            ENRICH_DOTS.split(' ').forEach(function (cls) {
                dot.classList.remove(cls);
            });
            dot.classList.add(spec.dot);
        }

        var label = row.querySelector('[data-vp-e-state]');
        if (label) {
            ENRICH_CLS.split(' ').forEach(function (cls) {
                label.classList.remove(cls);
            });
            label.classList.add(spec.cls);
            label.textContent = spec.label;
        }
    }

    /**
     * @param {string} value
     * @return {string}
     */
    function cssEscape(value) {
        if (window.CSS && window.CSS.escape) {
            return window.CSS.escape(value);
        }
        return String(value).replace(/["\\]/g, '\\$&');
    }

    /**
     * Ask one module, and put its answer where its brief was.
     *
     * **The only request this page makes that changes anything outside
     * the browser.** It writes nothing to MISP — the endpoint behind it
     * calls the non-writing module query — but it spends the
     * instance's quota and tells whoever operates the module that
     * somebody is looking at this value. So it is a POST, it carries a
     * CSRF token, and it happens on a press and on nothing else.
     *
     * The answer carries the token the next run will spend.
     *
     * **`mode` decides whether it asks anybody anything.** Without it
     * this is a press and the module is always queried, because the
     * profile's reuse window bounds what happens on its own and not
     * what a reader decided. With `auto` the server serves an answer
     * it already holds when that answer is still inside the window,
     * and only queries when it is not — which is what makes both the
     * fan-out and *Show what came back* the same request.
     *
     * @param {Element} panel
     * @param {string} name
     * @param {string} type
     * @param {string} [mode] `auto` to accept a stored answer
     * @return {Promise} Resolves when the pane holds the answer
     */
    function enrichAsk(panel, name, type, mode, all) {
        var slot = panel.querySelector(
            '[data-vp-e-pane="' + cssEscape(name) + '"] [data-vp-e-slot]'
        );
        if (!slot) {
            return Promise.resolve(false);
        }
        setEnrichState(panel, name, 'running');

        var body = new URLSearchParams();
        body.set('data[_Token][key]', panel.dataset.vpEToken || '');
        body.set('data[module]', name);
        body.set('data[type]', type || '');
        if (mode) {
            body.set('data[mode]', mode);
        }
        if (all) {
            body.set('data[all]', '1');
        }

        return fetch(panel.dataset.vpEUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: body.toString()
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error(String(response.status));
                }
                return response.text();
            })
            .then(function (markup) {
                slot.innerHTML = markup;
                initTimeBrushes(slot);
                refreshAllLists(slot);
                var result = slot.querySelector('[data-vp-e-result]');
                setEnrichState(
                    panel,
                    name,
                    result ? result.dataset.vpEStateIs : 'unknown',
                    result
                );
                if (result && result.dataset.vpEToken) {
                    panel.dataset.vpEToken = result.dataset.vpEToken;
                }
                rebuildEnrichAll(panel);
                return true;
            })
            .catch(function () {
                /*
                 * The request failed, which is not the same as a
                 * module failing — the brief stays, so the reader can
                 * press again, and the row says the transport rather
                 * than blaming the module.
                 */
                setEnrichState(panel, name, 'unreachable');
                return false;
            });
    }

    /**
     * Put a button into its running state, and hand back the undo.
     *
     * @param {Element} button
     * @return {Function}
     */
    function enrichBusy(button) {
        var label = button.querySelector('[data-vp-e-label]');
        var icon = button.querySelector('[data-vp-e-icon]');
        var was = label ? label.innerHTML : '';
        var wasDisabled = button.disabled;
        button.disabled = true;
        if (icon) {
            icon.className = 'fas fa-circle-notch fa-spin';
        }
        return function (text) {
            button.disabled = wasDisabled;
            if (icon) {
                icon.className = 'fas fa-play';
            }
            if (label) {
                label.innerHTML = text === undefined ? was : text;
            }
        };
    }

    /**
     * One module, from its own row.
     *
     * @param {Element} button
     */
    function runEnrichModule(button) {
        var panel = button.closest('[data-vp-enrich]');
        if (!panel || button.disabled) {
            return;
        }
        var done = enrichBusy(button);
        var label = button.querySelector('[data-vp-e-label]');
        var mode = button.dataset.vpEMode || null;
        if (label) {
            /*
             * *Show what came back* is not running anything unless the
             * kept answer has gone stale, so it must not claim to be.
             */
            label.textContent = button.dataset.vpEAll === '1' ? 'Loading…'
                : mode === 'auto' ? 'Fetching…' : 'Running…';
        }
        enrichAsk(panel, button.dataset.vpERun, button.dataset.vpEType,
            mode, button.dataset.vpEAll === '1')
            .then(function (ok) {
                // A filled pane replaced this button along with the
                // brief around it; only a failure has one to restore.
                if (!ok) {
                    done();
                }
            });
    }

    /**
     * Every selected module, one after another.
     *
     * **Sequential, and that is the whole design.** A run is one
     * module per request — the queued path that would make a single
     * batched call safe is `POST /attributes/enrich`, which writes —
     * so `Run 3 selected` is three requests. Firing them together
     * would put three simultaneous outbound queries on the instance's
     * quota and give the reader no way to stop after the first
     * answer; one at a time keeps the press honest about what it is
     * doing, and the rail shows it happening row by row.
     *
     * @param {Element} button
     */
    function runEnrichSelected(button) {
        var panel = button.closest('[data-vp-enrich]');
        if (!panel || button.disabled) {
            return;
        }
        var picked = [...panel.querySelectorAll('[data-vp-e-select]')]
            .filter(function (box) { return box.checked; })
            .map(function (box) {
                return {
                    name: box.dataset.vpESelect,
                    type: box.dataset.vpESeltype
                };
            });
        if (!picked.length) {
            return;
        }
        var done = enrichBusy(button);
        var label = button.querySelector('[data-vp-e-label]');

        picked.reduce(function (chain, one, i) {
            return chain.then(function () {
                if (label) {
                    label.textContent = 'Running ' + (i + 1)
                        + ' of ' + picked.length + '…';
                }
                return enrichAsk(panel, one.name, one.type);
            });
        }, Promise.resolve()).then(function () {
            done('Run <span data-vp-e-runcount>0</span> selected');
            panel.querySelectorAll('[data-vp-e-select]')
                .forEach(function (box) { box.checked = false; });
            refreshEnrichTray(panel);
            // The merged pane is the point of running several.
            pickEnrichModule(panel, '__all');
        });
    }

    /**
     * What the current selection commits to.
     *
     * Phase 12 priced it in quota and third-party exposure; **neither
     * has any source** — module introspection carries a name, its
     * accepted types, a description, its kinds and its config keys,
     * and nothing about money or rate limits. So the tray states the
     * one cost that is knowable and is the same thing the reader is
     * agreeing to: how many separate queries leave the building.
     *
     * **Phase 7 made that number per module rather than per
     * selection.** `ModuleLocality` says which modules answer without
     * anything leaving the instance, so three local selections no
     * longer claim three outbound queries. A box reads `0` only for a
     * module known to answer from inside: everything else is presumed
     * to leave, which is what an enrichment module does unless
     * somebody has established otherwise.
     *
     * @param {Element} panel
     */
    function refreshEnrichTray(panel) {
        var boxes = panel.querySelectorAll('[data-vp-e-select]');
        var picked = 0;
        boxes.forEach(function (box) {
            if (box.checked) {
                picked++;
            }
        });

        /*
         * The tray's cost line went in 2026-09-21 — the panel header
         * already says how many of the selection would leave the
         * instance, and every rail row carries its own locality — so
         * what is kept in step here is the two counts and the button.
         */
        setText(panel, '[data-vp-e-picked]', picked);
        setText(panel, '[data-vp-e-runcount]', picked);

        var run = panel.querySelector('[data-vp-e-run-selected]');
        if (run) {
            run.disabled = picked === 0
                || panel.dataset.vpECanrun !== '1';
        }

        var all = panel.querySelector('[data-vp-e-select-all]');
        if (all) {
            all.checked = picked > 0 && picked === boxes.length;
            // Some but not all is its own state, and a box that reads
            // "unchecked" over six ticked rows is a lie about them.
            all.indeterminate = picked > 0 && picked < boxes.length;
        }
    }

    // Rows of one module the merged pane copies, as many as a pane opens on.
    var ENRICH_MERGED_ROWS = 200;

    /**
     * @param {Element} root
     * @param {string} selector
     * @param {boolean} visible
     */
    function showEnrich(root, selector, visible) {
        var target = root.querySelector(selector);
        if (target) {
            target.classList.toggle('d-none', !visible);
        }
    }

    /**
     * Whether a merged-pane cell is still hiding something below its
     * fold.
     *
     * The scrollbar is the only other signal there is, and on a
     * platform that hides scrollbars until they move there is none —
     * so a cell that clips says so with an edge, and stops saying it
     * once the reader reaches the bottom.
     *
     * @param {Element} cell A cloned `.vp-e-shape`
     */
    function markEnrichCellMore(cell) {
        var inner = cell.querySelector(
            ':scope > :not(.vp-e-shape-head)'
        );
        if (!inner) {
            return;
        }
        var more = inner.scrollTop + inner.clientHeight
            < inner.scrollHeight - 2;
        cell.classList.toggle('vp-e-allcell-more', more);
    }

    /**
     * Rebuild the merged pane from the answers already on the page.
     *
     * `E2`'s one addition to the direction it came from: the rail
     * costs the reader cross-module reading and this buys it back. It
     * clones what the module panes hold rather than asking for
     * anything, so it costs no request and **cannot disagree with the
     * panes it merges**.
     *
     * It used to say *this visit*, which was exact while the tab had
     * no memory and became a lie in phase 11: a pane can now hold an
     * answer a colleague fetched yesterday, and the merged view says
     * *open on this page* because that is the span it actually
     * describes. Which of them was queried just now is the profile
     * strip's sentence, not this one's.
     *
     * **And it runs once on load**, because the panes are no longer
     * empty when they arrive: every held answer is drawn into its own
     * pane server-side, so there is something to merge before a reader
     * has pressed anything. That is what lets this be the pane the tab
     * opens on rather than a pane that fills as they work.
     *
     * @param {Element} panel
     */
    function rebuildEnrichAll(panel) {
        var body = panel.querySelector('[data-vp-e-allbody]');
        if (!body) {
            return;
        }
        body.innerHTML = '';
        var groups = 0;
        var elements = 0;
        panel.querySelectorAll('[data-vp-e-pane]').forEach(function (pane) {
            var name = pane.dataset.vpEPane;
            if (name === '__none' || name === '__all') {
                return;
            }
            /*
             * A pane holds one of three things: a held answer's
             * drawing, a run's full result, or a brief nobody has
             * pressed. The first two are merged and the third has
             * nothing to merge — and a result that did not answer is
             * skipped here as it always was, because a failure in the
             * column of answers competes with them.
             */
            var result = pane.querySelector('[data-vp-e-result]');
            if (result && result.dataset.vpEStateIs !== 'ok') {
                return;
            }
            var shapes = pane.querySelectorAll('[data-vp-e-shape]');
            var items = pane.querySelectorAll('[data-vp-e-item]');
            var held = pane.hasAttribute('data-vp-e-held');
            if (!shapes.length && !items.length && !held) {
                return;
            }
            groups++;
            /*
             * The module's name the way this pane has always said it —
             * a heading over its answer, not a bar around it — with
             * the way into its own pane at the end of the line.
             */
            var group = document.createElement('div');
            group.className = 'vp-e-group';
            group.textContent = name;
            var open = document.createElement('button');
            open.type = 'button';
            open.className = 'vp-e-allopen';
            open.dataset.vpEPick = name;
            open.textContent = panel.dataset.vpEAOpen || 'Open';
            group.appendChild(open);
            body.appendChild(group);

            if (!shapes.length && !items.length) {
                /*
                 * An answer nothing draws and nobody has opened. It is
                 * named rather than dropped, because the tab's badge
                 * counts answers in the store and this pane would
                 * otherwise be short by exactly this one.
                 */
                var note = document.createElement('div');
                note.className = 'vp-e-cold-prose vp-e-allnote';
                note.textContent = panel.dataset.vpEARows
                    || 'Answered in rows — open this module to read them.';
                body.appendChild(note);
            }
            if (shapes.length) {
                /*
                 * **The drawings side by side, and each one capped.**
                 * A geolocation is 360px tall and 400 wide and a pane
                 * is a thousand; stacking them spends a screen on two
                 * answers that fit on one row. What the grid cannot
                 * fix is a widget that is long rather than wide —
                 * `circl_passivedns` draws 199 rows — so a cell keeps
                 * its heading and scrolls its own content.
                 */
                var grid = document.createElement('div');
                grid.className = 'vp-e-allgrid';
                shapes.forEach(function (shape) {
                    grid.appendChild(shape.cloneNode(true));
                });
                body.appendChild(grid);
                // A clone keeps the ready flag and not the listeners.
                grid.querySelectorAll('[data-vp-timebrush-ready]')
                    .forEach(function (strip) {
                        delete strip.dataset.vpTimebrushReady;
                    });
                initTimeBrushes(grid);
                refreshAllLists(grid);
                /*
                 * **A drawing that needs the width takes the row.**
                 * Asked of the drawing rather than kept as a list of
                 * shapes, so a renderer added tomorrow answers it
                 * without being registered anywhere: a table of seven
                 * columns is unreadable in a third of a pane and a map
                 * is not.
                 *
                 * Columns rather than measured overflow, because a
                 * table does not overflow — it squeezes, and seven
                 * columns of squeezed text report that they fit.
                 */
                grid.querySelectorAll(':scope > .vp-e-shape')
                    .forEach(function (cell) {
                        var wide = false;
                        cell.querySelectorAll('table').forEach(
                            function (table) {
                                var head = table.querySelector('tr');
                                if (head && head.children.length >= 5) {
                                    wide = true;
                                }
                            }
                        );
                        var inner = cell.querySelector(
                            ':scope > :not(.vp-e-shape-head)'
                        );
                        if (inner
                            && inner.scrollWidth > inner.clientWidth + 2
                        ) {
                            wide = true;
                        }
                        if (wide) {
                            cell.classList.add('vp-e-allwide');
                        }
                    });
                /*
                 * Heights second, and after it is in the document: a
                 * cell that has never been laid out reports no height
                 * at all, so every one of them would claim to fit.
                 */
                grid.querySelectorAll(':scope > .vp-e-shape')
                    .forEach(function (cell) {
                        markEnrichCellMore(cell);
                        var inner = cell.querySelector(
                            ':scope > :not(.vp-e-shape-head)'
                        );
                        if (inner) {
                            inner.addEventListener('scroll', function () {
                                markEnrichCellMore(cell);
                            });
                        }
                    });
            }
            // A pane showing everything kept is not copied whole: the
            // merge would hold its thousands of rows a second time.
            var merged = Array.prototype.slice.call(items, 0, ENRICH_MERGED_ROWS);
            merged.forEach(function (item) {
                elements++;
                body.appendChild(item.cloneNode(true));
            });
            if (items.length > merged.length) {
                var rest = document.createElement('div');
                rest.className = 'vp-e-cold-prose vp-e-allnote';
                rest.textContent = (panel.dataset.vpEAMore
                    || '%s more in this module\'s own pane.').replace(
                    '%s',
                    (items.length - merged.length).toLocaleString('en-US')
                );
                body.appendChild(rest);
            }
        });

        var sub = panel.querySelector('[data-vp-e-allsub]');
        var head = panel.querySelector('[data-vp-e-allhead]');
        if (groups === 0) {
            if (sub) { sub.textContent = 'Nothing open yet'; }
            if (head) {
                head.textContent = 'Nothing has been opened here yet.';
            }
            return;
        }
        /*
         * Two sentences for two states, because they answer different
         * questions. Before anything is opened this pane is every
         * answer the store holds, drawn, and counting *0 elements*
         * over five widgets would be counting the wrong thing. Once
         * rows are open it is the cross-module reading the rail costs,
         * which is what the element count is for.
         */
        if (elements === 0) {
            var drawn = (groups === 1
                ? panel.dataset.vpEADrawnOne
                : panel.dataset.vpEADrawnMany) || '%s answers, drawn here.';
            var label = (groups === 1
                ? panel.dataset.vpEAOne
                : panel.dataset.vpEAMany) || '%s answers';
            if (sub) { sub.textContent = label.replace('%s', groups); }
            if (head) { head.textContent = drawn.replace('%s', groups); }
            return;
        }
        var summary = elements + (elements === 1
            ? ' element across ' : ' elements across ')
            + groups + (groups === 1 ? ' module' : ' modules');
        if (sub) {
            sub.textContent = summary;
        }
        if (head) {
            head.textContent = summary + ', open here.';
        }
    }

    /**
     * Open or shut one object's attribute table.
     *
     * @param {Element} item An object card
     * @param {boolean} open
     */
    function setEnrichFold(item, open) {
        var head = item.querySelector('[data-vp-e-disc]');
        var fold = item.querySelector('[data-vp-e-fold]');
        if (!head || !fold) {
            return;
        }
        head.setAttribute('aria-expanded', open ? 'true' : 'false');
        fold.classList.toggle('d-none', !open);
    }

    /**
     * Fold an object's attributes away.
     *
     * A long answer arrives with its later objects folded —
     * `circl_passivedns` returns two hundred and a pane that opens
     * with two hundred tables is not one a reader finds anything in.
     * What the reader does from there is remembered, so that filtering
     * and then clearing the filter gives them back the pane they had
     * rather than the one the server sent.
     *
     * @param {Element} button
     */
    function toggleEnrichDisc(button) {
        var item = button.closest('[data-vp-e-item]');
        if (!item) {
            return;
        }
        var open = button.getAttribute('aria-expanded') !== 'true';
        setEnrichFold(item, open);
        item.dataset.vpEWas = open ? 'true' : 'false';
    }

    /**
     * Open or shut every object in one answer.
     *
     * @param {Element} button
     */
    function toggleEnrichFoldAll(button) {
        var scope = button.closest('[data-vp-e-result]');
        if (!scope) {
            return;
        }
        var open = button.dataset.vpEFoldAll !== 'close';
        scope.querySelectorAll('[data-vp-e-obj]').forEach(function (obj) {
            setEnrichFold(obj, open);
            obj.dataset.vpEWas = open ? 'true' : 'false';
        });
        button.dataset.vpEFoldAll = open ? 'close' : 'open';

        var label = button.querySelector('[data-vp-e-fold-label]');
        if (label) {
            label.textContent = open
                ? (button.dataset.vpECloseLabel || 'Collapse all')
                : (button.dataset.vpEOpenLabel || 'Expand all');
        }
        var icon = button.querySelector('[data-vp-e-fold-icon]');
        if (icon) {
            icon.classList.toggle('fa-chevron-down', !open);
            icon.classList.toggle('fa-chevron-up', open);
        }
    }

    /**
     * Narrow one answer to the rows that carry a string.
     *
     * **It asks nobody anything.** A capped answer is two hundred
     * elements and the reader is hunting one of them; this hides rows
     * that are already on the page, which is the only kind of
     * narrowing this tab is allowed to do.
     *
     * A match inside a folded object opens it, because a hit the
     * reader cannot see is not a hit they can act on — and clearing
     * the box puts every card back the way they left it rather than
     * the way it arrived.
     *
     * @param {Element} input
     */
    function filterEnrichResult(input) {
        var scope = input.closest('[data-vp-e-result]');
        if (!scope) {
            return;
        }
        var query = input.value.trim().toLowerCase();
        var shown = 0;
        var total = 0;

        scope.querySelectorAll('[data-vp-e-item]').forEach(function (item) {
            total++;
            var hit = query === ''
                || item.textContent.toLowerCase().indexOf(query) !== -1;
            item.classList.toggle('d-none', !hit);
            if (hit) {
                shown++;
            }
            if (item.hasAttribute('data-vp-e-obj')) {
                if (item.dataset.vpEWas === undefined) {
                    var head = item.querySelector('[data-vp-e-disc]');
                    item.dataset.vpEWas = head
                        && head.getAttribute('aria-expanded') === 'true'
                        ? 'true'
                        : 'false';
                }
                setEnrichFold(
                    item,
                    query === '' ? item.dataset.vpEWas === 'true' : hit
                );
            }
        });

        /*
         * A heading counting three objects over none of them is a
         * worse lie than no heading, so a section with nothing left
         * in it goes with its rows — and one that keeps some of them
         * counts what it is showing rather than what it was sent.
         */
        var panel = scope.closest('[data-vp-enrich]');
        var ofFmt = (panel && panel.dataset.vpEOf) || '%1$s of %2$s';
        scope.querySelectorAll('[data-vp-e-section]')
            .forEach(function (section) {
                var items = [...section.querySelectorAll('[data-vp-e-item]')];
                var live = items.filter(function (item) {
                    return !item.classList.contains('d-none');
                }).length;
                section.classList.toggle('d-none', live === 0);

                var head = section.querySelector('[data-vp-e-group-n]');
                if (!head) {
                    return;
                }
                if (head.dataset.vpEGroupAll === undefined) {
                    head.dataset.vpEGroupAll = head.textContent.trim();
                }
                head.textContent = (query === '' || live === items.length)
                    ? head.dataset.vpEGroupAll
                    : ofFmt
                        .replace('%1$s', live)
                        .replace('%2$s', head.dataset.vpEGroupAll);
            });

        var out = scope.querySelector('[data-vp-e-filter-n]');
        if (out) {
            out.textContent = query === ''
                ? ''
                : (out.dataset.vpEFilterFmt || '%1$s of %2$s shown')
                    .replace('%1$s', shown)
                    .replace('%2$s', total);
        }
    }

    /*
     * The type a value nobody holds is matched on. The tab's header names
     * it in a chip that opens a menu of types; when nothing was read, the
     * same list sits in the page instead. Picking reloads the tab with
     * `?as=` and sends nothing to any module.
     *
     * The menu never scrolls: it widens into columns, then scrolls the
     * page to make room, then opens upwards, and only then drops rows
     * with a "+N more" line.
     */
    var etOpen = null;
    var etRefocus = false;
    var etBound = false;
    var ET_GAP = 6;
    var ET_EDGE = 12;

    function etMono(text) {
        return '<span class="vp-et-mono">' + tlEscape(text) + '</span>';
    }

    function etMark(text, query) {
        var at = query ? text.toLowerCase().indexOf(query) : -1;
        if (at === -1) {
            return tlEscape(text);
        }
        return tlEscape(text.slice(0, at)) + '<mark class="vp-et-hl">'
            + tlEscape(text.slice(at, at + query.length)) + '</mark>'
            + tlEscape(text.slice(at + query.length));
    }

    function etModules(button) {
        try {
            return JSON.parse(button.dataset.vpEtModules || '[]');
        } catch (e) {
            return [];
        }
    }

    function etJson(value) {
        try {
            return JSON.parse(value || '[]');
        } catch (e) {
            return [];
        }
    }

    function etVisible(grid) {
        return Array.prototype.filter.call(grid.children, function (b) {
            return !b.hidden && !b.hasAttribute('data-vp-et-cut');
        });
    }

    function etLayout(ctx, cols) {
        ctx.pop.classList.toggle('is-cols', cols > 1);
        ctx.pop.querySelectorAll('.vp-et-grid').forEach(function (grid) {
            grid.style.setProperty('--vp-et-cols', cols);
            grid.style.setProperty('--vp-et-rows',
                Math.max(1, Math.ceil(etVisible(grid).length / cols)));
        });
    }

    function etSetMore(ctx, grid) {
        var more = grid.parentNode.querySelector('[data-vp-et-more]');
        if (!more) {
            return;
        }
        var cut = grid.querySelectorAll('[data-vp-et-cut]').length;
        more.hidden = !cut || grid.hidden;
        more.textContent = !cut ? '' : (etVisible(grid).length
            ? ctx.pop.dataset.vpEtMore
            : ctx.pop.dataset.vpEtMoreAll).replace('%d', cut);
    }

    function etUncut(ctx) {
        ctx.pop.querySelectorAll('[data-vp-et-cut]').forEach(function (b) {
            b.removeAttribute('data-vp-et-cut');
        });
        ctx.pop.querySelectorAll('.vp-et-grid').forEach(function (grid) {
            etSetMore(ctx, grid);
        });
    }

    // Last resort: drop whole rows, the least telling group first.
    function etCutToFit(ctx, room, cols) {
        var order = ['.vp-et-sec-fails', '.vp-et-sec-any', '.vp-et-sec-fits'];
        function cutRow(grid, floor) {
            var shown = etVisible(grid);
            var rows = Math.ceil(shown.length / cols);
            if (rows <= floor) {
                return false;
            }
            shown.slice((rows - 1) * cols).forEach(function (b) {
                b.setAttribute('data-vp-et-cut', '');
            });
            etSetMore(ctx, grid);
            etLayout(ctx, cols);
            return true;
        }
        [1, 0].forEach(function (floor) {
            order.forEach(function (sel) {
                var grid = ctx.pop.querySelector(
                    sel + ':not([hidden]) .vp-et-grid:not([hidden])'
                );
                while (grid && ctx.pop.offsetHeight > room
                    && cutRow(grid, floor)) {
                    // keep cutting
                }
            });
        });
    }

    // How far down the viewport the navbar and any pinned bar reach.
    function etTopCover(x) {
        var y = 0;
        etPointer(true);
        for (var i = 0; i < 4; i++) {
            var el = document.elementFromPoint(x, y + 1);
            while (el && el !== document.body) {
                var pos = getComputedStyle(el).position;
                if (pos === 'fixed' || pos === 'sticky') {
                    break;
                }
                el = el.parentElement;
            }
            if (!el || el === document.body) {
                break;
            }
            var bottom = el.getBoundingClientRect().bottom;
            if (bottom <= y + 1) {
                break;
            }
            y = bottom;
        }
        etPointer(false);
        return y;
    }

    function etPointer(off) {
        document.querySelectorAll('.vp-et-pop').forEach(function (p) {
            p.style.pointerEvents = off ? 'none' : '';
        });
    }

    // Scroll the chip up under the pinned bars to make room below it.
    function etMakeRoom(ctx, need, cover) {
        var a = ctx.chip.getBoundingClientRect();
        var doc = document.documentElement;
        var by = Math.min(need, a.top - cover - ET_EDGE,
            doc.scrollHeight - window.innerHeight - window.scrollY);
        if (by <= 8) {
            return false;
        }
        window.scrollBy({top: Math.ceil(by), behavior: 'instant'});
        // A bar that pins once scrolled past now covers more.
        a = ctx.chip.getBoundingClientRect();
        var over = etTopCover(a.left + a.width / 2) + ET_EDGE - a.top;
        if (over > 0) {
            window.scrollBy({top: -Math.ceil(over), behavior: 'instant'});
        }
        return true;
    }

    function etFit(ctx, mayScroll) {
        var pop = ctx.pop;
        var rem = parseFloat(
            getComputedStyle(document.documentElement).fontSize
        ) || 16;
        etUncut(ctx);
        if (ctx.inline) {
            // Sized on the whole list, so the box keeps its width while typing.
            var widest = 0;
            pop.querySelectorAll('.vp-et-grid').forEach(function (grid) {
                widest = Math.max(widest, grid.children.length);
            });
            var fitCols = Math.max(1, Math.floor(
                (pop.parentNode.clientWidth - 58) / (17 * rem + 4)
            ));
            etLayout(ctx,
                Math.max(1, Math.min(fitCols, Math.ceil(widest / 3))));
            return;
        }
        if (!pop.classList.contains('show')) {
            return;
        }
        var colW = 16 * rem;
        pop.style.top = '0px';
        var frame = pop.offsetParent || ctx.root;
        var box = frame.getBoundingClientRect();
        var card = ctx.root.getBoundingClientRect();
        var a = ctx.chip.getBoundingClientRect();
        var cover = etTopCover(a.left + a.width / 2);
        var vh = window.innerHeight;
        var maxW = card.width - 2 * ET_EDGE;
        var baseW = Math.min(maxW, 27 * rem);
        var maxCols = Math.max(1, Math.floor((maxW - 10) / colW));
        var below = vh - a.bottom - ET_GAP - ET_EDGE;
        var above = a.top - cover - ET_GAP - ET_EDGE;

        function tryCols(room) {
            var cols = 1;
            for (;;) {
                pop.style.width = (cols === 1
                    ? baseW
                    : Math.min(maxW, cols * colW + 10)) + 'px';
                etLayout(ctx, cols);
                if (pop.offsetHeight <= room || cols >= maxCols) {
                    return cols;
                }
                cols++;
            }
        }
        var side = 'below';
        var room = below;
        var cols = tryCols(below);
        if (pop.offsetHeight > below && mayScroll
            && etMakeRoom(ctx, pop.offsetHeight - below, cover)
        ) {
            box = frame.getBoundingClientRect();
            card = ctx.root.getBoundingClientRect();
            a = ctx.chip.getBoundingClientRect();
            cover = etTopCover(a.left + a.width / 2);
            below = vh - a.bottom - ET_GAP - ET_EDGE;
            above = a.top - cover - ET_GAP - ET_EDGE;
            room = below;
            cols = tryCols(below);
        }
        if (pop.offsetHeight > below && above > below) {
            side = 'above';
            room = above;
            cols = tryCols(above);
        }
        if (pop.offsetHeight > room) {
            etCutToFit(ctx, room, cols);
        }
        var width = pop.offsetWidth;
        var left = Math.max(card.left + ET_EDGE,
            Math.min(a.left - 6, card.right - ET_EDGE - width));
        var top = side === 'below'
            ? a.bottom + ET_GAP
            : a.top - ET_GAP - pop.offsetHeight;
        pop.style.left = Math.round(left - box.left) + 'px';
        pop.style.top = Math.round(top - box.top) + 'px';
        pop.classList.toggle('is-above', side === 'above');
        if (ctx.active && (ctx.active.hidden
            || ctx.active.hasAttribute('data-vp-et-cut'))
        ) {
            etSetActive(ctx, null);
        }
    }

    function etItems(ctx) {
        return Array.prototype.filter.call(
            ctx.pop.querySelectorAll('.vp-et-opt, .vp-et-fold'),
            function (b) {
                if (b.hidden || b.hasAttribute('data-vp-et-cut')
                    || (b.classList.contains('vp-et-fold') && ctx.query)
                ) {
                    return false;
                }
                var sec = b.closest('.vp-et-sec');
                var grid = b.closest('.vp-et-grid');
                return !(sec && sec.hidden) && !(grid && grid.hidden);
            }
        );
    }

    // The footer names the modules a row stands for, on two lines at most.
    function etFillPeek(ctx, lead, names) {
        var peek = ctx.peek;
        var line = parseFloat(getComputedStyle(peek).lineHeight) || 18;
        for (var k = names.length; k >= 0; k--) {
            peek.innerHTML = lead + ' '
                + names.slice(0, k).map(etMono).join(', ')
                + (k < names.length ? ' <span class="vp-et-peek-more">+'
                    + (names.length - k) + '</span>' : '');
            if (peek.scrollHeight <= 2 * line + 2 || k === 0) {
                return;
            }
        }
    }

    function etPeek(ctx) {
        var b = ctx.active;
        var data = ctx.pop.dataset;
        if (!b) {
            ctx.peek.textContent = data.vpEtPeekIdle;
        } else if (b.classList.contains('vp-et-fold')) {
            ctx.peek.textContent = data.vpEtPeekFold;
        } else if (b.hasAttribute('data-vp-et-reset')) {
            var read = ctx.read.map(etMono).join(', ');
            etFillPeek(ctx, (ctx.source === 'read'
                ? tlEscape(data.vpEtPeekType)
                : tlEscape(data.vpEtPeekBack)).replace('%s', read),
                etModules(b));
        } else {
            etFillPeek(ctx, tlEscape(data.vpEtPeekType)
                .replace('%s', etMono(b.dataset.vpEtType)), etModules(b));
        }
    }

    function etSetActive(ctx, b) {
        if (ctx.active) {
            ctx.active.classList.remove('is-active');
        }
        ctx.active = b;
        if (b) {
            b.classList.add('is-active');
            ctx.input.setAttribute('aria-activedescendant', b.id);
        } else {
            ctx.input.removeAttribute('aria-activedescendant');
        }
        etPeek(ctx);
    }

    function etSetFold(ctx) {
        var fold = ctx.pop.querySelector('[data-vp-et-fold]');
        var grid = ctx.pop.querySelector('[data-vp-et-failgrid]');
        if (!fold || !grid) {
            return;
        }
        var open = !!ctx.query || ctx.failsOpen;
        fold.setAttribute('aria-expanded', open ? 'true' : 'false');
        fold.classList.toggle('is-forced', !!ctx.query);
        grid.hidden = !open;
    }

    function etSearch(ctx, mayScroll) {
        var raw = ctx.input.value.trim();
        var q = raw.toLowerCase();
        ctx.query = q;
        var shown = 0;
        ctx.pop.querySelectorAll('.vp-et-opt[data-vp-et-type]')
            .forEach(function (b) {
                var type = b.dataset.vpEtType;
                var nameHit = !!q && type.toLowerCase().indexOf(q) !== -1;
                var mods = q ? etModules(b).filter(function (name) {
                    return name.toLowerCase().indexOf(q) !== -1;
                }) : [];
                var show = !q || nameHit || mods.length > 0;
                b.hidden = !show;
                b.querySelector('[data-vp-et-name]').innerHTML =
                    etMark(type, nameHit ? q : '');
                var hits = b.querySelector('[data-vp-et-hits]');
                hits.hidden = !mods.length;
                hits.innerHTML = mods.length
                    ? '<i class="fas fa-plug" aria-hidden="true"></i>'
                        + mods.map(function (name) {
                            return '<span class="vp-et-hit">'
                                + etMark(name, q) + '</span>';
                        }).join('<span class="vp-et-hits-sep"'
                            + ' aria-hidden="true">·</span>')
                    : '';
                if (show) {
                    shown++;
                }
            });
        ctx.pop.querySelectorAll('.vp-et-sec').forEach(function (sec) {
            if (sec.classList.contains('vp-et-sec-read')) {
                sec.hidden = !!q;
                return;
            }
            var visible = Array.prototype.filter.call(
                sec.querySelectorAll('.vp-et-opt'),
                function (b) { return !b.hidden; }
            ).length;
            sec.hidden = !visible;
            var n = sec.querySelector('[data-vp-et-n]');
            if (n) {
                n.textContent = visible;
            }
        });
        var nothing = ctx.pop.querySelector('[data-vp-et-nothing]');
        nothing.hidden = !q || shown > 0;
        nothing.textContent = q && !shown
            ? ctx.pop.dataset.vpEtNothing.replace('%s', raw)
            : '';
        etSetFold(ctx);
        etSetActive(ctx, null);
        etFit(ctx, mayScroll);
        if (q && shown) {
            etSetActive(ctx, etItems(ctx)[0] || null);
        }
    }

    function etToggleFold(ctx) {
        if (ctx.query) {
            return;
        }
        ctx.failsOpen = !ctx.failsOpen;
        etSetFold(ctx);
        etFit(ctx, true);
        etSetActive(ctx, ctx.pop.querySelector('[data-vp-et-fold]'));
    }

    function etMove(ctx, step) {
        var items = etItems(ctx);
        if (!items.length) {
            return;
        }
        var i = items.indexOf(ctx.active);
        i = i === -1
            ? (step > 0 ? 0 : items.length - 1)
            : Math.max(0, Math.min(items.length - 1, i + step));
        etSetActive(ctx, items[i]);
    }

    function etKey(ctx, e) {
        var steps = {ArrowDown: 1, ArrowUp: -1, PageDown: 8, PageUp: -8};
        if (steps[e.key]) {
            e.preventDefault();
            etMove(ctx, steps[e.key]);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (ctx.active) {
                etActivate(ctx, ctx.active, true);
            }
        } else if (e.key === 'Escape') {
            if (!ctx.inline) {
                e.preventDefault();
                e.stopPropagation();
                etClose(ctx, true);
            } else if (ctx.input.value) {
                e.preventDefault();
                ctx.input.value = '';
                etSearch(ctx);
            }
        }
    }

    function etOpenMenu(ctx) {
        if (etOpen && etOpen !== ctx) {
            etClose(etOpen, false);
        }
        etOpen = ctx;
        ctx.pop.classList.add('show');
        ctx.chip.setAttribute('aria-expanded', 'true');
        ctx.input.value = '';
        // A failing pick is opened to view, or the reader cannot see it.
        ctx.failsOpen = ctx.source === 'picked' && ctx.failing;
        etSearch(ctx, true);
        ctx.input.focus({preventScroll: true});
    }

    function etClose(ctx, focusChip) {
        if (!ctx || ctx.inline) {
            return;
        }
        ctx.pop.classList.remove('show');
        ctx.chip.setAttribute('aria-expanded', 'false');
        if (etOpen === ctx) {
            etOpen = null;
        }
        if (focusChip) {
            ctx.chip.focus({preventScroll: true});
        }
    }

    function etReload(ctx, as) {
        var container = ctx.root.closest('[data-url]');
        if (!container || typeof window.reloadAjaxTabIndex !== 'function') {
            return;
        }
        var parts = container.dataset.url.split('?');
        var query = new URLSearchParams(parts[1] || '');
        if (as) {
            query.set('as', as);
        } else {
            query.delete('as');
        }
        var rest = query.toString();
        window.reloadAjaxTabIndex(container,
            parts[0] + (rest ? '?' + rest : ''));
    }

    // Focus follows a keyboard pick across the reload; a click leaves it be.
    function etSwitching(ctx, label, byKey) {
        etRefocus = !!byKey;
        if (ctx.chip) {
            ctx.chip.classList.add('is-switching');
            ctx.chip.innerHTML = '<i class="fas fa-circle-notch fa-spin'
                + ' vp-et-chip-spin" aria-hidden="true"></i>'
                + '<span class="vp-et-chip-seg"><span class="vp-et-chip-type">'
                + tlEscape(label) + '</span><span class="vp-et-chip-basis">'
                + tlEscape(ctx.chip.dataset.vpEtSwitching) + '</span></span>';
        }
        if (ctx.inline) {
            ctx.pop.classList.add('is-switching');
        }
    }

    function etActivate(ctx, b, byKey) {
        if (b.classList.contains('vp-et-fold')) {
            etToggleFold(ctx);
            return;
        }
        if (b.hasAttribute('data-vp-et-reset')) {
            etClose(ctx, ctx.source === 'read' && !!byKey);
            if (ctx.source !== 'read') {
                etSwitching(ctx, ctx.read.join(', '), byKey);
                etReload(ctx, null);
            }
            return;
        }
        var type = b.dataset.vpEtType;
        var soleRead = ctx.read.length === 1 && ctx.read[0] === type;
        var already = (ctx.source === 'picked' && ctx.lead.length === 1
                && ctx.lead[0] === type)
            || (ctx.source === 'read' && soleRead);
        etClose(ctx, already && !!byKey);
        if (already) {
            return;
        }
        etSwitching(ctx, type, byKey);
        // The parser's own single type is not a pick: going there is back.
        etReload(ctx, soleRead ? null : type);
    }

    function etWire(ctx) {
        var pop = ctx.pop;
        pop.vpEtCtx = ctx;
        ctx.input = pop.querySelector('.vp-et-input');
        ctx.peek = pop.querySelector('[data-vp-et-peek]');
        ctx.input.addEventListener('input', function () { etSearch(ctx); });
        ctx.input.addEventListener('keydown', function (e) { etKey(ctx, e); });
        pop.addEventListener('click', function (e) {
            var b = e.target.closest('.vp-et-opt, .vp-et-fold');
            if (b && pop.contains(b)) {
                etActivate(ctx, b, false);
            }
        });
        pop.addEventListener('mousemove', function (e) {
            var b = e.target.closest('.vp-et-opt, .vp-et-fold');
            if (b && b !== ctx.active && etItems(ctx).indexOf(b) !== -1) {
                etSetActive(ctx, b);
            }
        });
        pop.addEventListener('mouseleave', function () {
            if (!ctx.query) {
                etSetActive(ctx, null);
            }
        });
        // A click on a row keeps the focus in the search field.
        pop.addEventListener('mousedown', function (e) {
            if (e.target.closest('.vp-et-opt, .vp-et-fold')) {
                e.preventDefault();
            }
        });
    }

    function etBindDocument() {
        if (etBound) {
            return;
        }
        etBound = true;
        /*
         * Bootstrap's dropdown handler takes every Escape inside a
         * .dropdown-menu in the capture phase on `document` and throws
         * looking for a toggle this menu does not have. Window capture
         * runs first, so Escape is handled here and goes no further.
         */
        window.addEventListener('keydown', function (e) {
            var pop = e.key === 'Escape' && e.target.closest
                ? e.target.closest('.vp-et-pop')
                : null;
            if (pop && pop.vpEtCtx) {
                e.stopPropagation();
                etKey(pop.vpEtCtx, e);
            }
        }, true);
        document.addEventListener('mousedown', function (e) {
            if (etOpen && !etOpen.pop.contains(e.target)
                && !etOpen.chip.contains(e.target)
            ) {
                etClose(etOpen, false);
            }
        });
        document.addEventListener('focusin', function (e) {
            if (etOpen && !etOpen.pop.contains(e.target)
                && !etOpen.chip.contains(e.target)
            ) {
                etClose(etOpen, false);
            }
        });
        window.addEventListener('resize', function () {
            if (etOpen) {
                etFit(etOpen);
            }
            document.querySelectorAll('[data-vp-et-inline]')
                .forEach(function (pop) {
                    if (pop.vpEtCtx) {
                        etFit(pop.vpEtCtx);
                    }
                });
        });
    }

    /**
     * @param {Element|Document} root
     */
    function initEnrichmentTyping(root) {
        var panels = root.querySelectorAll
            ? root.querySelectorAll('[data-vp-enrich][data-vp-et]')
            : [];
        panels.forEach(function (panel) {
            if (panel.dataset.vpEtBound) {
                return;
            }
            panel.dataset.vpEtBound = '1';
            etBindDocument();
            if (etOpen && !etOpen.root.isConnected) {
                etOpen = null;
            }
            var base = {
                root: panel,
                source: panel.dataset.vpEtSource,
                read: etJson(panel.dataset.vpEtRead),
                lead: etJson(panel.dataset.vpEtLead),
                failing: panel.dataset.vpEtFailing === '1'
            };
            var focus = null;
            var chip = panel.querySelector('[data-vp-et-chip]');
            if (chip) {
                var ctx = Object.assign({}, base, {
                    chip: chip,
                    pop: chip.nextElementSibling,
                    inline: false,
                    failsOpen: false
                });
                etWire(ctx);
                chip.addEventListener('click', function () {
                    if (ctx.pop.classList.contains('show')) {
                        etClose(ctx, false);
                    } else {
                        etOpenMenu(ctx);
                    }
                });
                chip.addEventListener('keydown', function (e) {
                    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp')
                        && !ctx.pop.classList.contains('show')
                    ) {
                        e.preventDefault();
                        etOpenMenu(ctx);
                    }
                });
                var back = panel.querySelector('[data-vp-et-back]');
                if (back) {
                    back.addEventListener('click', function (e) {
                        etSwitching(ctx, ctx.read.join(', '), e.detail === 0);
                        etReload(ctx, null);
                    });
                }
                focus = chip;
            }
            var inline = panel.querySelector('[data-vp-et-inline]');
            if (inline) {
                var ictx = Object.assign({}, base, {
                    chip: null,
                    pop: inline,
                    inline: true,
                    failsOpen: !inline.querySelector(
                        '.vp-et-sec-fits:not([hidden]),'
                        + ' .vp-et-sec-any:not([hidden])'
                    )
                });
                etWire(ictx);
                etSearch(ictx);
                focus = focus || ictx.input;
            }
            if (etRefocus && focus) {
                etRefocus = false;
                focus.focus({preventScroll: true});
            }
        });
    }

    /**
     * The tab arrives at rest: every pane rendered, every row *Not
     * asked*, and — since phase 7 — whatever the reader's Analyst
     * Profile named for this value's types already ticked. This
     * settles the tray to match, which on a profile that declares
     * nothing is the same "nothing selected" it always was.
     *
     * @param {Element} root
     */
    function initEnrichment(root) {
        var panels = root.querySelectorAll
            ? root.querySelectorAll('[data-vp-enrich]')
            : [];
        panels.forEach(function (panel) {
            refreshEnrichTray(panel);
            /*
             * The merged pane, built from the answers the server drew
             * into the panes. No request and no state of its own — it
             * is the same clone the tab has always done, run once
             * before the reader has touched anything.
             */
            rebuildEnrichAll(panel);
            sizeEnrichPane(panel);
            enrichAutoFire(panel);
            openLinkedEnrichModule(panel);
        });
        if (panels.length && !window.__vpEnrichSized) {
            window.__vpEnrichSized = true;
            window.addEventListener('resize', function () {
                document.querySelectorAll('[data-vp-enrich]')
                    .forEach(sizeEnrichPane);
            });
        }
    }

    /**
     * The module a link on this page asked for before the Enrichment tab
     * had loaded (`showEnrichModule`).
     */
    var enrichModuleWanted = null;

    /**
     * Open the module a link named (`?module=` from the hover card, or a
     * module in the Overview strip's panel), with its answer drawn.
     *
     * @param {Element} panel
     */
    function openLinkedEnrichModule(panel) {
        if (enrichModuleWanted !== null) {
            var wanted = enrichModuleWanted;
            enrichModuleWanted = null;
            openEnrichModule(panel, wanted);
            return;
        }
        var name = new URLSearchParams(window.location.search).get('module');
        if (!name || panel.dataset.vpELinked === '1') {
            return;
        }
        if (openEnrichModule(panel, name)) {
            panel.dataset.vpELinked = '1';
        }
    }

    /**
     * Switch to the Enrichment tab and open one module there, without
     * leaving the page.
     *
     * @param {string} name
     */
    function showEnrichModule(name) {
        var panel = document.querySelector('[data-vp-enrich]');
        var tab = document.querySelector('.nav-link[href="#tab-enrichment"]');
        if (!panel) {
            enrichModuleWanted = name;
        } else if (tab && !tab.classList.contains('active')) {
            tab.addEventListener('shown.bs.tab', function () {
                openEnrichModule(panel, name);
            }, {once: true});
        } else {
            openEnrichModule(panel, name);
        }
        window.location.hash = '#tab-enrichment';
    }

    /**
     * Pick a module on the Enrichment tab with its answer drawn.
     *
     * A module the auto-fire is already fetching fills its own pane;
     * any other is shown from the store, which asks nobody anything. A
     * module with nothing stored is only selected — a link never runs
     * one.
     *
     * @param {Element} panel
     * @param {string} name
     * @return {boolean} Whether the tab has a pane for it
     */
    function openEnrichModule(panel, name) {
        var pane = null;
        panel.querySelectorAll('[data-vp-e-pane]').forEach(function (p) {
            if (p.dataset.vpEPane === name) {
                pane = p;
            }
        });
        if (!pane) {
            return false;
        }
        pickEnrichModule(panel, name);
        var row = panel.querySelector(
            '[data-vp-e-row="' + cssEscape(name) + '"]'
        );
        if (row) {
            row.scrollIntoView({block: 'nearest'});
        }

        var plan;
        try {
            plan = JSON.parse(panel.dataset.vpEAuto || '[]');
        } catch (e) {
            plan = [];
        }
        var fetching = Array.isArray(plan) && plan.some(function (one) {
            return one.module === name;
        });
        if (fetching) {
            return true;
        }
        var show = pane.querySelector(
            '[data-vp-e-run][data-vp-e-mode="stored"]'
        );
        if (show && !show.disabled) {
            runEnrichModule(show);
        }
        return true;
    }

    /**
     * Fit the answer to what is left of the screen.
     *
     * **So that `Run n selected` is on it.** The rail pins that button
     * to its own foot and the split stretches both columns to the
     * taller of them, so an answer of any length used to push the
     * button a page-scroll below the answer it applies to. The pane
     * scrolls instead, and what it is capped at is whatever the
     * viewport has left under it — which is a measurement and not a
     * constant, because what sits above this tab on the page is a
     * header, a fact strip and a profile block of no fixed height.
     *
     * The stylesheet carries a viewport-relative cap for the moment
     * before this runs and for the case where it does not. Below the
     * breakpoint the two columns stack and neither is capped: a
     * scroller inside a scroller on a phone is two thumbs' worth of
     * the same gesture.
     *
     * @param {Element} panel
     */
    function sizeEnrichPane(panel) {
        var pane = panel.querySelector('.vp-e-pane');
        if (!pane) {
            return;
        }
        if (window.innerWidth < 992) {
            pane.style.maxHeight = '';
            return;
        }
        pane.style.maxHeight = '';
        var top = pane.getBoundingClientRect().top;
        var room = window.innerHeight - top - 16;
        pane.style.maxHeight = Math.round(Math.max(416, room)) + 'px';
    }

    /**
     * Fire the modules the profile marked `auto`.
     *
     * **The one place on this page where a query leaves the instance
     * without a press**, and it takes two separate acts to reach: an
     * analyst marking a module `auto` in their Analyst Profile, and an
     * administrator setting
     * `Plugin.ValueIntelligence_enrichment_auto_run` to something other
     * than off. The server does both checks — this list arrives empty
     * unless they passed, and the endpoint decides again when each
     * request lands.
     *
     * **Concurrent, where `Run n selected` is sequential**, and the
     * difference is intent rather than inconsistency. A reader ticking
     * three boxes chose them one at a time and may want to stop after
     * the first answer, so those go one at a time and the button
     * counts them off. These were chosen in advance, by a profile, for
     * every value of this type — nobody is watching them go, and what
     * the reader wants is the fast module readable while the slow one
     * is still running.
     *
     * Five at a time. It is what the shipped default's widest type
     * declares, so the common case is one wave, and it is a bound on
     * one reader rather than on the instance: each request holds a
     * PHP worker for up to `Plugin.Enrichment_timeout`.
     *
     * Parallelism here is real only because `viewEnrichmentRun` closes
     * the session — PHP's file session lock would otherwise serialise
     * these into precisely the queue they exist not to be.
     *
     * @param {Element} panel
     */
    function enrichAutoFire(panel) {
        var plan;
        try {
            plan = JSON.parse(panel.dataset.vpEAuto || '[]');
        } catch (e) {
            plan = [];
        }
        if (!Array.isArray(plan) || !plan.length) {
            return;
        }
        if (panel.dataset.vpEAutoDone === '1') {
            return;
        }
        /*
         * Once per panel. A tab re-shown from cache must not re-fire
         * what it already fired, and the marker is on the element so
         * it dies with the fragment rather than outliving it.
         */
        panel.dataset.vpEAutoDone = '1';

        /*
         * The merged pane, because several answers are landing and
         * picking one of them would be picking by latency. Set before
         * the first response so the reader watches them arrive rather
         * than being moved once they have.
         */
        pickEnrichModule(panel, '__all');

        var queue = plan.slice();
        var width = parseInt(panel.dataset.vpEAutoMax, 10) || 5;
        var lanes = Math.min(width, queue.length);

        var next = function () {
            var one = queue.shift();
            if (!one) {
                return Promise.resolve();
            }
            return enrichAsk(panel, one.module, one.type, 'auto')
                .then(next);
        };
        for (var i = 0; i < lanes; i++) {
            next();
        }
    }

    /**
     * The Overview's enrichment panel, once it has landed.
     *
     * @param {Element} root
     */
    function initEnrichPanel(root) {
        var panels = root.querySelectorAll
            ? root.querySelectorAll('[data-vp-ebadge]')
            : [];
        panels.forEach(function (panel) {
            initEnrichDrawer(panel);
            enrichPanelFire(panel);
        });
    }

    /**
     * A drawn cell of the strip opens its full drawing under the row
     * (tile-drawer.js), the way a tile of the event page's object views
     * does.
     *
     * @param {Element} panel
     */
    function initEnrichDrawer(panel) {
        if (!window.TileDrawer || panel.vpEbDrawer) {
            return;
        }
        panel.vpEbDrawer = new window.TileDrawer(panel, {
            panelId: 'vp-eb-drawer',
            anchor: function (tile) {
                return tile.closest('[data-vp-eb-strip]');
            },
            onClick: function (event) {
                var link = event.target.closest('a[data-vp-eb-open]');
                if (!link || event.button !== 0 || event.ctrlKey
                    || event.metaKey || event.shiftKey || event.altKey
                ) {
                    return false;
                }
                event.preventDefault();
                showEnrichModule(link.dataset.vpEbOpen);
                return true;
            },
            onOpen: function (drawer) {
                initTimeBrushes(drawer);
                refreshAllLists(drawer);
            }
        });
        followEnrichStrip(panel);
    }

    /**
     * The notch follows its cell while the row scrolls sideways.
     *
     * @param {Element} panel
     */
    function followEnrichStrip(panel) {
        var strip = panel.querySelector('[data-vp-eb-strip]');
        if (strip) {
            strip.addEventListener('scroll', function () {
                panel.vpEbDrawer.notch();
            }, {passive: true});
        }
    }

    /**
     * Fire the modules the profile marked `auto`, into the Overview's
     * chip slots.
     *
     * `enrichAutoFire`'s counterpart on the other surface, and
     * deliberately the same request: the plan arrives on the panel's
     * markup, five go at a time, and each one is `mode=auto` at an
     * endpoint that decides the gate, the reuse window and the
     * in-flight claim again when it lands. The two differ in which
     * element comes back.
     *
     * **A shorter list than the tab's.** The tab sends its `fresh`
     * dispositions as well, because a pane cannot render an answer it
     * never fetched; a chip slot already holds one, drawn out of the
     * store by the render that produced this plan. So only `fire` is
     * here, and on an instance with the gate off the plan is empty and
     * nothing leaves the browser.
     *
     * @param {Element} panel
     */
    function enrichPanelFire(panel) {
        var plan;
        try {
            plan = JSON.parse(panel.dataset.vpEbFire || '[]');
        } catch (e) {
            plan = [];
        }
        if (!Array.isArray(plan) || !plan.length) {
            return;
        }
        /*
         * Once per panel. A panel re-shown from cache must not re-fire
         * what it already fired, and the marker is on the element so
         * it dies with the fragment rather than outliving it.
         */
        if (panel.dataset.vpEbDone === '1') {
            return;
        }
        panel.dataset.vpEbDone = '1';

        var queue = plan.slice();
        var width = parseInt(panel.dataset.vpEbMax, 10) || 5;
        var lanes = Math.min(width, queue.length);

        var next = function () {
            var one = queue.shift();
            if (!one) {
                return Promise.resolve();
            }
            return enrichBadgeAsk(panel, one.module, one.type)
                .then(next);
        };
        var running = [];
        for (var i = 0; i < lanes; i++) {
            running.push(next());
        }
        /*
         * Once, when they have all landed, and never per answer. A
         * widget is built from every answer the store holds, so
         * redrawing it after each one would be N requests to draw the
         * same row N times, each of them already out of date.
         */
        Promise.all(running).then(function () {
            enrichStripRedraw(panel);
        });
    }

    /**
     * Redraw the strip from the store, now that the modules that fired
     * on arrival have answered.
     *
     * **The panel's own endpoint, and only the strip taken out of it.**
     * The rows below have been updated one at a time as each answer
     * landed, and replacing them with a second render would undo that
     * — and would move a reader's eye for no gain, because they have
     * already seen those change.
     *
     * A failure is silence: the row on the page is what the store held
     * when it was drawn, which is true and merely older than it could
     * be. Blanking it because a second request failed would replace an
     * honest row with nothing.
     *
     * @param {Element} panel
     */
    function enrichStripRedraw(panel) {
        var url = panel.dataset.vpEbPanel;
        var strip = panel.querySelector('[data-vp-eb-strip]');
        if (!url || !strip) {
            return;
        }
        fetch(url, {
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        }).then(function (response) {
            return response.ok ? response.text() : null;
        }).then(function (html) {
            if (html === null) {
                return;
            }
            var frame = document.createElement('div');
            frame.innerHTML = html;
            var fresh = frame.querySelector('[data-vp-eb-strip]');
            var drawer = panel.vpEbDrawer;
            var opened = drawer && drawer.isOpen()
                ? drawer.opened.dataset.vpEbShape
                : null;
            if (fresh) {
                strip.replaceWith(fresh);
                if (drawer) {
                    followEnrichStrip(panel);
                    // The panel stays open on the same shape's new cell.
                    var again = opened === null ? null : fresh.querySelector(
                        '[data-td-tile][data-vp-eb-shape="'
                        + cssEscape(opened) + '"]'
                    );
                    if (again) {
                        drawer.open(again, {force: true, stay: true});
                    } else if (opened !== null) {
                        drawer.close(false);
                    }
                }
                /*
                 * The rows the widgets have just taken over. A module
                 * that fired kept a chip row while it was answering,
                 * and now its answer is drawn above — the chip would
                 * be the same answer twice, so the row goes and the
                 * count is restated without it.
                 */
                enrichPanelDrawn(panel).forEach(function (name) {
                    var row = panel.querySelector(
                        '[data-vp-eb-row="' + cssEscape(name) + '"]'
                    );
                    if (row) {
                        row.remove();
                    }
                });
                enrichPanelCount(panel);
            } else {
                /*
                 * Nothing drawable came back, which is a real outcome:
                 * every module that fired answered with something no
                 * renderer claims. The waiting cell must not be left
                 * spinning over it.
                 */
                strip.remove();
                if (drawer) {
                    drawer.close(false);
                }
            }
        }).catch(function () {
        });
    }

    /**
     * Ask one module and put its chips where its spinner was.
     *
     * @param {Element} panel
     * @param {string} name
     * @param {string} type
     * @return {Promise}
     */
    function enrichBadgeAsk(panel, name, type) {
        var row = panel.querySelector(
            '[data-vp-eb-row="' + cssEscape(name) + '"]'
        );
        var slot = row && row.querySelector('[data-vp-eb-slot]');
        if (!slot) {
            return Promise.resolve(false);
        }

        var body = new URLSearchParams();
        body.set('data[_Token][key]', panel.dataset.vpEbToken || '');
        body.set('data[module]', name);
        body.set('data[type]', type || '');
        body.set('data[mode]', 'auto');

        return fetch(panel.dataset.vpEbUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: body.toString()
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error(String(response.status));
                }
                return response.text();
            })
            .then(function (markup) {
                slot.innerHTML = markup;
                var res = slot.querySelector('[data-vp-eb-res]');
                if (res && res.dataset.vpEbToken) {
                    panel.dataset.vpEbToken = res.dataset.vpEbToken;
                }
                enrichPanelSettle(panel, row, res
                    ? res.dataset.vpEbState
                    : 'fail');
                return true;
            })
            .catch(function () {
                /*
                 * The request failed, which is not the same as the
                 * module failing — but the panel is a summary and has
                 * no room to say which. The tab draws that distinction
                 * and is one click away.
                 */
                enrichPanelSettle(panel, row, 'fail');
                return false;
            });
    }

    /**
     * Put a landed module where its answer belongs, and restate the
     * count.
     *
     * **A module that did not answer leaves the rows.** An error
     * sitting in the column of answers competes with them, so the
     * failures collect into one trailing line — the same line the
     * server builds for the modules that had already been asked, built
     * the same way, so a reader cannot tell which of the two put a
     * name there.
     *
     * @param {Element} panel
     * @param {Element} row
     * @param {string} state `ok`, `silent` or `fail`
     */
    function enrichPanelSettle(panel, row, state) {
        if (state !== 'ok' && row) {
            var name = row.dataset.vpEbRow;
            var foot = panel.querySelector('[data-vp-eb-foot]');
            if (foot) {
                var fmt = state === 'silent'
                    ? (panel.dataset.vpEbSilent || '%s had nothing to say')
                    : (panel.dataset.vpEbFail || '%s could not answer');
                var line = document.createElement('span');
                line.className = 'vp-eb-failed';
                line.textContent = fmt.replace('%s', name);
                foot.appendChild(line);
                foot.classList.remove('d-none');
            }
            row.remove();
        }
        enrichPanelCount(panel);
    }

    /**
     * The modules the strip answers for, off the strip itself.
     *
     * @param {Element} panel
     * @return {Array} Module names
     */
    function enrichPanelDrawn(panel) {
        var strip = panel.querySelector('[data-vp-eb-strip]');
        var raw = strip ? (strip.dataset.vpEbDrawn || '') : '';
        return raw === '' ? [] : raw.split(',');
    }

    /**
     * Restate how much of the panel is an answer.
     *
     * Rebuilt from the panel rather than counted up as replies land,
     * so a request that never came back cannot leave the line claiming
     * something is still on its way.
     *
     * **The drawn count on both sides of it.** A module whose answer
     * became a widget has no row to be counted by, and the line is
     * about what the panel holds rather than about how many rows it
     * has — counting rows alone would report *0 of 1* under five
     * widgets.
     *
     * @param {Element} panel
     */
    function enrichPanelCount(panel) {
        var body = panel.querySelector('[data-vp-eb-body]');
        var rows = panel.querySelectorAll('[data-vp-eb-row]').length;
        if (body) {
            /*
             * An empty body holding its padding open under the
             * widgets is a gap a reader reads as something missing.
             */
            body.classList.toggle('d-none', rows === 0);
        }
        var out = panel.querySelector('[data-vp-eb-count]');
        if (!out) {
            return;
        }
        var drawn = enrichPanelDrawn(panel).length;
        var failed = panel.querySelectorAll('.vp-eb-failed').length;
        var answered = panel.querySelectorAll(
            '[data-vp-eb-res][data-vp-eb-state="ok"]'
        ).length;
        out.textContent = (panel.dataset.vpEbSub || '%1$s of %2$s')
            .replace('%1$s', answered + drawn)
            .replace('%2$s', rows + failed + drawn);
    }

    /**
     * @param {Event} event
     * @return {boolean} Whether the click belonged to this tab
     */
    function onEnrichClick(event) {
        /*
         * Run before pick, because the button sits inside the pane and
         * not inside the row: a press must ask, not merely select.
         */
        var runAll = event.target.closest('[data-vp-e-run-selected]');
        if (runAll) {
            runEnrichSelected(runAll);
            return true;
        }

        var run = event.target.closest('[data-vp-e-run]');
        if (run) {
            runEnrichModule(run);
            return true;
        }

        var foldAll = event.target.closest('[data-vp-e-fold-all]');
        if (foldAll) {
            toggleEnrichFoldAll(foldAll);
            return true;
        }

        var disc = event.target.closest('[data-vp-e-disc]');
        if (disc) {
            toggleEnrichDisc(disc);
            return true;
        }

        var pick = event.target.closest('[data-vp-e-pick]');
        if (pick) {
            var panel = pick.closest('[data-vp-enrich]');
            if (panel) {
                pickEnrichModule(panel, pick.dataset.vpEPick);
            }
            return true;
        }

        return false;
    }

    /**
     * Analyst data tab
     * ------------------------------------------------------------
     * Four behaviours, all client-side against markup the two
     * endpoints already sent: the order of the thread, which kinds it
     * shows, whether an item's replies are open, and a strip marker
     * lighting up the table row it belongs to.
     *
     * A reply is never sorted or filtered on its own. The unit is the
     * top-level item and everything written under it — `.vpa-item` —
     * because a reply reordered away from what it replies to is no
     * longer a reply, and a thread that hides the note but keeps the
     * opinion written on it is showing an answer to a question it has
     * taken off the page.
     */

    // Per-panel state, keyed by the element so a panel re-fetched into
    // the tab starts from its markup rather than from what the last
    // one was showing.
    var analystState = new WeakMap();

    /**
     * @param {Element} panel
     * @return {Object} The panel's sort and kind, defaulted
     */
    function analystStateOf(panel) {
        if (!analystState.has(panel)) {
            analystState.set(panel, {sort: 'newest', kind: 'all'});
        }
        return analystState.get(panel);
    }

    /**
     * Reorder and re-show the thread from the panel's current state.
     *
     * @param {Element} panel
     */
    function refreshAnalyst(panel) {
        var thread = panel.querySelector('.vpa-thread');
        if (!thread) {
            return;
        }
        var state = analystStateOf(panel);
        var items = Array.prototype.slice.call(
            thread.querySelectorAll('[data-vp-a-item]')
        );

        items.sort(function (a, b) {
            if (state.sort === 'org') {
                var byOrg = a.dataset.vpAOrg.localeCompare(b.dataset.vpAOrg);
                if (byOrg !== 0) {
                    return byOrg;
                }
            }
            var dates = a.dataset.vpADate.localeCompare(b.dataset.vpADate);
            if (dates !== 0) {
                // Oldest first only when asked; by organisation keeps
                // each organisation's own thread in the order it was
                // written, newest at the top like everything else.
                return state.sort === 'oldest' ? dates : -dates;
            }
            // Same day: the order the endpoint sent, which is the order
            // the rows came back in.
            return parseInt(a.dataset.vpAOrder, 10)
                - parseInt(b.dataset.vpAOrder, 10);
        });

        var shown = 0;
        items.forEach(function (item) {
            thread.appendChild(item);
            var on = state.kind === 'all'
                || item.dataset.vpAKind === state.kind;
            item.classList.toggle('d-none', !on);
            if (on) {
                shown++;
            }
        });

        var empty = panel.querySelector('[data-vp-a-empty]');
        if (empty) {
            empty.classList.toggle('d-none', shown > 0);
        }

        panel.querySelectorAll('[data-vp-a-sort]').forEach(function (button) {
            var active = button.dataset.vpASort === state.sort;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        panel
            .querySelectorAll('[data-vp-a-kind-filter]')
            .forEach(function (button) {
                var active = button.dataset.vpAKindFilter === state.kind;
                button.classList.toggle('active', active);
                button.setAttribute('aria-pressed', active ? 'true' : 'false');
            });
    }

    /**
     * Open or close one item's replies.
     *
     * @param {Element} button
     */
    function toggleAnalystReplies(button) {
        /*
         * The replies block is the next sibling of the .vp-analyst the
         * button sits in — never a descendant of it. Walking down from
         * the item would find the replies of a nested item first, and
         * open somebody else's sub-thread.
         */
        var claim = button.closest('.vp-analyst');
        var replies = claim ? claim.nextElementSibling : null;
        if (!replies || !replies.classList.contains('vpa-replies')) {
            return;
        }
        var open = replies.classList.toggle('d-none');
        button.setAttribute('aria-expanded', open ? 'false' : 'true');
        var caret = button.querySelector('i');
        if (caret) {
            caret.classList.toggle('fa-caret-down', !open);
            caret.classList.toggle('fa-caret-right', open);
        }
    }

    /**
    /**
     * @param {Element} root
     */
    function initAnalyst(root) {
        var panels = root.querySelectorAll
            ? root.querySelectorAll('[data-vp-analyst-thread]')
            : [];
        panels.forEach(function (panel) {
            refreshAnalyst(panel);
        });
    }

    /**
     * @param {Event} event
     * @return {boolean} Whether the click belonged to this tab
     */
    function onAnalystClick(event) {
        var sort = event.target.closest('[data-vp-a-sort]');
        if (sort) {
            var sortPanel = sort.closest('[data-vp-analyst-thread]');
            if (sortPanel) {
                analystStateOf(sortPanel).sort = sort.dataset.vpASort;
                refreshAnalyst(sortPanel);
            }
            return true;
        }

        var kind = event.target.closest('[data-vp-a-kind-filter]');
        if (kind) {
            var kindPanel = kind.closest('[data-vp-analyst-thread]');
            if (kindPanel) {
                analystStateOf(kindPanel).kind = kind.dataset.vpAKindFilter;
                refreshAnalyst(kindPanel);
            }
            return true;
        }

        var replies = event.target.closest('[data-vp-a-replies]');
        if (replies) {
            toggleAnalystReplies(replies);
            return true;
        }

        return false;
    }


    /* ==================================================================
     * Timeline tab
     * ------------------------------------------------------------------
     * One window, and two regions that read it. The spine is a control:
     * brushing it sets the window, and the lanes and the chronology both
     * re-scope to whatever it says. Neither of the two owns the window —
     * they read a shared object, which is why they can never disagree
     * about which entries they are describing.
     *
     * Everything is client-side against rows already in the DOM. The
     * lanes are redrawn because a mark's position is a fraction of the
     * window and the window moves; the chronology is only shown and
     * hidden, because a day is wholly inside a window or wholly outside
     * it and its grouping therefore never changes.
     * ================================================================== */

    var tl = {
        data: null,
        // The rows as an array, built once per fragment by `tlEntries`.
        entries: null,
        // The chronology's two row sets, likewise: every `[at]` row,
        // and every row including a collapsed run's summary.
        dated: null,
        rows: null,
        // Bin index bounds of the brush, or null while the window is the
        // one the panel was rendered with.
        brush: null,
        // The sources the chart and the chronology are showing, as an
        // array of source keys, or null while that is all of them. Set
        // from two controls: the spine's key, one source at a time, and
        // a lane button, which sets the whole array at once.
        filter: null,
        // Runs the reader has opened, by their run id.
        expanded: null,
        // Whether the reader asked past the display limit.
        showAll: false,
        spine: null,
    };

    var TL_LIMIT = 14;

    /**
     * The window the whole tab is currently describing.
     *
     * @return {{from: string, to: string, moved: boolean}|null}
     */
    function tlWindow() {
        if (!tl.data) {
            return null;
        }
        if (!tl.brush) {
            return {
                from: tl.data.window.from,
                to: tl.data.window.to,
                moved: false,
            };
        }
        return {
            from: tl.data.bins[tl.brush.from].from,
            to: tl.data.bins[tl.brush.to].to,
            moved: true,
        };
    }

    /**
     * Whether one entry falls in a window — overlap, not start.
     *
     * The server's `timelineTouches`, and it has to be the same rule:
     * a fragment fetched for a window and a window the reader brushed
     * over that fragment are two paths to one set, and a lane whose
     * rows change depending on which of the two got there is the
     * disagreement `by_day` travels with the payload to prevent.
     *
     * An instant is its own end, so there is one rule and not two.
     *
     * @param {string} day The entry's own `Y-m-d`
     * @param {?string} spanTo Its far end, or null on an instant
     * @param {{from: string, to: string}} window_
     * @return {boolean}
     */
    function tlTouches(day, spanTo, window_) {
        var to = spanTo ? spanTo.slice(0, 10) : day;
        return to >= window_.from && day <= window_.to;
    }

    /**
     * `tlTouches` over a rendered row, which is where the chronology
     * and the header tally read the same rule from.
     *
     * @param {Element} row
     * @param {{from: string, to: string}} window_
     * @return {boolean}
     */
    function tlRowTouches(row, window_) {
        return tlTouches(
            row.dataset.vpTlDay,
            row.dataset.vpTlSpanTo || null,
            window_
        );
    }

    /**
     * Which bins the current window covers, so the brush can be painted
     * over the window the panel was rendered with and not only over one
     * the reader dragged.
     *
     * @return {{from: number, to: number}}
     */
    function tlBins() {
        if (tl.brush) {
            return tl.brush;
        }
        var window_ = tl.data.window;
        var from = null;
        var to = null;
        tl.data.bins.forEach(function (bin, index) {
            if (bin.to >= window_.from && bin.from <= window_.to) {
                if (from === null) {
                    from = index;
                }
                to = index;
            }
        });
        return {
            from: from === null ? 0 : from,
            to: to === null ? tl.data.bins.length - 1 : to,
        };
    }

    /**
     * Every dated entry, read off the rows the template rendered.
     *
     * The rows are the one copy of the entry set: the lanes derive their
     * marks from these and the chronology *is* these, so the two cannot
     * describe different sets.
     *
     * **Read once per fragment and held.** The rows do not change while
     * a fragment is on screen — a brush re-scopes them, it does not
     * replace them — and this runs on every frame of a drag, so at
     * `TIMELINE_ROW_CAP`'s 1,000 it was a `querySelectorAll` and seven
     * dataset reads per row per pointer move. The cache is dropped in
     * `initTimeline`, which is the only place new rows arrive.
     *
     * Measured on `193.161.193.99`, 1,092 rows, ten frames of a drag:
     * 278 ms before, 204 ms with this held, 178 ms with the
     * chronology's two row sets held as well. What is left is the
     * lanes' mark rendering, which scales with how much of the window
     * is brushed rather than with the cap.
     *
     * @param {Element} panel
     * @return {Array}
     */
    function tlEntries(panel) {
        if (tl.entries !== null) {
            return tl.entries;
        }
        var out = [];
        panel.querySelectorAll('[data-vp-tl-at]').forEach(function (row) {
            out.push({
                at: row.dataset.vpTlAt,
                day: row.dataset.vpTlDay,
                source: row.dataset.vpTlSource,
                precision: row.dataset.vpTlPrecision,
                spanTo: row.dataset.vpTlSpanTo || null,
                ref: row.dataset.vpTlRef || '',
                /*
                 * From the row's own attribute and not from its text.
                 * `.vp-tl-main` holds the source label, the title, the
                 * precision chip and the template's indentation, so
                 * reading it back turned every mark's tooltip into a
                 * dump of the row one paint after the fragment landed —
                 * the server had written the title alone.
                 */
                title: row.dataset.vpTlTitle || '',
                /*
                 * Where the row opens, composed by the server — the
                 * anchor depends on what the entry is *about*, which
                 * the browser cannot work out from a source name.
                 * Empty for an entry with nowhere to go.
                 */
                href: row.dataset.vpTlHref || '',
            });
        });
        tl.entries = out;
        return out;
    }

    /**
     * @param {string} text
     * @return {string}
     */
    function tlEscape(text) {
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    /**
     * @param {string} at `Y-m-d H:i:s`, in UTC
     * @return {number} Epoch milliseconds
     */
    function tlStamp(at) {
        return Date.parse(at.replace(' ', 'T') + 'Z');
    }

    /**
     * @param {Date} d
     * @return {string} `Y-m-d`
     */
    function tlIso(d) {
        return d.toISOString().slice(0, 10);
    }

    /**
     * The lane's calendar bins for a window, with a day-to-bin map.
     *
     * Mirrors `ValueIntelligenceBuckets::series()` and `::locate()` — whole
     * days, fixed weeks laid forwards from the window's start, or
     * calendar months clipped at both ends — and takes its grain from
     * the rule the server shipped rather than from a second copy of
     * the thresholds. The two renderers have to agree bin for bin: the
     * server draws the fragment and this redraws it on every frame of
     * a brush, so a lane that rebinned on its own would be a lane that
     * jumped when the reader let go of the handle.
     *
     * @param {{from: string, to: string}} window_
     * @return {{bins: Array, at: Object}}
     */
    function tlLaneBins(window_) {
        var months = tl.data.months || [];
        var rule = (tl.data.lane && tl.data.lane.rule) || [];
        var from = window_.from;
        var to = window_.to;
        var last = tlStamp(to + ' 00:00:00');
        var days = 1 + Math.round(
            (last - tlStamp(from + ' 00:00:00')) / 864e5
        );
        var unit = 'week';
        rule.some(function (step) {
            if (step.days === null || days <= step.days) {
                unit = step.unit;
                return true;
            }
            return false;
        });

        var bins = [];
        var cursor;
        if (unit === 'month') {
            cursor = new Date(tlStamp(from.slice(0, 7) + '-01 00:00:00'));
            var stopMonth = to.slice(0, 7);
            while (tlIso(cursor).slice(0, 7) <= stopMonth) {
                var eom = tlIso(new Date(Date.UTC(
                    cursor.getUTCFullYear(),
                    cursor.getUTCMonth() + 1,
                    0
                )));
                bins.push({
                    from: tlIso(cursor),
                    to: eom < to ? eom : to
                });
                cursor = new Date(Date.UTC(
                    cursor.getUTCFullYear(),
                    cursor.getUTCMonth() + 1,
                    1
                ));
            }
        } else {
            var step = unit === 'week' ? 7 : 1;
            cursor = new Date(tlStamp(from + ' 00:00:00'));
            while (cursor.getTime() <= last) {
                var end = cursor.getTime() + (step - 1) * 864e5;
                bins.push({
                    from: tlIso(cursor),
                    to: tlIso(new Date(end > last ? last : end))
                });
                cursor = new Date(
                    tlStamp(bins[bins.length - 1].to + ' 00:00:00') + 864e5
                );
            }
        }

        /*
         * The name, out of the twelve the server shipped and by the
         * same one rule it uses — a name per unit would put the two
         * renderers a word apart on every month bin.
         */
        var at = {};
        bins.forEach(function (bin, index) {
            var a = new Date(tlStamp(bin.from + ' 00:00:00'));
            var b = new Date(tlStamp(bin.to + ' 00:00:00'));
            bin.title = bin.from === bin.to
                ? a.getUTCDate() + ' ' + (months[a.getUTCMonth()] || '')
                    + ' ' + a.getUTCFullYear()
                : a.getUTCDate() + ' ' + (months[a.getUTCMonth()] || '')
                    + ' – ' + b.getUTCDate() + ' '
                    + (months[b.getUTCMonth()] || '') + ' '
                    + b.getUTCFullYear();
            var day = new Date(a.getTime());
            while (tlIso(day) <= bin.to) {
                at[tlIso(day)] = index;
                day = new Date(day.getTime() + 864e5);
            }
        });
        return { bins: bins, at: at };
    }

    /**
     * A lane's binned rows as columns, in the axis's viewBox units.
     *
     * The mirror of the template's `$columnsFor`, and the same three
     * decisions: the scale is the lane's own tallest bin, a segment
     * gap is a hairline only while a segment is tall enough to have
     * one, and a bar is never shorter than two units so a bin holding
     * one row is still a bin holding one row.
     *
     * @param {Array} bins From `tlLaneBins`
     * @param {Object} byBin index => `n`, `parts` (`hue`, `n`), `title`
     * @param {boolean} own Whether the hues are analyst-chosen
     * @param {boolean} ground Whether the lane behind is hatched
     * @return {{svg: string, peak: ?Object}}
     */
    function tlColumns(bins, byBin, own, ground) {
        var lane = tl.data.lane || {};
        var width = lane.width || 740;
        var base = lane.base === undefined ? 37 : lane.base;
        var tallest = lane.bar || 25;
        var gapX = lane.gap === undefined ? 1 : lane.gap;
        var window_ = tlWindow();
        var t0 = tlStamp(window_.from + ' 00:00:00');
        var span = Math.max(1, tlStamp(window_.to + ' 23:59:59') - t0);

        function edge(at) {
            return (Math.max(0, Math.min(1, (tlStamp(at) - t0) / span))
                * width);
        }

        var max = 0;
        Object.keys(byBin).forEach(function (i) {
            max = Math.max(max, byBin[i].n);
        });
        if (!max) {
            return { svg: '', peak: null };
        }

        var svg = '';
        var peak = null;
        Object.keys(byBin).forEach(function (key) {
            var i = Number(key);
            var bin = byBin[key];
            if (!bins[i]) {
                return;
            }
            var x = Math.round(edge(bins[i].from + ' 00:00:00') * 100) / 100;
            var w = Math.round(Math.max(
                1,
                edge(bins[i].to + ' 23:59:59') - x - gapX
            ) * 100) / 100;
            var h = Math.max(2, Math.round(tallest * bin.n / max * 10) / 10);
            if (peak === null || bin.n > peak.n) {
                peak = { n: bin.n, at: x + w / 2, title: bin.title };
            }
            if (ground) {
                svg += '<rect class="vp-lane-ground" x="' + (x - 1)
                    + '" y="' + (Math.round((base - h - 1) * 100) / 100)
                    + '" width="' + (w + 2) + '" height="' + (h + 2)
                    + '" rx="2"></rect>';
            }
            if (own) {
                svg += '<rect class="vp-lane-bar-own" x="' + x + '" y="'
                    + (Math.round((base - h) * 100) / 100) + '" width="'
                    + w + '" height="' + h + '" rx="1.5"></rect>';
            }
            /*
             * Segments off shared boundaries, not off independently
             * rounded heights — see the template's `$columnsFor`. A
             * tag column can hold 41 segments in 25 units, and a
             * sub-pixel crack between each pair turns it into a
             * barcode.
             */
            var gapY = bin.parts.length > 1 && h >= 6 ? 1 : 0;
            var inner = h - gapY * (bin.parts.length - 1);
            var bottom = base;
            var acc = 0;
            bin.parts.forEach(function (part, k) {
                acc += part.n;
                var top = base - inner * acc / bin.n - gapY * k;
                var y0 = Math.round(top * 100) / 100;
                var ph = Math.max(
                    0.5,
                    Math.round((Math.round(bottom * 100) / 100 - y0) * 100)
                        / 100
                );
                svg += '<rect class="vp-lane-bar'
                    + (own && ph >= 3 ? ' vp-lane-bar-edge' : '')
                    + '" x="' + x + '" y="' + y0
                    + '" width="' + w + '" height="' + ph
                    + '" style="--vp-tl-hue: ' + tlEscape(part.hue)
                    + ';"><title>' + tlEscape(bin.title)
                    + '</title></rect>';
                bottom = top - gapY;
            });
        });
        return { svg: svg, peak: peak };
    }

    /**
     * Put the lane's one direct label where its tallest column is, or
     * take it away.
     *
     * Below three it is not printed: a lane whose busiest bin holds two
     * rows is telling the reader nothing the bars have not.
     *
     * @param {Element} axis
     * @param {?Object} peak
     */
    function tlPeak(axis, peak) {
        var old = axis.querySelector('.vp-lane-peak');
        if (old) {
            old.remove();
        }
        if (peak === null || peak.n < 3) {
            return;
        }
        var width = (tl.data.lane && tl.data.lane.width) || 740;
        var at = 100 * peak.at / width;
        var tag = document.createElement('span');
        tag.className = 'vp-lane-peak'
            + (at > 86 ? ' vp-lane-peak-r' : (at < 6 ? ' vp-lane-peak-l'
                : ''));
        tag.style.left = (Math.round(at * 100) / 100) + '%';
        tag.title = peak.title;
        tag.textContent = tlPeakLabel(peak.n);
        var plot = axis.querySelector('.vp-lane-plot') || axis;
        plot.insertBefore(tag, plot.firstChild);
    }

    /**
     * @param {number} n
     * @return {string}
     */
    function tlPeakLabel(n) {
        var template = (tl.data.labels && tl.data.labels.peak) || 'peak %s';
        return template.replace('%s', tlCount(n));
    }

    /**
     * Paint the brush over the bins the window covers, and show the
     * reset control only once the reader has moved it.
     *
     * @param {Element} panel
     */
    function tlPaintBrush(panel) {
        window.MispBrush.paint(panel, tlBins(), tl.data.bins.length);

        var reset = panel.querySelector('[data-vp-tl-reset]');
        if (reset) {
            // Offered while the brush is off the window the fragment
            // arrived with, and also while that window is itself one
            // the panel was fetched for — there the way back is a
            // request rather than a repaint, so the button has to be
            // there before the reader touches the brush at all.
            reset.hidden = !tl.brush && !tl.data.window.requested;
        }
    }

    /**
     * The Tags lane: one mark per tag, at the first time it was
     * attached, in the tag's own colour.
     *
     * The chip row under the lane is **not** touched. It is the
     * window-independent half of this lane on purpose — first attaches
     * cluster at the start of a value's history and the window
     * defaults to the last month, so the marks are often all outside
     * it and the sentence has to survive that.
     *
     * @param {Element} axis
     * @param {Object} window_ `from` and `to`
     * @param {function(string): number} xFor
     */
    function tlDrawTagLane(axis, window_, bins) {
        var tags = tl.data.tags || [];
        var labels = tl.data.labels || {};
        var svg = axis.querySelector('[data-vp-tl-marks]');
        var mine = tags.filter(function (tag) {
            if (!tag.at) {
                return false;
            }
            var day = tag.at.slice(0, 10);
            return day >= window_.from && day <= window_.to;
        });
        if (svg) {
            /*
             * A segment per tag, **in that tag's own colour** — which
             * is the whole reason this lane is drawn rather than
             * counted. A source lane's segments answer *which source*;
             * these answer *which tag*, and the chip row under the
             * lane spells the names out.
             */
            var byBin = {};
            mine.forEach(function (tag) {
                var i = bins.at[tag.at.slice(0, 10)];
                if (i === undefined) {
                    return;
                }
                if (!byBin[i]) {
                    byBin[i] = { n: 0, parts: [], names: [] };
                }
                byBin[i].n++;
                byBin[i].parts.push({
                    hue: tag.colour || 'var(--vp-tl-tag)',
                    n: 1
                });
                byBin[i].names.push(tag.name);
            });
            Object.keys(byBin).forEach(function (i) {
                var rest = byBin[i].n - Math.min(6, byBin[i].n);
                byBin[i].title = (labels.tag_first || '%1$s — %2$s')
                    .replace('%1$s', byBin[i].names.slice(0, 6).join(', ')
                        + (rest > 0
                            ? (labels.tag_more || ' +%s more')
                                .replace('%s', rest)
                            : ''))
                    .replace('%2$s', bins.bins[i].title);
            });
            var drawn = tlColumns(bins.bins, byBin, true, false);
            svg.innerHTML = drawn.svg;
            tlPeak(axis, drawn.peak);
        }
        // How many of the set the window holds, over how many there
        // are — the second number is the tag set and never moves.
        var count = axis.parentNode.querySelector(
            '[data-vp-tl-count="' + axis.dataset.vpTlAxis + '"]'
        );
        if (count) {
            setText(count, '[data-vp-tl-count-n]', mine.length);
        }
    }

    /**
     * Redraw every lane's marks for the current window, and recount it.
     *
     * A lane that MISP cannot date has no axis element at all, so it is
     * untouched here — its hatch and its count are properties of the
     * schema rather than of the window, and moving the brush must not
     * make them flicker.
     *
     * @param {Element} panel
     * @param {Array} entries
     */
    function tlDrawLanes(panel, entries) {
        var window_ = tlWindow();
        var geometry = tl.data.lane;
        var from = tlStamp(window_.from + ' 00:00:00');
        var to = tlStamp(window_.to + ' 23:59:59');
        var span = Math.max(1, to - from);

        function fractionFor(at) {
            return Math.max(0, Math.min(1, (tlStamp(at) - from) / span));
        }

        function xFor(at) {
            return Math.round(
                fractionFor(at) * (geometry.width - geometry.mark) * 10
            ) / 10;
        }

        var windowCounts = tlWindowCounts(window_);
        // One binning for the whole grid: every lane's columns share
        // boundaries, which is what lets a reader compare two lanes by
        // looking straight down.
        var laneBins = tlLaneBins(window_);

        /*
         * Where the rows stop, and how many rows there are to stop.
         *
         * The cap is applied once to the merged array, so every lane's
         * rows are newer than the same moment and one cut line is true
         * for all of them. `null` — no row in the window at all — means
         * the whole window is a span the lanes cannot draw.
         */
        var inWindow = entries.filter(function (entry) {
            return entry.day >= window_.from && entry.day <= window_.to;
        });
        var boundary = null;
        inWindow.forEach(function (entry) {
            if (boundary === null || entry.at < boundary) {
                boundary = entry.at;
            }
        });
        var cutFraction = boundary === null ? 1 : fractionFor(boundary);
        var cutTemplate = (tl.data.labels && tl.data.labels.cut) || '';
        var cutTotal = 0;

        panel.querySelectorAll('[data-vp-tl-axis]').forEach(function (axis) {
            /*
             * The Tags lane draws the tag set rather than the entry
             * set: one mark per tag at its first attach, in the tag's
             * own colour. Its rows are not chronology entries — the
             * same audit row counted twice would put the panel's
             * totals out — so it is placed here and returns before
             * everything below, none of which is about it: it has no
             * source in the day map, and no cap to band.
             */
            if (axis.dataset.vpTlDraw === 'tagfirst') {
                tlDrawTagLane(axis, window_, laneBins);
                return;
            }
            var sources = (axis.dataset.vpTlSources || '').split(',');
            var spans = axis.dataset.vpTlDraw === 'spans';
            var hatched = !!axis.querySelector('.vp-lane-fill');
            var svg = axis.querySelector('[data-vp-tl-marks]');
            var mine = entries.filter(function (entry) {
                return sources.indexOf(entry.source) !== -1
                    && tlTouches(entry.day, entry.spanTo, window_);
            });

            if (svg && spans) {
                /*
                 * The seen lane keeps its rects. It draws intervals,
                 * not instants, and a first-seen span binned into a
                 * column would be a bar saying *something lasted a
                 * while somewhere in here*.
                 */
                var marks = '';
                mine.forEach(function (entry) {
                    var x = xFor(entry.at);
                    var end = xFor(entry.spanTo || entry.at);
                    marks += '<rect class="vp-lane-span" x="' + x
                        + '" y="19" width="'
                        + Math.max(geometry.mark, end - x)
                        + '" height="7" rx="3" style="--vp-tl-hue: '
                        + 'var(--vp-tl-' + entry.source + ');"><title>'
                        + tlEscape(entry.title) + '</title></rect>';
                });
                svg.innerHTML = marks;
                tlPeak(axis, null);
            } else if (svg) {
                var byBin = {};
                mine.forEach(function (entry) {
                    var i = laneBins.at[entry.day];
                    if (i === undefined) {
                        return;
                    }
                    if (!byBin[i]) {
                        byBin[i] = { n: 0, by: {} };
                    }
                    byBin[i].n++;
                    byBin[i].by[entry.source] =
                        (byBin[i].by[entry.source] || 0) + 1;
                });
                /*
                 * Segments in the vocabulary's order and not in arrival
                 * order, so a source sits in the same place in every
                 * column of the lane — otherwise a stack that happened
                 * to start with a cluster reads as a different lane
                 * from the one beside it.
                 */
                Object.keys(byBin).forEach(function (i) {
                    var parts = [];
                    var words = [];
                    var order = tlSources();
                    Object.keys(byBin[i].by).forEach(function (source) {
                        // The key is built from the counts, so a source
                        // with rows always has a dataset — but a
                        // segment silently dropped here would be a
                        // column shorter than its own tooltip.
                        if (order.indexOf(source) === -1) {
                            order.push(source);
                        }
                    });
                    order.forEach(function (source) {
                        if (!byBin[i].by[source]) {
                            return;
                        }
                        parts.push({
                            hue: 'var(--vp-tl-' + source + ')',
                            n: byBin[i].by[source]
                        });
                        words.push(byBin[i].by[source] + ' '
                            + tlLabel(source));
                    });
                    byBin[i].parts = parts;
                    byBin[i].title = laneBins.bins[i].title + ' — '
                        + words.join(', ');
                });
                var drawn = tlColumns(
                    laneBins.bins,
                    byBin,
                    false,
                    hatched
                );
                svg.innerHTML = drawn.svg;
                tlPeak(axis, drawn.peak);
            }

            // The span labels are HTML over the axis, never SVG text:
            // the axis is stretched with preserveAspectRatio="none",
            // which would smear a word along with it.
            axis.querySelectorAll('.vp-lane-tag').forEach(function (tag) {
                tag.remove();
            });
            if (spans) {
                // A label is drawn only where it clears the last one
                // drawn — `lane.tag_char` and `lane.tag_ref` are the
                // server's two numbers, not a second estimate, so the
                // same window keeps the same labels across a brush.
                var tagChar = geometry.tag_char || 6.22;
                var tagRef = geometry.tag_ref || 560;
                var tagEnd = null;
                /*
                 * **Ascending, explicitly.** `mine` is filtered out of
                 * the chronology's rows and the chronology is newest
                 * first, so a greedy pass over it in arrival order runs
                 * right to left and keeps the *last* label of a cluster
                 * where the server kept the first. The two then
                 * disagree about which labels a window holds — the
                 * server drew two on `143.14.244.37` and the script
                 * redrew one, in the same window.
                 */
                mine.slice().sort(function (a, b) {
                    if (a.at !== b.at) {
                        return a.at < b.at ? -1 : 1;
                    }
                    // The tie-break, and it is load-bearing: 24 of
                    // `45.178.180.13`'s spans share one instant, so
                    // without it the two renderers put a label in the
                    // same place and print a different id in it.
                    return Number(a.ref) - Number(b.ref);
                }).forEach(function (entry) {
                    var label = entry.ref === null || entry.ref === undefined
                        ? ''
                        : String(entry.ref);
                    if (label === '') {
                        return;
                    }
                    var at = Math.round(
                        ((100 * xFor(entry.at)) / geometry.width) * 100
                    ) / 100;
                    if (tagEnd !== null && at < tagEnd) {
                        return;
                    }
                    tagEnd = at + (100 * label.length * tagChar) / tagRef;
                    // An anchor only where there is somewhere to go, so
                    // the rebuilt label matches what the server drew
                    // rather than offering a dead one.
                    var tag = document.createElement(
                        entry.href ? 'a' : 'span'
                    );
                    tag.className = 'vp-lane-tag';
                    if (entry.href) {
                        tag.setAttribute('href', entry.href);
                        tag.setAttribute('title', entry.title);
                    }
                    tag.style.left = at + '%';
                    tag.textContent = label;
                    svg.parentNode.insertBefore(tag, svg);
                });
            }

            /*
             * The marks above came from `mine` — the rows the fragment
             * carries — and the count comes from the aggregate. The two
             * are allowed to differ, and where they do it is the marks
             * that are the sample: a lane can show fewer marks than its
             * count, which is what a capped chronology looks like from
             * here.
             */
            var laneTotal = 0;
            var parts = [];
            sources.forEach(function (source) {
                var n = windowCounts[source] || 0;
                laneTotal += n;
                if (n > 0) {
                    parts.push(n + ' ' + tlLabel(source));
                }
            });

            /*
             * And where they differ, the lane says *where*. The
             * difference is entries it counted and has no row for, and
             * every one of them is older than the boundary, so the band
             * from the window's start to there is exactly the span the
             * marks are silent about.
             *
             * Only the mark lanes. The seen lane's own cap cuts the
             * *newest* of its spans, so a band anchored to the window's
             * start would be backwards there, and its sub-label states
             * its three numbers already.
             */
            axis.querySelectorAll('.vp-lane-cut').forEach(function (old_) {
                old_.remove();
            });
            var cut = axis.dataset.vpTlDraw === 'marks'
                ? Math.max(0, laneTotal - mine.length)
                : 0;
            if (cut > 0) {
                cutTotal += cut;
                var band = document.createElement('div');
                band.className = 'vp-lane-cut';
                band.dataset.vpTlCut = axis.dataset.vpTlAxis;
                band.style.setProperty('--vp-cut',
                    Math.round(cutFraction * 10000) / 10000);
                band.title = cutTemplate
                    .replace('%1$s', tlCount(cut))
                    .replace('%2$s', tlCount(inWindow.length));
                axis.insertBefore(band, axis.firstChild);
            }

            var key = axis.dataset.vpTlAxis;
            var cell = panel.querySelector(
                '[data-vp-tl-count="' + key + '"]'
            );
            if (!cell) {
                return;
            }
            setText(cell, '[data-vp-tl-count-n]', laneTotal);
            setText(cell, '[data-vp-tl-count-why]', parts.join(', '));
        });

        /*
         * One sentence for the bands, with the grid's whole share of
         * what they cover. Summed over the lanes that drew one rather
         * than taken as *window total less rows carried*, so the seen
         * lane's own truncation is never counted into a claim about the
         * row cap.
         */
        var note = panel.querySelector('[data-vp-tl-cut-note]');
        if (note) {
            note.hidden = cutTotal === 0;
            setText(note, '[data-vp-tl-cut-n]', tlCount(cutTotal));
        }
    }

    /**
     * How much of each source falls inside a window, summed over every
     * day the viewer may see.
     *
     * **Not a tally over the rows in the DOM**, which is what this used
     * to be and what makes the number wrong the moment a value's
     * chronology does not fit in one fragment: the list carries the
     * newest few hundred entries, so on a busy value they can all sit
     * inside three days and a tally over them reports a quiet window as
     * a busy one. The day map is the same aggregate the server counted
     * the default window from, so brushing cannot make the panel
     * disagree with itself.
     *
     * @param {Object} window_ `from` and `to`, `YYYY-MM-DD`
     * @return {Object} source => count, plus `total`
     */
    function tlWindowCounts(window_) {
        var out = { total: 0 };
        var byDay = tl.data.by_day || {};
        var add = function (source, n) {
            out[source] = (out[source] || 0) + n;
            out.total += n;
        };
        Object.keys(byDay).forEach(function (day) {
            if (day < window_.from || day > window_.to) {
                return;
            }
            Object.keys(byDay[day]).forEach(function (source) {
                add(source, byDay[day][source]);
            });
        });
        /*
         * `timelineWindowCounts`' span rule, and the same reasoning:
         * an interval crossing the window is a thing the lane draws a
         * bar for, and the day map has nothing in the middle of one to
         * count. Only a span with neither end inside — an end inside is
         * a day the map already counted, and adding it again would put
         * the column one ahead of the rows underneath it.
         */
        (tl.data.spans || []).forEach(function (span) {
            if (span.to < window_.from || span.from > window_.to) {
                return;
            }
            if ((span.from >= window_.from && span.from <= window_.to)
                || (span.to >= window_.from && span.to <= window_.to)
            ) {
                return;
            }
            add(span.source, 1);
        });
        return out;
    }

    /**
     * @param {string} source
     * @return {string} The label the spine's legend already uses, so one
     *                  source is never named two ways on one tab.
     */
    function tlLabel(source) {
        var found = source;
        tl.data.datasets.forEach(function (dataset) {
            if (dataset.source === source) {
                found = dataset.label;
            }
        });
        return found;
    }

    /**
     * The sources the spine has a dataset for, in the key's order.
     *
     * The key's own filter is expressed in these rather than in the
     * lanes' sources: a lane names every source it would carry whether
     * or not this value has one, and the key draws only what the counts
     * found.
     *
     * @return {Array<string>}
     */
    function tlSources() {
        return tl.data.datasets.map(function (dataset) {
            return dataset.source;
        });
    }

    /**
     * @param {string} source
     * @return {boolean} Whether the chart and the chronology draw it
     */
    function tlShows(source) {
        return tl.filter === null || tl.filter.indexOf(source) !== -1;
    }

    /**
     * @param {Array<string>} a
     * @param {Array<string>} b
     * @return {boolean} Whether the two name the same set
     */
    function tlSameSet(a, b) {
        return a.length === b.length && a.every(function (item) {
            return b.indexOf(item) !== -1;
        });
    }

    /**
     * @param {Array<string>} sources
     * @return {boolean} Whether the filter is exactly this set
     */
    function tlFilterIs(sources) {
        return tl.filter !== null && tlSameSet(tl.filter, sources);
    }

    /**
     * Narrow the chart and the chronology to a set of sources, or to
     * all of them.
     *
     * The spine is **rebuilt**, which is what the Sightings panel does
     * with `hiddenOrgs` for the same reason: a chart's datasets are its
     * state and `bootChart` hands back a refresh rather than the
     * instance. It costs one rebuild per click and none per brush
     * frame — the spine covers the whole range whatever the window is,
     * so a filter is the only thing that can change what it draws.
     *
     * The lanes are deliberately left alone. They are one lane per
     * source already, so narrowing them would blank rows rather than
     * answer anything, and their `In window` counts stay each lane's
     * own truth.
     *
     * @param {Element} panel
     * @param {Array<string>|null} sources
     */
    function tlSetFilter(panel, sources) {
        tl.filter = sources === null ? null : sources.slice();
        if (tl.filter !== null) {
            // In the key's order, so the note over the chronology reads
            // the way the legend does and not the way it was clicked.
            var order = tlSources();
            tl.filter.sort(function (a, b) {
                return order.indexOf(a) - order.indexOf(b);
            });
        }
        tl.showAll = false;
        tlSyncFilter(panel);
        if (tl.spine) {
            tl.spine.refresh();
        }
        tlRefreshList(panel);
    }

    /**
     * Put everything that expresses the filter in step with it: the
     * key, the lane buttons, and the note naming it.
     *
     * The two controls do not read `aria-pressed` the same way — a key
     * is pressed while its source is drawn, a lane button while the
     * filter is its lane and nothing else — because they are two
     * gestures over one state. Both are recomputed from `tl.filter`
     * rather than toggled where they were clicked, so pressing either
     * one cannot leave the other lying about what is on screen.
     *
     * @param {Element} panel
     */
    function tlSyncFilter(panel) {
        panel.querySelectorAll('[data-vp-tl-key]').forEach(
            function (key) {
                key.setAttribute(
                    'aria-pressed',
                    String(tlShows(key.dataset.vpTlKey))
                );
            }
        );
        var named = null;
        panel.querySelectorAll('[data-vp-tl-lane]').forEach(
            function (button) {
                var mine = (button.dataset.vpTlSources || '').split(',');
                var is = tlFilterIs(mine);
                button.setAttribute('aria-pressed', String(is));
                if (is) {
                    named = button.textContent.trim();
                }
            }
        );
        var name = panel.querySelector('[data-vp-tl-filter-name]');
        var verb = panel.querySelector('[data-vp-tl-filter-verb]');
        if (name && tl.filter !== null) {
            var labels = tl.data.labels || {};
            var dropped = tlSources().filter(function (source) {
                return tl.filter.indexOf(source) === -1;
            });
            /*
             * Three ways of naming one filter, shortest first. A lane's
             * own label wherever the filter is exactly a lane, because
             * `Sightings` is what the reader pressed and `Sightings,
             * False positives, Expirations` is that said three times.
             * Then what a shift-click took out, for the same reason
             * from the other side. The list only where it is the only
             * thing that says which sources are on screen.
             */
            var hiding = named === null && dropped.length === 1
                && tl.filter.length > 1;
            if (named !== null) {
                name.textContent = named;
            } else if (hiding) {
                name.textContent = tlLabel(dropped[0]);
            } else {
                name.textContent = tl.filter.map(tlLabel).join(', ');
            }
            if (verb) {
                verb.textContent = hiding
                    ? (labels.hiding || verb.textContent)
                    : (labels.showing || verb.textContent);
            }
        }
    }

    /**
     * A count, grouped the way `number_format` groups it.
     *
     * Not `toLocaleString`: `number_format` is called with its defaults
     * everywhere on this page, so it groups in threes with a comma
     * whatever the instance's language, and following the browser's
     * locale here would make one number read two ways in one panel —
     * the chronology's header is the server's and the band's tooltip is
     * this file's, and at a cap of 1,000 both of them carry four
     * digits.
     *
     * @param {number} n
     * @return {string}
     */
    function tlCount(n) {
        return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    /**
     * How many of the rows this fragment carries fall in a window,
     * counted with no regard for the source filter.
     *
     * The filter is the reader's own narrowing and says nothing about
     * what the fragment holds, so a filtered-away row still counts as
     * carried — otherwise ticking a lane would look like a reason to go
     * back to the server.
     *
     * @param {Element} panel
     * @param {Object} window_ `from` and `to`
     * @return {number}
     */
    function tlCarried(panel, window_) {
        var n = 0;
        panel.querySelectorAll('[data-vp-tl-at]').forEach(function (row) {
            if (tlRowTouches(row, window_)) {
                n++;
            }
        });
        return n;
    }

    /**
     * Whether the window on screen holds entries this fragment cannot
     * list — the aggregate counts them and no row carries them.
     *
     * @param {Element} panel
     * @return {boolean}
     */
    function tlPastTheRows(panel) {
        var window_ = tlWindow();
        var total = tlWindowCounts(window_).total;
        return total > 0 && tlCarried(panel, window_) < total;
    }

    /**
     * Ask the endpoint again, for one window or for the default one.
     *
     * The whole panel comes back, and it has to: the rows are what
     * changes, but the chronology, the lane marks and the brush are
     * three readings of one array and the fragment is where that array
     * lives. `reloadAjaxTabIndex` keeps the old markup on screen and
     * dims it, so a brush release is a panel that dims and re-fills
     * rather than one that collapses to a spinner.
     *
     * The spine is unaffected by the round trip — its bins come from
     * counts the window never narrows — so what the reader sees change
     * is the list they were asking about.
     *
     * @param {Element} panel
     * @param {Object|null} window_ `from` and `to`, or null for the
     *                              value's own default window
     * @return {boolean} Whether the request could be made
     */
    function tlFetchWindow(panel, window_) {
        var base = panel.dataset.vpTlBase;
        var container = panel.closest('.ajax-card, .ajax-tab-content');
        if (!base || !container || !window.reloadAjaxTabIndex) {
            return false;
        }
        window.reloadAjaxTabIndex(
            container,
            window_ === null
                ? base
                : base + '/' + window_.from + '/' + window_.to
        );
        return true;
    }

    /**
     * The brush has been let go. If it landed past the rows the
     * fragment carries, go and get them.
     *
     * On release and never during the drag, for `wireAuditBrush`'s
     * reason: a range inside what was fetched is instant, and one past
     * it is a request, so the check runs once rather than every few
     * pixels.
     *
     * @param {Element} panel
     */
    function tlSettle(panel) {
        if (!tl.brush) {
            return;
        }
        var window_ = tlWindow();
        /*
         * The window the fragment already is. A brush over every bin of
         * a spine that was fetched for every bin lands here, and asking
         * again would fetch the same rows over the same cap — the one
         * case where `tlPastTheRows` is true and there is nothing on
         * the other end to get.
         */
        if (window_.from === tl.data.window.from
            && window_.to === tl.data.window.to
        ) {
            return;
        }
        if (!tlPastTheRows(panel)) {
            return;
        }
        tlFetchWindow(panel, window_);
    }

    /**
     * The five-tick ruler over the lanes, for whatever window is
     * current.
     *
     * The template renders it for the window the panel arrives with,
     * and nothing redrew it after that — so a reader who brushed had
     * the marks re-placed against the new window under a ruler still
     * labelling the old one. The lane marks are already rendered twice
     * for the same reason (server-side once, here on every window), so
     * this is that pair completed rather than a new one.
     *
     * The rule is `$rulerLabel`'s in `value_timeline.ctp` — the day,
     * plus the month where it changed and the year where that did — and
     * the month names come from the payload rather than from
     * `toLocaleString`, so the first paint and every one after it read
     * one vocabulary.
     *
     * @param {Element} panel
     */
    function tlRuler(panel) {
        var host = panel.querySelector('[data-vp-tl-ticks]');
        if (!host) {
            return;
        }
        var window_ = tlWindow();
        var from = tlStamp(window_.from + ' 00:00:00');
        var span = Math.max(
            1,
            tlStamp(window_.to + ' 23:59:59') - from
        );
        var months = tl.data.months || [];
        var html = '';
        var prev = null;
        for (var i = 0; i < 5; i++) {
            var at = new Date(from + Math.round((span * i) / 4));
            var year = at.getUTCFullYear();
            var month = at.getUTCMonth();
            var label = String(at.getUTCDate());
            if (prev === null || prev.year !== year
                || prev.month !== month) {
                label += ' ' + (months[month] || '');
                if (prev === null || prev.year !== year) {
                    label += ' ' + year;
                }
            }
            html += '<span>' + tlEscape(label) + '</span>';
            prev = { year: year, month: month };
        }
        host.innerHTML = html;
    }

    /**
     * How many entries a collapsed run stands for.
     *
     * @param {Element} list
     * @param {string} run
     * @return {number}
     */
    function tlRunSize(list, run) {
        return list.querySelectorAll(
            '[data-vp-tl-in-run="' + run + '"]'
        ).length;
    }

    /**
     * Show the entries in the window, hide the rest, and keep every
     * count that describes them in step.
     *
     * @param {Element} panel
     */
    function tlRefreshList(panel) {
        var list = panel.querySelector('[data-vp-tl-list]');
        if (!list) {
            return;
        }
        var window_ = tlWindow();
        var sources = tl.filter;
        /*
         * The two row sets, held for the life of the fragment for
         * `tlEntries`' reason: this runs on every frame of a drag and
         * the rows do not change under it. They are two sets and not
         * one — a summary row standing for a collapsed run has
         * `data-vp-tl-row` and no `data-vp-tl-at`, because it is not an
         * entry.
         */
        if (tl.dated === null) {
            tl.dated = [].slice.call(
                list.querySelectorAll('[data-vp-tl-at]'));
            tl.rows = [].slice.call(
                list.querySelectorAll('[data-vp-tl-row]'));
        }

        /*
         * What the window holds, counted before anything is decided
         * about how to show it. Collapsing a run is a display device:
         * its entries are still in the window, and counting them only
         * when they are on screen is how this header would come to
         * disagree with the lanes above it.
         */
        var matched = 0;
        var tally = { exact: 0, partial: 0 };
        tl.dated.forEach(function (row) {
            if (!tlRowTouches(row, window_)) {
                return;
            }
            if (sources
                && sources.indexOf(row.dataset.vpTlSource) === -1) {
                return;
            }
            matched++;
            tally[row.dataset.vpTlPrecision]++;
        });

        // What is on screen, and how many entries that accounts for —
        // which is not the same number, because one summary row stands
        // for a whole run.
        var units = 0;
        var covered = 0;
        tl.rows.forEach(function (row) {
            var run = row.dataset.vpTlRun;
            var inRun = row.dataset.vpTlInRun;
            var keep = tlRowTouches(row, window_);
            if (keep && sources) {
                keep = sources.indexOf(row.dataset.vpTlSource) !== -1;
            }
            // A summary row and the rows it stands for are never both
            // on screen: one of them is the reader's current answer.
            if (keep && run) {
                keep = !tl.expanded[run];
            }
            if (keep && inRun) {
                keep = !!tl.expanded[inRun];
            }
            if (!keep || (!tl.showAll && units >= TL_LIMIT)) {
                if (!row.hidden) {
                    row.hidden = true;
                }
                return;
            }
            units++;
            covered += run ? tlRunSize(list, run) : 1;
            if (row.hidden) {
                row.hidden = false;
            }
        });

        // A day heading with nothing under it is a claim that something
        // happened that day.
        list.querySelectorAll('[data-vp-tl-day-head]').forEach(
            function (head) {
                var day = head.dataset.vpTlDayHead;
                var visible = list.querySelector(
                    '[data-vp-tl-day="' + day + '"]:not([hidden])'
                );
                head.hidden = !visible;
            }
        );

        setText(list, '[data-vp-tl-tally-exact]', tally.exact);
        setText(list, '[data-vp-tl-tally-part]', tally.partial);
        /*
         * The window's own count, from the aggregate rather than from
         * `matched` — the number of rows the list ended up showing. The
         * precision tally beside it stays a tally over those rows,
         * because it is a statement about the list and sums to it.
         */
        var counts = tlWindowCounts(window_);
        setText(panel, '[data-vp-tl-window-count]', counts.total);
        var noun = panel.querySelector('[data-vp-tl-window-noun]');
        if (noun) {
            noun.textContent = counts.total === 1
                ? noun.dataset.vpTlOne
                : noun.dataset.vpTlMany;
        }
        /*
         * And the same window under the filter, still from the
         * aggregate: it is what the capped empty state below claims.
         * The lanes' header keeps the unfiltered total, because the
         * lanes do not answer to the filter.
         */
        var shownTotal = counts.total;
        if (sources !== null) {
            shownTotal = 0;
            sources.forEach(function (source) {
                shownTotal += counts[source] || 0;
            });
        }
        var label = panel.querySelector('[data-vp-tl-window-label]');
        if (label) {
            label.textContent = window_.from + ' → ' + window_.to;
        }

        var foot = list.querySelector('[data-vp-tl-foot]');
        if (foot) {
            foot.hidden = covered >= matched;
            setText(foot, '[data-vp-tl-more-n]', matched - covered);
        }

        /*
         * Only a brush or a filter can empty this list. A value with
         * nothing dated has its own empty state from the template, and
         * "none in this window" over it would be a different claim.
         *
         * Which of the two empties it is matters. A window the
         * aggregate says holds entries is empty because the rows are
         * capped and these are older than the cap reaches, not because
         * the value was quiet — and the plain sentence there flatly
         * contradicts the count beside the window label, which is the
         * one reading that makes the panel look broken. Every value
         * with years of history hits it on its first active bar.
         *
         * A filtered list is counted the same way rather than sent back
         * to the plain sentence. *2 publications fall in this window
         * and none of them are among the rows this list carries* is as
         * true of one source as of all of them, and the key is what
         * makes the state easy to reach: one press narrows to a source
         * whose rows the cap dropped.
         */
        var hasRows = !!list.querySelector('[data-vp-tl-at]');
        var outOfReach = matched === 0 && hasRows && shownTotal > 0;
        var blank = list.querySelector('[data-vp-tl-blank]');
        if (blank) {
            blank.hidden = matched > 0 || !hasRows || outOfReach;
        }
        var capped = list.querySelector('[data-vp-tl-blank-capped]');
        if (capped) {
            capped.hidden = !outOfReach;
            setText(capped, '[data-vp-tl-blank-n]', shownTotal);
            /*
             * The remedy, and only where there is one. Releasing the
             * brush fetches the window, so this state is normally what
             * a reader sees for as long as they hold the pointer — but
             * the fetch needs `reloadAjaxTabIndex` and a container to
             * put the answer in, and where either is missing the
             * sentence would be an instruction that does nothing.
             */
            var advice = capped.querySelector('[data-vp-tl-blank-fetch]');
            if (advice) {
                advice.hidden = !tl.brush
                    || !panel.dataset.vpTlBase
                    || !panel.closest('.ajax-card, .ajax-tab-content')
                    || !window.reloadAjaxTabIndex;
            }
        }

        var note = list.querySelector('[data-vp-tl-filter-note]');
        if (note) {
            note.hidden = tl.filter === null;
        }
    }

    /**
     * @param {Element} panel
     */
    function refreshTimeline(panel) {
        if (!tl.data) {
            return;
        }
        tlPaintBrush(panel);
        tlRuler(panel);
        tlDrawLanes(panel, tlEntries(panel));
        tlRefreshList(panel);
    }

    /**
     * The year each bar belongs to, keyed by the bars that start one.
     *
     * A bar's own label is `Nov` or `4 Jan` — the month, because the
     * grain is a month for anything over 400 days and the spine covers
     * the value's whole range. So a month name repeats every twelve
     * bars, and on a value with two years of history a reader brushing
     * a `Nov` has no way to tell the panel which one they meant.
     *
     * Only the bars that open a year carry it, and the first bar always
     * does. A year printed under every bar is the axis's own label
     * repeated twenty-three times.
     *
     * @return {Object} Bin index => `YYYY`
     */
    function tlYearStarts() {
        var starts = {};
        var last = null;
        tl.data.bins.forEach(function (bin, index) {
            /*
             * The elided bin opens no year. It stands for a span that
             * may cross several, and its `to` is the far end of that
             * span — so writing a year under it would date the break
             * to the year it ends in and leave the bin *after* it,
             * the first one drawn to scale again, unlabelled. Passed
             * over entirely, `last` is unchanged and the next real
             * bin takes the year if it differs.
             */
            if (bin.elided) {
                return;
            }
            var year = String(bin.to).slice(0, 4);
            if (year !== last) {
                starts[index] = year;
            }
            last = year;
        });
        return starts;
    }

    /**
     * The spine. Stacked bars, one segment per source, over the value's
     * whole dated range — and the colours are the tokens the lanes
     * read, so a segment and the lane beneath it are the same colour by
     * construction rather than by being kept in step.
     *
     * @param {Element} canvas
     * @return {Chart}
     */
    function buildTimelineSpine(canvas) {
        /*
         * The year boundaries are the axis's anchor ticks. `autoSkip`
         * thins the rest to whatever fits and keeps every major, which
         * is the only way a year survives a wide range: it runs *after*
         * the label callback, and Chart.js 4.1.1's `afterAutoSkip`
         * scale hook is an empty stub rather than a dispatch, so a year
         * written on a bar that is then skipped cannot be moved to a
         * bar that was not.
         *
         * The newest bar is a major too, and it carries no year: past
         * the last major, `autoSkip` labels only one average major
         * spacing further and then stops, which dropped the two most
         * recent months of `8.8.8.8` — the end of the axis is the one
         * place a reader is most sure of and least willing to count
         * back from.
         */
        var yearStarts = tlYearStarts();
        var config = window.VP.chart.resolve({
            type: 'bar',
            plugins: [{
                /*
                 * The brush is an overlay over this canvas and has to
                 * stop where the plot area does, so its floor is the
                 * height of the laid-out x axis and not a number in the
                 * stylesheet. The CSS default was one line of month
                 * names; a second line for the year put the mask over
                 * the first, which is the whitening a reader sees over
                 * the months.
                 *
                 * Read after layout, so it is right for the grain, the
                 * panel's width and whatever rotation Chart.js chose —
                 * three things the stylesheet cannot know.
                 */
                id: 'vpTlBrushFloor',
                afterLayout: function (chart) {
                    var host = chart.canvas
                        .closest('[data-vp-tl-spine]');
                    if (!host || !chart.chartArea) {
                        return;
                    }
                    host.style.setProperty(
                        '--misp-brush-floor',
                        Math.round(chart.height - chart.chartArea.bottom)
                            + 'px'
                    );
                },
            }, {
                /*
                 * The empty end of the axis, and the break across it.
                 *
                 * The band goes in `beforeDraw`, under the grid lines
                 * rather than over them. Those lines are what say the
                 * stretch is *zero* rather than *not plotted*, and a
                 * tint painted over them would take away the one cue
                 * that tells the two apart — which is the whole thing
                 * this band exists to be clear about.
                 *
                 * The break goes in `afterDatasetsDraw`, over
                 * everything, because it is a statement about the axis
                 * and not a layer of it.
                 */
                id: 'vpTlDormancy',
                beforeDraw: function (chart, args, opts) {
                    var box = tlTailBox(chart);
                    if (!box) {
                        return;
                    }
                    var ctx = chart.ctx;
                    ctx.save();
                    ctx.fillStyle = opts.band;
                    ctx.fillRect(
                        box.from,
                        box.top,
                        box.right - box.from,
                        box.bottom - box.top
                    );
                    ctx.restore();
                },
                afterDatasetsDraw: function (chart, args, opts) {
                    var box = tlTailBox(chart);
                    if (!box) {
                        return;
                    }
                    chart.ctx.save();
                    if (box.cut) {
                        tlDrawCut(chart, box, opts);
                    }
                    tlDrawToday(chart, box, opts);
                    chart.ctx.restore();
                },
            }],
            data: {
                labels: tl.data.bins.map(function (bin) {
                    return bin.label;
                }),
                datasets: tl.data.datasets.map(function (dataset) {
                    return {
                        label: dataset.label,
                        data: dataset.data,
                        backgroundColor: dataset.colour,
                        borderWidth: 0,
                        barPercentage: 0.72,
                        categoryPercentage: 0.86,
                        /*
                         * The key's filter. Hidden rather than dropped,
                         * so a dataset keeps its index whatever is
                         * switched off — and the stack and the count
                         * axis both close over what is left, which is
                         * the whole point of pressing a key on a chart
                         * whose bottom segment is three orders of
                         * magnitude taller than the rest.
                         */
                        hidden: !tlShows(dataset.source),
                    };
                }),
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        afterBuildTicks: function (scale) {
                            var last = tl.data.bins.length - 1;
                            scale.ticks.forEach(function (tick) {
                                tick.major = tick.value === last
                                    || Object.prototype.hasOwnProperty
                                        .call(yearStarts, tick.value);
                            });
                        },
                        ticks: {
                            color: 'var(--bs-secondary-color)',
                            font: { size: 10 },
                            major: { enabled: true },
                            callback: function (value) {
                                var bin = tl.data.bins[value];
                                if (!bin) {
                                    return '';
                                }
                                // An array is two lines: the month
                                // over the year it opens.
                                return yearStarts[value] === undefined
                                    ? bin.label
                                    : [bin.label, yearStarts[value]];
                            },
                        },
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: 'var(--bs-border-color-translucent)' },
                        ticks: {
                            color: 'var(--bs-secondary-color)',
                            font: { size: 10 },
                            precision: 0,
                        },
                    },
                },
                plugins: {
                    legend: { display: false },
                    /*
                     * Four tokens rather than four literals, so the
                     * band follows the theme the way every other
                     * colour on this canvas does — `resolve()` walks
                     * plugin options with the rest of the config and
                     * `boot()` re-resolves them on a theme flip.
                     *
                     * `ground` is the canvas's own background and is
                     * what the break is cut out of: a gap has to be
                     * the colour of the paper, not a colour of its
                     * own, or it reads as a bar.
                     */
                    vpTlDormancy: {
                        band: 'var(--bs-secondary-bg)',
                        ground: 'var(--bs-body-bg)',
                        rule: 'var(--bs-secondary-color)',
                        label: 'var(--bs-secondary-color)',
                    },
                    tooltip: {
                        callbacks: {
                            title: function (items) {
                                return tl.data.bins[items[0].dataIndex].title;
                            },
                        },
                    },
                },
            },
        }, canvas);
        return new Chart(canvas, config);
    }

    /**
     * Where the value stops and the wait begins, in canvas pixels.
     *
     * The bins are equal-width categories and their date spans are
     * not, so the geometry is bin arithmetic over the plot area and
     * never date arithmetic: one slot is `chartArea.width / bins`, and
     * the tail starts at the left edge of slot `tail.at`.
     *
     * @param {Chart} chart
     * @return {Object|null} `from`, `right`, `top`, `bottom`, `slot`,
     *     and `cut` — the elided slot's edges, or null where the tail
     *     is short enough to be drawn whole.
     */
    function tlTailBox(chart) {
        var tail = tl.data && tl.data.tail;
        var area = chart.chartArea;
        if (!tail || !area || !tl.data.bins.length) {
            return null;
        }
        var slot = area.width / tl.data.bins.length;
        return {
            from: area.left + slot * tail.at,
            right: area.right,
            top: area.top,
            bottom: area.bottom,
            slot: slot,
            cut: tail.elided > 0
                ? {
                    from: area.left + slot * tail.at,
                    to: area.left + slot * (tail.at + 1),
                }
                : null,
        };
    }

    /**
     * The break in the axis: a gap cut out of the plot, edged by two
     * leaning rules.
     *
     * The printed convention, and it is the convention because it says
     * the one thing a reader has to know here — *the distance across
     * this is not the distance it looks like*. A texture would not:
     * this panel already spends 135° on *MISP cannot date this* and
     * 45° on *this was not fetched* (§19.3), and a third hatch would
     * be a third thing to learn where the fourth reading is that they
     * are all the same thing.
     *
     * @param {Chart} chart
     * @param {Object} box From `tlTailBox()`
     * @param {Object} opts The plugin's resolved colours
     */
    function tlDrawCut(chart, box, opts) {
        var ctx = chart.ctx;
        var mid = (box.cut.from + box.cut.to) / 2;
        var half = Math.max(3, Math.min(7, box.slot * 0.3));
        var lean = 5;
        ctx.fillStyle = opts.ground;
        ctx.fillRect(
            mid - half,
            box.top,
            half * 2,
            box.bottom - box.top
        );
        ctx.strokeStyle = opts.rule;
        ctx.lineWidth = 1;
        [mid - half, mid + half].forEach(function (x) {
            ctx.beginPath();
            ctx.moveTo(x + lean, box.top);
            ctx.lineTo(x - lean, box.bottom);
            ctx.stroke();
        });
    }

    /**
     * *today*, at the right-hand end of the band.
     *
     * The axis genuinely ends there — `series()` clamps its last bin
     * to the current day — so this names an edge rather than marking
     * a position, which is why it is a word at the end and not a rule
     * somewhere in the middle.
     *
     * Dropped where the band is too narrow to hold it. A caption wider
     * than the empty stretch would print over the bars it exists to be
     * to the right of, and a value quiet for one bin does not need
     * telling that its axis reaches today.
     *
     * @param {Chart} chart
     * @param {Object} box From `tlTailBox()`
     * @param {Object} opts The plugin's resolved colours
     */
    function tlDrawToday(chart, box, opts) {
        var text = tl.data.labels && tl.data.labels.today;
        if (!text) {
            return;
        }
        var ctx = chart.ctx;
        ctx.font = '10px ' + (
            getComputedStyle(chart.canvas).fontFamily || 'sans-serif'
        );
        if (ctx.measureText(text).width + 10 > box.right - box.from) {
            return;
        }
        ctx.fillStyle = opts.label;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'top';
        ctx.fillText(text, box.right - 4, box.top + 3);
    }

    /**
     * Drag on the spine. A click clears the brush — the same thing
     * `Reset window` offers, for a reader who never found it.
     *
     * The spine stays monthly however narrow the brush gets: four of
     * this tab's seven sources cannot be dated to the day, so a finer
     * bar would claim a precision the data has not got.
     *
     * @param {Element} panel
     */
    function wireTimelineBrush(panel) {
        window.MispBrush.attach(panel.querySelector('[data-misp-brush]'), {
            count: function () {
                return tl.data.bins.length;
            },
            range: function (from, to) {
                tl.brush = { from: from, to: to };
                tl.showAll = false;
                refreshTimeline(panel);
            },
            clear: function () {
                /*
                 * A click clears the brush, and where the fragment was
                 * fetched for a window that means going back for the
                 * default one — the same thing `Reset window` does,
                 * for a reader who never found the button.
                 */
                if (tl.data.window.requested
                    && tlFetchWindow(panel, null)) {
                    return;
                }
                tl.brush = null;
                tl.showAll = false;
                refreshTimeline(panel);
            },
            settle: function () {
                tlSettle(panel);
            },
        });
    }

    /* --------------------------------------------------------------
     * The History tab
     * --------------------------------------------------------------
     * The facets, the reveals, the search and the row set are all the
     * shared list contract (`00-shared.md` §5) and add nothing here.
     * Five behaviours the contract does not cover, and this panel does:
     *
     * 1. A section the filters empty is dropped and counted, not
     *    dimmed. Phase 16 greyed it to `0 of 9` and kept it, which is
     *    right at six sections; at a hundred and ninety the dimmed ones
     *    are the whole problem restated, so the fact that they exist is
     *    now a sentence above the list.
     * 2. Rows page inside their own section and never across the
     *    union, because a union of N event-scoped queries has no
     *    stable ordering key to page on.
     * 3. Sections page too, over whichever of them the filters left.
     * 4. The rail's counts follow the period and nothing else. Not the
     *    facet selections: a count that followed its own group would
     *    drop every sibling to zero the moment one was ticked, which is
     *    a rail nobody can use twice.
     * 5. A brush over a monthly chart writes the two date inputs and
     *    fires their `change`, so the whole existing filter path runs
     *    unchanged and the period stays statable as two dates. Where it
     *    reaches past the window the panel was fetched for, it re-fetches
     *    — the one control on this tab that goes back to the server.
     * -------------------------------------------------------------- */

    var audit = {
        // The plan, the rendered window and the log's span, as the
        // panel was sent them.
        data: null,
        chart: null,
        // The visible span, which the four zoom buttons move and
        // nothing else does. Null until the panel has a plan.
        zoom: null,
        labels: null,
    };

    /**
     * The bars currently drawn, each with the day offsets it covers.
     *
     * Everything about this chart that used to read a fixed array of
     * months reads this instead, because after §13.2 there is no fixed
     * array: what a bar is worth follows from how far the reader has
     * zoomed in.
     *
     * @return {Array} `bucket`, `from`, `to`
     */
    function auditBars() {
        return audit.zoom ? audit.zoom.window() : [];
    }

    /**
     * The whole log's bounds, which are not the visible span's.
     *
     * The period control offers the log and never the view: zooming
     * changes what the reader can see, and a filter that silently
     * narrowed to it would make the two gestures one after all.
     *
     * @return {{from: string, to: string}|null}
     */
    function auditWhole() {
        if (!audit.data || !audit.data.chart) {
            return null;
        }
        return {
            from: audit.data.chart.from,
            to: audit.data.chart.to,
        };
    }

    /**
     * The period the reader currently has set, as days, or nulls where
     * they have set none.
     *
     * Read off the same two inputs `activePeriod()` reads, because they
     * are the same control: the brush is a second way to write them and
     * never a second place the period lives.
     *
     * @param {Element} list
     * @return {{from: string|null, to: string|null}}
     */
    function auditTypedPeriod(list) {
        function day(selector) {
            var input = list.querySelector(selector);
            if (!input || input.value === '') {
                return null;
            }
            return input.value.slice(0, 10);
        }
        return {
            from: day('[data-vp-filter-from]'),
            to: day('[data-vp-filter-to]'),
        };
    }

    /**
     * The period the panel is describing: what the reader typed or
     * brushed, falling back to the window it was fetched for and then to
     * the whole chart.
     *
     * @param {Element} list
     * @return {{from: string, to: string}|null}
     */
    function auditPeriod(list) {
        var whole = auditWhole();
        if (!whole) {
            return null;
        }
        var typed = auditTypedPeriod(list);
        var rendered = audit.data.window;
        return {
            from: typed.from || (rendered ? rendered.from : whole.from),
            to: typed.to || (rendered ? rendered.to : whole.to),
        };
    }

    /**
     * Which month bars the period covers, so the brush can be painted
     * over a window the reader never dragged as well as over one they
     * did.
     *
     * @param {Element} list
     * @return {{from: number, to: number}|null}
     */
    function auditBins(list) {
        var period = auditPeriod(list);
        var bars = auditBars();
        if (!period || !bars.length) {
            return null;
        }
        var from = null;
        var to = null;
        bars.forEach(function (bar, index) {
            if (bar.bucket.to >= period.from
                && bar.bucket.from <= period.to
            ) {
                if (from === null) {
                    from = index;
                }
                to = index;
            }
        });
        // A period outside the visible span covers no bar. Phase 19
        // collapsed the brush onto the nearer edge, which was a
        // once-in-a-while state then and a routine one now that the
        // reader can zoom away from their own period — and an edge
        // window reads as a selection at that edge. `outside` instead,
        // which paints as a fully dimmed strip: none of what is on
        // screen is in the period, which is exactly true.
        if (from === null) {
            return 'outside';
        }
        return { from: from, to: to };
    }

    /**
     * @param {Element} list
     */
    function paintAuditBrush(list) {
        var bars = auditBars();
        var bounds = auditBins(list);
        if (bounds === null || !bars.length) {
            return;
        }
        window.MispBrush.paint(
            list,
            bounds === 'outside' ? null : bounds,
            bars.length
        );
        // The period moves without the chart moving — a typed date, a
        // cleared one, a drag — and whether it is still on screen is
        // what the zoom's note says, so that goes with it.
        paintAuditZoom(list);
    }

    /**
     * How many entries fall in one bar, summed out of the per-day
     * tally the panel was sent.
     *
     * The server ships one count per day and no totals per bar, which
     * is what lets three grains cost one tally rather than three
     * (§13.1). Summing a slice is the whole of the re-aggregation this
     * phase needed.
     *
     * @param {{from: number, to: number}} bar Day offsets
     * @return {number}
     */
    function auditBarTotal(bar) {
        var counts = audit.data.chart.counts;
        var total = 0;
        for (var i = bar.from; i <= bar.to; i += 1) {
            total += counts[i] || 0;
        }
        return total;
    }

    /**
     * The bars. No axes, for the reason the Sightings navigator has
     * none: the brush over it is positioned as a plain fraction of the
     * strip's width, and an axis would put the bars somewhere other
     * than where the drag maths says they are.
     *
     * Chart.js is handed a fresh dataset on every zoom step rather than
     * being told to rescale, because a zoom changes how many bars there
     * are and what each one covers — there is no view transform here,
     * only a different set of bars.
     *
     * @param {Element} canvas
     * @return {Object}
     */
    function buildAuditChart(canvas) {
        var bars = auditBars();
        var config = window.VP.chart.resolve({
            type: 'bar',
            data: {
                labels: bars.map(function (bar) {
                    return bar.bucket.label;
                }),
                datasets: [{
                    data: bars.map(auditBarTotal),
                    backgroundColor: 'var(--bs-secondary-color)',
                    borderWidth: 0,
                    barPercentage: 1,
                    categoryPercentage: 0.88,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                layout: { padding: 0 },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true },
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        displayColors: false,
                        callbacks: {
                            title: function (items) {
                                var bar = bars[items[0].dataIndex];
                                return bar ? bar.bucket.title : '';
                            },
                        },
                    },
                },
            },
        }, canvas);
        return new Chart(canvas, config);
    }

    /**
     * Redraw the chart, the brush over it and the zoom's own caption
     * after a zoom step.
     *
     * The period is deliberately not touched. That is §13.3's whole
     * point: these buttons change what the chart shows, and a reader
     * who has filtered to March keeps that filter while they look at
     * the rest of the year.
     *
     * @param {Element} list
     */
    function redrawAuditChart(list) {
        // `boot` hands back a refresh rather than the chart, and it is
        // the right thing to call: it rebuilds from the same builder,
        // destroys the instance it replaces, and leaves the theme
        // observer watching. Booting again per zoom step would stack a
        // MutationObserver on the canvas each time.
        if (audit.chart) {
            audit.chart.refresh();
        }
        // Paints the zoom too, because the note is about the pair.
        paintAuditBrush(list);
    }

    /**
     * Paint the zoom control, and tell the reader when the period they
     * have set is no longer on screen.
     *
     * @param {Element} list
     */
    function paintAuditZoom(list) {
        var zoom = list.querySelector('[data-vp-zoom]');
        if (!zoom || !audit.zoom) {
            return;
        }
        var away = auditBins(list) === 'outside';
        var labels = audit.labels || {};
        window.VP.zoom.paint(
            zoom,
            audit.zoom,
            labels,
            away ? (labels.away || null) : null
        );
    }

    /**
     * Write a brushed range into the two date inputs and let their own
     * `change` do the rest.
     *
     * The whole point of decision 5: `activePeriod()`, `refreshList()`,
     * the pagers and the rail all run exactly as they do when someone
     * types, so there is one filter path and not two.
     *
     * @param {Element} list
     * @param {number} from Bar index, over the drawn bars
     * @param {number} to Bar index
     */
    function writeAuditPeriod(list, from, to) {
        var bars = auditBars();
        if (!bars.length) {
            return;
        }
        var pairs = [
            ['[data-vp-filter-from]', bars[from].bucket.from + 'T00:00'],
            ['[data-vp-filter-to]', bars[to].bucket.to + 'T23:59'],
        ];
        pairs.forEach(function (pair) {
            var input = list.querySelector(pair[0]);
            if (input) {
                input.value = pair[1];
            }
        });
        listPages.set(list, 1);
        resetAuditPages(list);
        refreshList(list);
    }

    /**
     * @param {Element} list
     */
    function clearAuditPeriod(list) {
        list.querySelectorAll(
            '[data-vp-filter-from], [data-vp-filter-to]'
        ).forEach(function (input) {
            input.value = '';
        });
        listPages.set(list, 1);
        resetAuditPages(list);
        refreshList(list);
    }

    /**
     * Whether the period the reader has asked for is inside the window
     * the panel was fetched for.
     *
     * Inside is instant, because the rows are already here. Outside is a
     * request, because they are not — and pretending otherwise would
     * show them an empty period over a log that has entries in it.
     *
     * @param {Element} list
     * @return {boolean}
     */
    function auditWithinWindow(list) {
        if (!audit.data || audit.data.window === null) {
            return true;
        }
        var typed = auditTypedPeriod(list);
        var window_ = audit.data.window;
        return (typed.from === null || typed.from >= window_.from)
            && (typed.to === null || typed.to <= window_.to);
    }

    /**
     * Re-fetch the panel for a period, or for the whole log.
     *
     * @param {Element} list
     * @param {string} scope `all`, or `from/to`
     */
    function fetchAuditScope(list, scope) {
        var base = list.dataset.vpAuditBase;
        var container = list.closest('.ajax-tab-content');
        if (!base || !container || !window.reloadAjaxTabIndex) {
            return;
        }
        window.reloadAjaxTabIndex(
            container,
            scope === '' ? base : base + '/' + scope
        );
    }

    /**
     * @param {Element} list
     */
    function fetchAuditPeriod(list) {
        var typed = auditTypedPeriod(list);
        var whole = auditWhole();
        var from = typed.from || whole.from;
        var to = typed.to || whole.to;
        fetchAuditScope(list, from + '/' + to);
    }

    /**
     * Drag on the chart. A click clears the period — the same gesture
     * the Sightings and Timeline brushes offer, and the one this tab's
     * `Clear all` offers to a reader who found the button instead.
     *
     * This is the caller that needs `settle`: a range inside the
     * fetched window is instant, and one past it is a request, so the
     * check runs once on release rather than every few pixels of the
     * drag.
     *
     * @param {Element} list
     */
    function wireAuditBrush(list) {
        window.MispBrush.attach(list.querySelector('[data-misp-brush]'), {
            count: function () {
                return auditBars().length;
            },
            range: function (from, to) {
                writeAuditPeriod(list, from, to);
            },
            clear: function () {
                clearAuditPeriod(list);
            },
            settle: function () {
                if (!auditWithinWindow(list)) {
                    fetchAuditPeriod(list);
                }
            },
        });
    }

    /**
     * Re-tally the rail against the period, over every row the panel
     * holds rather than over the ones a pager left on screen.
     *
     * The facet selections are deliberately not applied. A group whose
     * counts followed its own ticks would drop every sibling to zero as
     * soon as one was ticked; a group that followed the *other* groups
     * would answer a different question in each of the four. The period
     * is a narrowing of the subject — this value, in March — and that is
     * what every log browser in this class scopes its sidebar to.
     *
     * @param {Element} list
     * @param {Object} period From `activePeriod()`
     */
    function retallyAuditFacets(list, period) {
        var counts = {};
        listRows(list).forEach(function (row) {
            if (!rowMatchesPeriod(row, period)) {
                return;
            }
            (row.dataset.vpFacet || '').split(/\s+/).forEach(function (t) {
                if (t !== '') {
                    counts[t] = (counts[t] || 0) + 1;
                }
            });
        });

        list.querySelectorAll('[data-vp-facet-group]')
            .forEach(function (group) {
                var max = 0;
                var rows = [];
                group.querySelectorAll('.vp-facet').forEach(function (row) {
                    var box = row.querySelector('[data-vp-facet-key]');
                    if (!box) {
                        return;
                    }
                    var token = box.dataset.vpFacetKey + ':' + box.value;
                    var count = counts[token] || 0;
                    max = Math.max(max, count);
                    rows.push({ row: row, box: box, count: count });
                });
                rows.forEach(function (entry) {
                    setText(entry.row, '.vp-facet-count', entry.count);
                    var bar = entry.row.querySelector('.vp-facet-bar');
                    if (bar) {
                        bar.style.setProperty(
                            '--vp-facet-share',
                            (max > 0
                                ? Math.round((entry.count / max) * 100)
                                : 0) + '%'
                        );
                    }
                    var zero = entry.count === 0;
                    entry.row.classList.toggle('opacity-50', zero);
                    // Never disable a box the reader has ticked: taking
                    // the control away would strand the filter it is
                    // still applying.
                    entry.box.disabled = zero && !entry.box.checked;
                });
            });
    }

    /**
     * How many sections the filters emptied, said out loud.
     *
     * The period variant names the dates, because decision 4 turns on
     * it: a box disappearing has to read as a filter narrowing, and a
     * count that named no period would read as data going missing.
     *
     * @param {Element} list
     * @param {number} dropped
     */
    function updateAuditDropped(list, dropped) {
        var note = list.querySelector('[data-vp-audit-dropped]');
        if (!note) {
            return;
        }
        note.classList.toggle('d-none', dropped === 0);
        if (dropped === 0) {
            note.textContent = '';
            return;
        }
        /*
         * The plural is picked here and not on the server, because the
         * server does not know this number — it is whatever the
         * reader's filter left standing. Choosing it there from the
         * section total is what made `1 of the sections below have no
         * entry` reachable.
         */
        var one = dropped === 1;
        var typed = auditTypedPeriod(list);
        if (typed.from !== null || typed.to !== null) {
            var period = auditPeriod(list);
            note.textContent = ((one
                ? note.dataset.vpAuditDropPeriodOne
                : note.dataset.vpAuditDropPeriodMany) || '')
                .replace('%1$s', dropped)
                .replace('%2$s', auditDate(period.from))
                .replace('%3$s', auditDate(period.to));
            return;
        }
        note.textContent = ((one
            ? note.dataset.vpAuditDropPlainOne
            : note.dataset.vpAuditDropPlainMany) || '')
            .replace('%1$s', dropped);
    }

    /**
     * A `Y-m-d` as the day the rest of the tab prints.
     *
     * Built from the chart's own month titles rather than from a locale
     * call, so a bar's tooltip and the sentence naming the period it
     * covers say the same month in the same words.
     *
     * @param {string} day
     * @return {string}
     */
    function auditDate(day) {
        // The monthly grain by name and not whichever one is drawn:
        // this wants `June 2024` to put a day inside, and at daily bars
        // the drawn bucket's own title is already a date.
        var title = audit.zoom
            ? audit.zoom.titleAt('month', day.slice(0, 10))
            : null;
        if (title === null) {
            return day;
        }
        return parseInt(day.slice(8, 10), 10) + ' ' + title;
    }

    /**
     * Whether the reader has this section open, remembered on the
     * element so a filter can close it and clearing the filter can put
     * it back the way they left it.
     *
     * @param {Element} section
     * @return {boolean}
     */
    function auditOpen(section) {
        if (section.dataset.vpAuditOpen === undefined) {
            var body = section.querySelector('[data-vp-audit-body]');
            section.dataset.vpAuditOpen =
                body && !body.classList.contains('d-none') ? '1' : '0';
        }
        return section.dataset.vpAuditOpen === '1';
    }

    /**
     * @param {Element} section
     */
    function applyAuditOpen(section) {
        var blank = section.dataset.vpAuditBlank === '1';
        var open = auditOpen(section) && !blank;
        var body = section.querySelector('[data-vp-audit-body]');
        if (body) {
            body.classList.toggle('d-none', !open);
        }
        var toggle = section.querySelector('[data-vp-audit-toggle]');
        if (toggle) {
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }
        var chevron = section.querySelector('[data-vp-audit-chevron]');
        if (chevron) {
            chevron.classList.toggle('fa-chevron-down', open);
            chevron.classList.toggle('fa-chevron-right', !open);
        }
    }

    /**
     * The section's own count line: `9 entries` with no filter set,
     * `3 of 9 entries` with one. Two numbers that disagree — a header
     * still claiming nine over three visible rows — is the thing this
     * exists to prevent.
     *
     * A section the filters empty is taken off the list rather than
     * dimmed. Phase 16 dimmed it, which is the right call at six
     * sections and the wrong one at a hundred and ninety: the dimmed
     * ones become the list. What it was — a section with nothing in it
     * for this period — is a sentence above the sections instead, where
     * one line covers all of them.
     *
     * @param {Element} section
     * @param {number} shown
     * @param {number} activeCount
     * @return {boolean} Whether the filters emptied it
     */
    function setAuditCount(section, shown, activeCount) {
        var total = parseInt(section.dataset.vpAuditTotal || '0', 10);
        var blank = activeCount > 0 && shown === 0;
        section.dataset.vpAuditBlank = blank ? '1' : '0';

        var label = section.querySelector('[data-vp-audit-count]');
        if (label) {
            label.textContent = activeCount === 0
                ? (label.dataset.vpAuditPlain || label.textContent)
                : (label.dataset.vpAuditTpl || '')
                    .replace('%1$s', shown)
                    .replace('%2$s', total);
        }
        applyAuditOpen(section);
        return blank;
    }

    /**
     * Page each section over its own surviving rows, then page the
     * sections themselves.
     *
     * Replaces the list-level `paginate()` for this panel rather than
     * running beside it: one pager over a union of sections would page
     * rows out of one section to make room for another's, and the range
     * it printed would belong to neither.
     *
     * @param {Element} list
     * @param {Array<Element>} filtered
     * @param {number} activeCount
     */
    function paginateAuditSections(list, filtered, activeCount) {
        var bySection = new Map();
        filtered.forEach(function (row) {
            var section = row.closest('[data-vp-audit-section]');
            if (!section) {
                return;
            }
            if (!bySection.has(section)) {
                bySection.set(section, []);
            }
            bySection.get(section).push(row);
        });

        var standing = [];
        var dropped = 0;
        auditGrouping(list).querySelectorAll('[data-vp-audit-section]')
            .forEach(function (section) {
                var rows = bySection.get(section) || [];
                var pager = section.querySelector('[data-vp-pager]');
                var size = pager
                    ? parseInt(pager.dataset.vpPageSize, 10)
                    : 0;

                if (!pager || !size || size < 1) {
                    rows.forEach(function (row) {
                        row.classList.remove('d-none');
                    });
                } else {
                    var pages = Math.max(1, Math.ceil(rows.length / size));
                    var page = Math.min(
                        parseInt(section.dataset.vpAuditPage || '1', 10),
                        pages
                    );
                    section.dataset.vpAuditPage = page;
                    var from = (page - 1) * size;
                    var to = Math.min(from + size, rows.length);
                    rows.forEach(function (row, index) {
                        row.classList.toggle(
                            'd-none',
                            index < from || index >= to
                        );
                    });
                    setText(
                        section,
                        '[data-vp-page-from]',
                        rows.length ? from + 1 : 0
                    );
                    setText(section, '[data-vp-page-to]', to);
                    setText(section, '[data-vp-page-of]', rows.length);
                    renderPager(pager, page, pages);
                }
                var blank = setAuditCount(section, rows.length, activeCount);
                if (blank) {
                    dropped++;
                }
                /*
                 * The event-level section is pinned rather than paged.
                 * It is not an occurrence, and a reader who paged the
                 * publications off the bottom of page one would have to
                 * guess which page they went to.
                 */
                if (!section.hasAttribute('data-vp-audit-pinned')) {
                    standing.push(section);
                }
                section.classList.toggle('d-none', blank);
            });

        pageAuditSections(list, standing);
        updateAuditDropped(list, dropped);
    }

    /**
     * Page the sections the filters left standing.
     *
     * @param {Element} list
     * @param {Array<Element>} standing Blank ones already excluded
     */
    function pageAuditSections(list, standing) {
        var host = auditGrouping(list)
            .querySelector('[data-vp-audit-sectionpager]');
        var pager = host ? host.querySelector('[data-vp-pager]') : null;
        if (!pager) {
            return;
        }
        var size = parseInt(pager.dataset.vpPageSize, 10);
        if (!size || size < 1) {
            return;
        }
        var pages = Math.max(1, Math.ceil(standing.length / size));
        var page = Math.min(
            parseInt(list.dataset.vpAuditSectionPage || '1', 10),
            pages
        );
        list.dataset.vpAuditSectionPage = page;
        var from = (page - 1) * size;
        var to = Math.min(from + size, standing.length);
        standing.forEach(function (section, index) {
            section.classList.toggle('d-none', index < from || index >= to);
        });
        setText(host, '[data-vp-page-from]', standing.length ? from + 1 : 0);
        setText(host, '[data-vp-page-to]', to);
        setText(host, '[data-vp-page-of]', standing.length);
        renderPager(pager, page, pages);
        host.classList.toggle('d-none', standing.length === 0);
    }

    /**
     * Narrowing changes how many pages a section has, so every section
     * goes back to page one rather than to a page that may no longer
     * exist. The section pager goes with them, for the same reason.
     *
     * @param {Element} list
     */
    function resetAuditPages(list) {
        list.querySelectorAll('[data-vp-audit-section]')
            .forEach(function (section) {
                section.dataset.vpAuditPage = 1;
            });
        list.dataset.vpAuditSectionPage = 1;
    }

    /**
     * @param {Element} list
     * @return {Element} The grouping on screen, or the list for a panel
     *     that has only one
     */
    function auditGrouping(list) {
        return list.querySelector('[data-vp-audit-grouping]:not([hidden])')
            || list;
    }

    /**
     * Refile every row under the grouping the reader picked.
     *
     * The rows move rather than being copied, so each one stays a
     * single list row and the rail, the header and the section counts
     * all keep counting it once. Newest first under an organisation or
     * a field, since those sections mix occurrences; back in rendered
     * order under By occurrence.
     *
     * By field opens each edit's diff, since the diff is what that
     * grouping is for, and leaving it closes them again.
     *
     * @param {Element} button A [data-vp-audit-group]
     */
    function switchAuditGrouping(button) {
        var list = button.closest('[data-vp-audit]');
        var key = button.dataset.vpAuditGroup;
        var target = list
            && list.querySelector('[data-vp-audit-grouping="' + key + '"]');
        if (!target || !target.hidden && auditGrouping(list) === target) {
            return;
        }
        var attribute = {
            occurrence: 'vpAuditHome',
            org: 'vpAuditOrg',
            field: 'vpAuditField',
        }[key];
        var rows = listRows(list);
        rows.forEach(function (row, index) {
            if (row.dataset.vpAuditSeq === undefined) {
                row.dataset.vpAuditSeq = index;
            }
        });
        var seq = function (row) {
            return parseInt(row.dataset.vpAuditSeq, 10);
        };
        rows.sort(key === 'occurrence'
            ? function (a, b) {
                return seq(a) - seq(b);
            }
            : function (a, b) {
                return (b.dataset.vpTime || '')
                    .localeCompare(a.dataset.vpTime || '')
                    || seq(a) - seq(b);
            });
        rows.forEach(function (row) {
            var body = document.getElementById(row.dataset[attribute]);
            if (!body) {
                return;
            }
            var host = body.querySelector(':scope > [data-vp-audit-pagerhost]');
            body.insertBefore(row, host);
            var diff = row.querySelector('[data-vp-audit-diff]');
            var table = row.querySelector('.vp-audit-diff');
            var open = key === 'field'
                && row.hasAttribute('data-vp-audit-edit');
            if (diff && table && table.classList.contains('d-none') === open) {
                toggleAuditDiff(diff);
            }
        });
        list.querySelectorAll('[data-vp-audit-grouping]')
            .forEach(function (grouping) {
                grouping.hidden = grouping !== target;
            });
        list.querySelectorAll('[data-vp-audit-group]').forEach(function (b) {
            var on = b === button;
            b.classList.toggle('active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        resetAuditPages(list);
        refreshList(list);
    }

    /**
     * @param {Element} button
     */
    function toggleAuditSection(button) {
        var section = button.closest('[data-vp-audit-section]');
        if (!section) {
            return;
        }
        section.dataset.vpAuditOpen = auditOpen(section) ? '0' : '1';
        applyAuditOpen(section);
    }

    /**
     * One control, two states: it opens everything while anything is
     * closed, and closes everything once nothing is.
     *
     * @param {Element} button
     */
    function toggleAuditAll(button) {
        var list = button.closest('[data-vp-list]');
        if (!list) {
            return;
        }
        var sections = auditGrouping(list)
            .querySelectorAll('[data-vp-audit-section]');
        var opening = false;
        sections.forEach(function (section) {
            if (!auditOpen(section)) {
                opening = true;
            }
        });
        sections.forEach(function (section) {
            section.dataset.vpAuditOpen = opening ? '1' : '0';
            applyAuditOpen(section);
        });
        var label = button.querySelector('[data-vp-audit-expand-label]');
        if (label) {
            label.textContent = opening
                ? (button.dataset.vpAuditLabelCollapse || '')
                : (button.dataset.vpAuditLabelExpand || '');
        }
    }

    /**
     * @param {Element} button
     */
    function toggleAuditDiff(button) {
        var row = button.closest('.vp-audit-row');
        if (!row) {
            return;
        }
        var diff = row.querySelector('.vp-audit-diff');
        if (!diff) {
            return;
        }
        var closed = diff.classList.toggle('d-none');
        button.setAttribute('aria-expanded', closed ? 'false' : 'true');
        var icon = button.querySelector('i');
        if (icon) {
            icon.classList.toggle('fa-chevron-down', closed);
            icon.classList.toggle('fa-chevron-up', !closed);
        }
    }

    /**
     * @param {Event} event
     * @return {boolean} Whether the click was this panel's
     */
    function onAuditClick(event) {
        var toggle = event.target.closest('[data-vp-audit-toggle]');
        if (toggle) {
            toggleAuditSection(toggle);
            return true;
        }
        var all = event.target.closest('[data-vp-audit-expand-all]');
        if (all) {
            toggleAuditAll(all);
            return true;
        }
        var grouping = event.target.closest('[data-vp-audit-group]');
        if (grouping) {
            switchAuditGrouping(grouping);
            return true;
        }
        var diff = event.target.closest('[data-vp-audit-diff]');
        if (diff) {
            toggleAuditDiff(diff);
            return true;
        }
        var scope = event.target.closest('[data-vp-audit-scope]');
        if (scope) {
            var list = scope.closest('[data-vp-audit]');
            if (list) {
                fetchAuditScope(list, scope.dataset.vpAuditScope);
            }
            return true;
        }
        return false;
    }

    /**
     * @param {Element} root Either the whole page or a fragment
     */
    function initHistory(root) {
        var list = (root || document).querySelector('[data-vp-audit]');
        if (!list) {
            return;
        }
        var payload = list.querySelector('[data-vp-audit-data]');
        if (!payload) {
            // The log has no entries at all, so there is no span to
            // draw and no period to pick inside it.
            audit.data = null;
            return;
        }
        audit.data = JSON.parse(payload.textContent);
        if (!audit.data.chart || !audit.data.chart.days) {
            return;
        }
        audit.zoom = window.VP.zoom.make(
            audit.data.chart,
            // The period, which on this tab is the two date inputs —
            // so `look inside the selection` and the filter are the
            // same range by construction, and the reader who only
            // wanted a closer look still has the four buttons.
            function () {
                var typed = auditTypedPeriod(list);
                if (typed.from === null && typed.to === null) {
                    return null;
                }
                var whole = auditWhole();
                return {
                    from: typed.from || whole.from,
                    to: typed.to || whole.to,
                };
            }
        );
        audit.labels = null;
        var zoom = list.querySelector('[data-vp-zoom]');
        if (zoom) {
            var spec = zoom.querySelector('[data-vp-zoom-labels]');
            audit.labels = spec ? JSON.parse(spec.textContent) : null;
        }
        audit.chart = window.VP.chart.boot(
            'vp-audit-activity',
            buildAuditChart
        );
        // Both controls are rendered hidden, because without this
        // script they would frame an empty canvas and offer gestures
        // that do nothing.
        var brush = list.querySelector('[data-misp-brush]');
        if (brush) {
            brush.hidden = false;
        }
        if (zoom) {
            zoom.hidden = false;
        }
        wireAuditBrush(list);
        window.VP.zoom.wire(zoom, audit.zoom, function () {
            redrawAuditChart(list);
        });
        paintAuditZoom(list);
        // `refreshAllLists` paints and re-tallies on the same pass, so
        // the panel lands with the brush over the window it was fetched
        // for rather than over the whole chart.
        refreshList(list);
    }

    /**
     * @param {Element} root Either the whole page or a fragment
     */
    function initTimeline(root) {
        var panel = (root || document).querySelector('[data-vp-tl]');
        if (!panel) {
            return;
        }
        var payload = panel.querySelector('[data-vp-tl-data]');
        if (!payload) {
            return;
        }
        tl.data = JSON.parse(payload.textContent);
        tl.entries = null;
        tl.dated = null;
        tl.rows = null;
        tl.brush = null;
        tl.filter = null;
        tl.expanded = {};
        tl.showAll = false;
        tl.spine = window.VP.chart.boot('vp-tl-spine', buildTimelineSpine);
        // The brush is rendered hidden, because without this script it
        // would frame an empty canvas and offer a gesture that does
        // nothing.
        var brush = panel.querySelector('[data-misp-brush]');
        if (brush) {
            brush.hidden = false;
        }
        // The key's buttons ship disabled for the same reason, and are
        // live from here.
        panel.querySelectorAll('[data-vp-tl-key]').forEach(
            function (key) {
                key.disabled = false;
            }
        );
        wireTimelineBrush(panel);
        tlSyncFilter(panel);
        refreshTimeline(panel);
    }

    /**
     * @param {Event} event
     * @return {void}
     */
    function onTimelineClick(event) {
        var panel = event.target.closest
            ? event.target.closest('[data-vp-tl]')
            : null;
        if (!panel || !tl.data) {
            return;
        }

        /*
         * The key as a filter. A plain click solos the source, which is
         * the gesture a reader wants for a segment the stack has
         * flattened to a hairline; shift, ctrl or meta toggles one,
         * which is how they drop the segment that is burying the rest.
         */
        var key = event.target.closest('[data-vp-tl-key]');
        if (key && !key.disabled) {
            var source = key.dataset.vpTlKey;
            if (!(event.shiftKey || event.ctrlKey || event.metaKey)) {
                tlSetFilter(panel, tlFilterIs([source]) ? null : [source]);
                return;
            }
            var next = (tl.filter === null ? tlSources() : tl.filter)
                .slice();
            var at = next.indexOf(source);
            if (at === -1) {
                next.push(source);
            } else {
                next.splice(at, 1);
            }
            /*
             * A selection that ends up naming every source, or none, is
             * no filter: keeping it would leave the note claiming a
             * narrowing that is not one, and an empty chart offers the
             * reader nothing to press their way out of.
             */
            tlSetFilter(
                panel,
                next.length === 0 || tlSameSet(next, tlSources())
                    ? null
                    : next
            );
            return;
        }

        var lane = event.target.closest('[data-vp-tl-lane]');
        if (lane) {
            // Pressing the lane that is already showing lets it go,
            // which is the same gesture the type chips in the banner
            // use.
            var mine = (lane.dataset.vpTlSources || '').split(',');
            tlSetFilter(panel, tlFilterIs(mine) ? null : mine);
            return;
        }

        if (event.target.closest('[data-vp-tl-filter-clear]')) {
            tlSetFilter(panel, null);
            return;
        }

        if (event.target.closest('[data-vp-tl-reset]')) {
            if (tl.data.window.requested
                && tlFetchWindow(panel, null)) {
                return;
            }
            tl.brush = null;
            tl.showAll = false;
            refreshTimeline(panel);
            return;
        }

        if (event.target.closest('[data-vp-tl-more]')) {
            tl.showAll = true;
            tlRefreshList(panel);
            return;
        }

        var expand = event.target.closest('[data-vp-tl-expand]');
        if (expand) {
            var row = expand.closest('[data-vp-tl-run]');
            if (row) {
                tl.expanded[row.dataset.vpTlRun] = true;
                tlRefreshList(panel);
            }
        }
    }

    /*
     * ------------------------------------------------------------------
     * The Relationships tab's contents strip
     * ------------------------------------------------------------------
     * Seven cards over six lazily-loaded endpoints. The strip is markup
     * only — `value_relation_summary.ctp` holds no data — so every number
     * on it is read off the panel that owns it, as that panel lands. A
     * panel declares itself with `data-vp-rel-summary` naming its
     * section, `data-vp-rel-count` carrying the figure already formatted
     * by PHP, and an optional `data-vp-rel-note` for the qualifier a bare
     * integer would lie without: a capped join, a suppressed scan, a
     * source this reader may not see.
     */

    /**
     * @return {Element|null} The strip, or null off the Relationships tab
     */
    function relationSummaryStrip() {
        return document.querySelector('[data-vp-relsum-strip]');
    }

    /**
     * The lazily-loaded container a card points into. It exists from
     * first paint — the anchor is on the div holding the spinner, not on
     * the panel the fetch will put inside it — so a press lands
     * somewhere sensible even before the section has arrived.
     *
     * @param {Element} card
     * @return {Element|null}
     */
    function relationSummaryContainer(card) {
        var href = card.getAttribute('href') || '';
        return href.charAt(0) === '#'
            ? document.getElementById(href.slice(1))
            : null;
    }

    /**
     * Copy one panel's headline number onto its card.
     *
     * @param {Element} strip
     * @param {Element} panel Carries data-vp-rel-summary
     */
    function readRelationSummary(strip, panel) {
        var key = panel.dataset.vpRelSummary;
        var card = key
            ? strip.querySelector('[data-vp-relsum="' + key + '"]')
            : null;
        if (!card) {
            return;
        }

        var count = panel.dataset.vpRelCount || '';
        var note = panel.dataset.vpRelNote || '';
        var figure = card.querySelector('[data-vp-relsum-count]');
        var noteEl = card.querySelector('[data-vp-relsum-note]');

        if (figure) {
            figure.textContent = count;
        }
        if (noteEl) {
            noteEl.textContent = note;
            noteEl.hidden = !note;
        }
        card.classList.remove('vp-relsum-pending', 'd-none');
        // A section holding nothing is still an answer and still worth
        // a card — it is just not the one the eye should land on first.
        card.classList.toggle('vp-relsum-zero', count === '0');
    }

    /**
     * Sections a loaded container did not draw have no card. The
     * siblings table is the case: the co-occurrence endpoint renders it
     * only for a value that sits in an object beside something else, so
     * one of that container's two cards is often the description of a
     * table nobody will scroll to.
     *
     * @param {Element} strip
     */
    function dropAbsentRelationSummaries(strip) {
        strip.querySelectorAll('[data-vp-relsum]').forEach(function (card) {
            var container = relationSummaryContainer(card);
            if (!container || !container.dataset.loaded) {
                return;
            }
            var key = card.dataset.vpRelsum;
            if (!container.querySelector(
                '[data-vp-rel-summary="' + key + '"]'
            )) {
                card.classList.add('d-none');
            }
        });
    }

    /**
     * @param {Element|Document} root The panel that just landed, or the
     *                                whole document on first run
     */
    /**
     * The same figures again, into the rail's "What is counted" card.
     *
     * That card's foot is the tab's arithmetic — eight notions in five
     * units — and it used to read them off the held digest server-side,
     * which meant the rail's live statement about the correlation
     * engine waited on a 20,000-row neighbourhood scan to render three
     * alerts. It reads nothing now: the rows arrive empty and the panel
     * that owns each section fills it here, off the very same
     * `data-vp-rel-*` stamps the strip above is reading.
     *
     * The `≥` a bounded section prints comes with the count, because
     * the panel already puts it there for the strip.
     *
     * @param {Element} panel The panel that just landed
     */
    function readRelationSplit(panel) {
        var key = panel.dataset.vpRelSummary;
        var row = key
            ? document.querySelector(
                '[data-vp-relsum-split="' + key + '"]'
            )
            : null;
        if (!row) {
            return;
        }

        var count = panel.dataset.vpRelCount || '';
        var note = panel.dataset.vpRelNote || '';
        var figure = row.querySelector('[data-vp-relsum-split-count]');
        if (figure) {
            figure.textContent = count;
        }
        var holder = row.querySelector('[data-vp-relsum-split-figure]');
        if (holder && note) {
            holder.setAttribute('title', note);
        }
        row.classList.remove('d-none');
        row.classList.toggle('vp-split-none', relationSplitValue(row) === 0);
    }

    /**
     * A filled row's figure as a number, for the bars and the reveal.
     *
     * The text is what the panel printed — thousands separators, and a
     * `≥` where the section is a floor — so it is read back rather than
     * carried separately. A row nobody has filled yet reads 0, which is
     * why the block is revealed on a stamp arriving rather than on a
     * total being positive.
     *
     * @param {Element} row
     * @return {number}
     */
    function relationSplitValue(row) {
        var figure = row.querySelector('[data-vp-relsum-split-count]');
        var text = figure ? figure.textContent : '';
        var digits = text.replace(/[^0-9]/g, '');
        return digits === '' ? 0 : parseInt(digits, 10);
    }

    /**
     * Scale the bars, count the notions, and reveal the block.
     *
     * Run after every arrival rather than once, because the panels land
     * one at a time and the widest figure is not known until the last
     * of them has. The scale is a rough sense of size and nothing more
     * — the notions do not share a unit — but a bar that contradicted
     * the number beside it would still be wrong, so 3 remote events
     * beside 1,214 co-occurring values keeps a minimum width instead of
     * rounding to nothing.
     */
    function layoutRelationSplit() {
        var block = document.querySelector('[data-vp-relsum-split-block]');
        if (!block) {
            return;
        }
        var rows = Array.prototype.slice.call(
            block.querySelectorAll('[data-vp-relsum-split]')
        ).filter(function (row) {
            return !row.classList.contains('d-none');
        });
        if (!rows.length) {
            return;
        }

        var max = 0;
        var capped = false;
        rows.forEach(function (row) {
            max = Math.max(max, relationSplitValue(row));
            if (/≥/.test(row.textContent)) {
                capped = true;
            }
        });
        rows.forEach(function (row) {
            var value = relationSplitValue(row);
            var fill = row.querySelector('[data-vp-relsum-split-fill]');
            if (!fill) {
                return;
            }
            fill.style.width = (value > 0 && max > 0
                ? Math.max(4, Math.round((value / max) * 100))
                : 0) + '%';
        });

        var head = block.querySelector('[data-vp-relsum-split-head]');
        if (head) {
            var form = rows.length === 1
                ? (head.dataset.vpSplitOne || '')
                : (head.dataset.vpSplitMany || '');
            head.textContent = form.replace('%d', String(rows.length));
        }
        var floor = block.querySelector('[data-vp-relsum-split-capped]');
        if (floor) {
            floor.classList.toggle('d-none', !capped);
        }
        block.classList.remove('d-none');
    }

    function initRelationSummary(root) {
        var strip = relationSummaryStrip();
        if (strip) {
            (root || document)
                .querySelectorAll('[data-vp-rel-summary]')
                .forEach(function (panel) {
                    readRelationSummary(strip, panel);
                });
            dropAbsentRelationSummaries(strip);
        }

        /*
         * **Over the whole document, not the container that just
         * arrived.** The strip is in the page shell, so it exists
         * before any panel lands and can be filled from each one as it
         * comes. The split rows are in the rail's own lazily-loaded
         * card, which is one of the nine and lands in whatever order
         * the fetches finish — usually first, because it is now the
         * cheapest. Filling it only from the arriving container left
         * it empty whenever a panel had already landed before it, so
         * every arrival re-reads every stamp on the page. The stamps
         * are attributes on markup that is already there and the fill
         * is idempotent, so the cost is a `querySelectorAll` per
         * panel.
         */
        document
            .querySelectorAll('[data-vp-rel-summary]')
            .forEach(readRelationSplit);
        layoutRelationSplit();
    }

    /**
     * The press. The anchor's own jump would work, but it would also
     * write the section id into the address bar — and the hash on this
     * page routes *tabs*, so a reload would find no tab called
     * `vp-rel-sec-dated` and open the Overview instead.
     *
     * @param {Element} card
     */
    function jumpToRelationSection(card) {
        var container = relationSummaryContainer(card);
        if (!container) {
            return;
        }
        var key = card.dataset.vpRelsum;
        var target = container.querySelector(
            '[data-vp-rel-summary="' + key + '"]'
        ) || container;

        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        flashRelationSection(target);
    }

    /**
     * Say which panel answered. Seven cards over a tab this long means
     * a press can land on a section that looks like the four around it,
     * and a reader who cannot tell whether the page moved will press
     * again.
     *
     * @param {Element} target
     */
    function flashRelationSection(target) {
        target.classList.remove('vp-relsum-landed');
        // Restart the animation rather than letting a second press
        // inside its duration do nothing.
        void target.offsetWidth;
        target.classList.add('vp-relsum-landed');
        window.setTimeout(function () {
            target.classList.remove('vp-relsum-landed');
        }, 1400);
    }

    function init() {
        if (!onValuePage()) {
            return;
        }

        markDisabled(document);

        document.addEventListener('click', function (event) {
            if (!event.target.closest) {
                return;
            }
            if (event.target.closest('a.disabled, a[aria-disabled="true"]')) {
                event.preventDefault();
                event.stopPropagation();
            }
        }, true);

        /*
         * `pointerover` and `focusin` rather than `pointerenter`, which
         * does not bubble and so cannot be delegated. Both fire before
         * the CSS reveal has to be right, and re-firing on a card
         * already open is harmless.
         */
        var placeFromEvent = function (event) {
            if (!event.target.closest) {
                return;
            }
            var wrap = event.target.closest(
                '.vp-threat .vp-claim-tipwrap'
            );
            if (wrap) {
                placeThreatTip(wrap);
            }
        };
        document.addEventListener('pointerover', placeFromEvent);
        document.addEventListener('focusin', placeFromEvent);

        document.addEventListener('click', function (event) {
            if (!event.target.closest) {
                return;
            }
            var chip = event.target.closest('.vp-type-chip');
            if (chip) {
                toggleTypeFilter(chip);
                return;
            }

            var threatPill = event.target.closest(
                '[data-vp-threat-filter]'
            );
            if (threatPill) {
                filterThreats(
                    threatPill.closest('[data-vp-threats]'),
                    threatPill.dataset.vpThreatFilter
                );
                return;
            }
            var threatMore = event.target.closest(
                '[data-vp-threat-expand]'
            );
            if (threatMore) {
                filterThreats(
                    threatMore.closest('[data-vp-threats]'),
                    'all'
                );
                return;
            }

            var summaryCard = event.target.closest('[data-vp-relsum]');
            if (summaryCard) {
                event.preventDefault();
                jumpToRelationSection(summaryCard);
                return;
            }

            var sortHeader = event.target.closest('[data-vp-sort-col]');
            if (sortHeader) {
                toggleColumnSort(sortHeader);
                return;
            }
            if (event.target.closest('[data-vp-filter-clear]')) {
                var active = document.querySelector('.vp-type-chip.active');
                if (active) {
                    toggleTypeFilter(active);
                }
                return;
            }

            var page = event.target.closest('[data-vp-page]');
            if (page && !page.disabled) {
                var pageList = page.closest('[data-vp-list]');
                var pageSection = page.closest('[data-vp-audit-section]');
                var pageSections = page
                    .closest('[data-vp-audit-sectionpager]');
                if (pageSections && pageList) {
                    pageList.dataset.vpAuditSectionPage =
                        parseInt(page.dataset.vpPage, 10);
                } else if (pageSection) {
                    pageSection.dataset.vpAuditPage =
                        parseInt(page.dataset.vpPage, 10);
                } else if (pageList) {
                    listPages.set(pageList, parseInt(page.dataset.vpPage, 10));
                }
                if (pageList) {
                    refreshList(pageList);
                }
                return;
            }

            if (onSightClick(event)) {
                return;
            }

            if (onEnrichClick(event)) {
                return;
            }

            if (onAnalystClick(event)) {
                return;
            }

            if (onAuditClick(event)) {
                return;
            }

            onTimelineClick(event);

            var pill = event.target.closest('[data-vp-pill]');
            if (pill) {
                pickPill(pill);
                return;
            }

            var more = event.target.closest('[data-vp-facet-more]');
            if (more) {
                expandFacetGroup(more);
                return;
            }

            /*
             * The one control on this page that asks for a read rather
             * than accepting the one it was given. It goes remote
             * whatever the panel holds, because the rows themselves are
             * what it is refusing.
             */
            var again = event.target.closest('[data-vp-narrow-fresh]');
            if (again) {
                var againList = again.closest('[data-vp-list]');
                if (againList) {
                    narrowRemotely(againList, true);
                }
                return;
            }

            var clearAll = event.target.closest('[data-vp-facet-clear]');
            if (clearAll && !clearAll.disabled) {
                var clearList = clearAll.closest('[data-vp-list]');
                if (clearList) {
                    clearListFilters(clearList);
                    // A reset over a served list is a narrowing like
                    // any other: the rows it wants back are the ones
                    // the fold cut, not the ones still on screen.
                    if (clearList.dataset.vpNarrowActive
                        && narrowRemotely(clearList)
                    ) {
                        listPages.set(clearList, 1);
                        resetAuditPages(clearList);
                        return;
                    }
                    narrowList(clearList);
                }
            }
        });

        // The standing panel used to pair a strip marker with the
        // table rows it stood for. Its ledger fuses the two — the
        // marker and the row are one object now — so the hover lives
        // in `.vpa-row:hover` and needs no script.

        document.addEventListener('change', function (event) {
            if (event.target.id === 'vp-occ-deleted-toggle') {
                refreshOccurrences();
            }

            if (event.target.matches
                && event.target.matches('[data-vp-e-select-all]')) {
                var allPanel = event.target.closest('[data-vp-enrich]');
                if (allPanel) {
                    allPanel
                        .querySelectorAll('[data-vp-e-select]')
                        .forEach(function (box) {
                            if (!box.disabled) {
                                box.checked = event.target.checked;
                            }
                        });
                    refreshEnrichTray(allPanel);
                }
                return;
            }

            if (event.target.matches
                && event.target.matches('[data-vp-e-select]')) {
                var enrichPanel = event.target.closest('[data-vp-enrich]');
                if (enrichPanel) {
                    refreshEnrichTray(enrichPanel);
                }
                return;
            }

            if (event.target.matches && event.target.matches('[data-vp-col]')) {
                toggleColumn(event.target);
            }

            if (event.target.matches
                && event.target.matches('[data-vp-page-size-pick]')) {
                changePageSize(event.target);
                return;
            }

            if (event.target.matches
                && event.target.matches('[data-vp-sight-range]')) {
                // A wider window is a different set of buckets, so a
                // brush drawn over the old ones no longer points at
                // anything the reader chose.
                sight.rangeKey = event.target.value;
                sight.brush = null;
                sight.expanded = false;
                sightToSpan(sight.rangeKey);
                var sightPanel = document.querySelector('[data-vp-sight]');
                if (sightPanel) {
                    syncSightPreset(sightPanel);
                    refreshSight(sightPanel);
                }
            }

            if (event.target.matches
                && event.target.matches('[data-vp-group]')) {
                switchGroup(event.target);
                return;
            }

            if (event.target.matches
                && event.target.matches('[data-vp-sort]')) {
                var sortList = event.target.closest('[data-vp-list]');
                if (sortList) {
                    // A reorder does not change how many rows there
                    // are, but page three of a new order is not the
                    // rows the reader was looking at either.
                    listPages.set(sortList, 1);
                    refreshList(sortList);
                }
                return;
            }

            // Before the narrowing branch, and not part of it: this
            // select names which date the rail cuts on rather than
            // stating a cut, and it re-filters only where swapping panes
            // dropped a bound.
            if (event.target.matches
                && event.target.matches('[data-vp-time-scope]')) {
                switchTimeScope(event.target);
                return;
            }

            // Narrowing a list changes how many pages it has, so any
            // facet, select, threshold or reveal switch sends the
            // reader back to page one rather than to a page that may no
            // longer exist.
            if (event.target.matches
                && event.target.matches(
                    '[data-vp-facet-key], [data-vp-reveal],'
                    + ' [data-vp-filter-key], [data-vp-filter-min],'
                    + ' [data-vp-filter-from], [data-vp-filter-to],'
                    + ' [data-vp-range-from], [data-vp-range-to]'
                )) {
                var list = event.target.closest('[data-vp-list]');
                if (list) {
                    narrowList(list);
                }
            }
        });

        document.addEventListener('input', function (event) {
            if (!event.target.matches) {
                return;
            }
            if (event.target.matches('[data-vp-facet-search]')) {
                filterFacetGroup(event.target);
                return;
            }
            if (event.target.matches('[data-vp-e-filter]')) {
                filterEnrichResult(event.target);
                return;
            }
            if (event.target.matches(
                '[data-vp-filter-text], [data-vp-filter-min],'
                + ' [data-vp-filter-from], [data-vp-filter-to],'
                + ' [data-vp-range-from], [data-vp-range-to]'
            )) {
                var typedList = event.target.closest('[data-vp-list]');
                if (typedList) {
                    narrowList(typedList);
                }
            }
        });

        // Panels arrive after load, one fetch each, so the state the page
        // is holding has to be applied to each one as it lands.
        document.addEventListener('misp:container-loaded', function (event) {
            markDisabled(event.target);
            refreshOccurrences();
            initTimeBrushes(event.target);
            refreshAllLists(event.target);
            initSightings(event.target);
            initEnrichment(event.target);
            initEnrichmentTyping(event.target);
            initEnrichPanel(event.target);
            initAnalyst(event.target);
            initTimeline(event.target);
            initHistory(event.target);
            initRelationSummary(event.target);
        });

        refreshOccurrences();
        // Before the first refresh, so the windows paint with the rest.
        initTimeBrushes(document);
        refreshAllLists(document);
        initSightings(document);
        initEnrichment(document);
        initEnrichmentTyping(document);
        initEnrichPanel(document);
        initAnalyst(document);
        initTimeline(document);
        initHistory(document);
        initRelationSummary(document);
        initGrading();
    }

    /**
     * A grade changes how much an organisation counts, so the assessment
     * panels already drawn are read again (org-grade.js).
     */
    function initGrading() {
        document.addEventListener('og:graded', function () {
            if (typeof window.reloadAjaxTabIndex !== 'function') {
                return;
            }
            document.querySelectorAll('[data-url*="/values/viewVerdict"]')
                .forEach(function (box) {
                    if (!box.dataset.loaded) {
                        return;
                    }
                    // Past the page's memo of shared panel responses.
                    var url = box.dataset.url.replace(/[?&]og=\d+$/, '');
                    window.reloadAjaxTabIndex(box, url
                        + (url.indexOf('?') < 0 ? '?' : '&')
                        + 'og=' + Date.now());
                });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
