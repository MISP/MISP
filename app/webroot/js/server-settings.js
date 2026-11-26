/**
 * Server settings page (Overmind): navigation, filters, inline editing,
 * module switches, health probes and the global settings search.
 *
 * Everything is delegated from the page shell (#ssShell), so the fragments
 * the navigation swaps in carry no script of their own beyond what their
 * elements already had. Relies on showToast() / showConfirmModal() from
 * mispOvermind.js and on bootstrap.bundle, both loaded after this file —
 * nothing here runs before DOMContentLoaded.
 */
(function () {
    'use strict';

    var XHR = { 'X-Requested-With': 'XMLHttpRequest' };
    var MAX_PARALLEL_PROBES = 2;
    var SEARCH_LIMIT = 60;

    var shell, content, config, L;
    var current = null;
    var verdicts = {};
    var probeQueue = [];
    var probesRunning = 0;
    var searchIndex = null;
    var searchIndexLoading = null;
    var openCell = null;

    function onReady(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    onReady(function () {
        shell = document.getElementById('ssShell');
        content = document.getElementById('ssContent');
        var configNode = document.getElementById('ssConfig');
        if (!shell || !content || !configNode) {
            return;
        }
        config = JSON.parse(configNode.textContent);
        L = config.labels;
        verdicts = config.verdicts || {};

        document.addEventListener('click', onClick);
        content.addEventListener('input', onInput);
        content.addEventListener('change', onChange);
        content.addEventListener('keydown', onContentKeydown);
        document.addEventListener('keydown', onGlobalKeydown);
        window.addEventListener('popstate', function (event) {
            var id = event.state && event.state.ssDestination ? event.state.ssDestination : destinationFromLocation();
            navigate(id, { hash: location.hash });
        });
        initSearch();
        setInterval(function () { updateAges(document); }, 60000);

        navigate(config.destination, { replace: true, hash: location.hash });
    });

    /* ------------------------------------------------------------ helpers */

    function fmt(template) {
        var args = Array.prototype.slice.call(arguments, 1);
        return template.replace(/%s/g, function () { return args.length ? args.shift() : ''; });
    }

    function urlFor(id) {
        return config.base + '/' + encodeURIComponent(id);
    }

    function destinationFromLocation() {
        var path = location.pathname.replace(/\/+$/, '');
        var base = new URL(config.base, location.origin).pathname.replace(/\/+$/, '');
        if (path.indexOf(base + '/') === 0) {
            return decodeURIComponent(path.substring(base.length + 1).split('/')[0]);
        }
        return 'overview';
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function toast(message, variant) {
        if (typeof showToast === 'function') {
            showToast(message, variant);
        }
    }

    // innerHTML does not execute <script>; re-create the executable ones.
    function runScripts(container) {
        container.querySelectorAll('script').forEach(function (old) {
            var type = (old.getAttribute('type') || '').toLowerCase();
            if (type && type !== 'text/javascript' && type !== 'module') {
                return;
            }
            var script = document.createElement('script');
            if (old.src) {
                script.src = old.src;
            } else {
                script.textContent = old.textContent;
            }
            document.head.appendChild(script);
            document.head.removeChild(script);
        });
        if (typeof initTopbarFilterSelects === 'function') {
            initTopbarFilterSelects(container);
        }
    }

    function parseHtml(html) {
        var template = document.createElement('template');
        template.innerHTML = html.trim();
        return template.content.firstElementChild;
    }

    function relativeAge(at) {
        if (!at) {
            return L.notChecked;
        }
        var minutes = Math.floor((Date.now() / 1000 - at) / 60);
        if (minutes < 1) {
            return L.checkedNow;
        }
        if (minutes < 60) {
            return fmt(L.checkedMinutes, minutes);
        }
        if (minutes < 60 * 24) {
            return fmt(L.checkedHours, Math.floor(minutes / 60));
        }
        return fmt(L.checkedDays, Math.floor(minutes / 1440));
    }

    function updateAges(root) {
        root.querySelectorAll('[data-ss-age]').forEach(function (node) {
            node.textContent = relativeAge(parseInt(node.dataset.ssAge, 10));
        });
        root.querySelectorAll('[data-ss-tile]').forEach(function (tile) {
            var age = tile.querySelector('[data-ss-tile-age]');
            if (age && !tile.classList.contains('ss-tile-loading')) {
                age.textContent = relativeAge(parseInt(tile.dataset.ssAt, 10));
            }
        });
    }

    /* --------------------------------------------------------- navigation */

    function navigate(id, opts) {
        opts = opts || {};
        probeQueue.length = 0;
        openCell = null;
        setActiveNav(id);
        content.classList.add('ss-busy');
        content.setAttribute('aria-busy', 'true');

        return fetch(urlFor(id), { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            })
            .then(function (html) {
                content.innerHTML = html;
                var page = content.querySelector('[data-ss-page]');
                current = page ? page.dataset.ssPage : id;
                var url = urlFor(current) + (opts.hash || '');
                if (opts.push) {
                    history.pushState({ ssDestination: current }, '', url);
                } else if (opts.replace) {
                    history.replaceState({ ssDestination: current }, '', url);
                }
                setActiveNav(current);
                refreshBadges(page);
                runScripts(content);
                initPage(content, opts);
                if (opts.push) {
                    var top = shell.getBoundingClientRect().top + window.scrollY - 72;
                    if (window.scrollY > top) {
                        window.scrollTo({ top: Math.max(top, 0) });
                    }
                }
            })
            .catch(function (error) {
                console.error(error);
                content.innerHTML = '<div class="card shadow-sm"><div class="card-body d-flex flex-column align-items-center text-center py-5">'
                    + '<i class="fas fa-triangle-exclamation fa-2x text-danger mb-3"></i>'
                    + '<p class="mb-3">' + escapeHtml(L.loadFailed) + '</p>'
                    + '<button type="button" class="btn btn-outline-primary btn-sm" data-ss-retry="' + escapeHtml(id) + '">'
                    + escapeHtml(L.retry) + '</button></div></div>';
            })
            .finally(function () {
                content.classList.remove('ss-busy');
                content.removeAttribute('aria-busy');
            });
    }

    function setActiveNav(id) {
        shell.querySelectorAll('.ss-nav [data-ss-nav]').forEach(function (link) {
            var active = link.dataset.ssNav === id;
            link.classList.toggle('active', active);
            if (active) {
                link.setAttribute('aria-current', 'page');
                var children = link.closest('.ss-nav-children');
                if (children && !children.classList.contains('show') && window.bootstrap) {
                    bootstrap.Collapse.getOrCreateInstance(children, { toggle: false }).show();
                }
            } else {
                link.removeAttribute('aria-current');
            }
        });
    }

    function refreshBadges(page) {
        if (!page || !page.dataset.ssCounters) {
            return;
        }
        var counters = JSON.parse(page.dataset.ssCounters);
        var total = [0, 0];
        Object.keys(counters).forEach(function (id) {
            if (id !== 'integrations') {
                total[0] += counters[id][0];
                total[1] += counters[id][1];
            }
        });
        counters.overview = total;
        shell.querySelectorAll('[data-ss-badge]').forEach(function (badge) {
            var byLevel = counters[badge.dataset.ssBadge] || [0, 0];
            var count = byLevel[0] + byLevel[1];
            badge.textContent = count;
            badge.classList.toggle('d-none', count === 0);
            badge.classList.toggle('ss-nav-badge-critical', byLevel[0] > 0);
            badge.classList.toggle('ss-nav-badge-warning', byLevel[0] === 0);
        });
    }

    function initPage(root, opts) {
        root.querySelectorAll('[data-ss-settings]').forEach(function (container) {
            // A page made only of advanced settings (ZeroMQ, Kafka…) would open empty.
            var tiered = container.hasAttribute('data-ss-tiered');
            if (tiered && container.querySelector('tr.ss-row') && !container.querySelector(
                'tr.ss-row[data-ss-tier="essential"], tr.ss-row[data-ss-tier="standard"]')) {
                setFilterState(container, 'advanced', true);
            } else {
                applyFilter(container);
            }
        });
        initModules(root);
        initTiles(root);
        root.querySelectorAll('[data-ss-probe-pending]').forEach(function (placeholder) {
            enqueueProbe({ probe: placeholder.dataset.ssProbe, mode: 'card', el: placeholder });
        });
        updateAges(root);

        var hash = opts.hash || '';
        var setting = opts.setting || (hash.indexOf('#setting=') === 0 ? decodeURIComponent(hash.substring(9)) : null);
        var filter = opts.filter || (hash === '#problems' ? 'problems' : null);
        if (filter) {
            var toggle = root.querySelector('[data-ss-toggle="' + filter + '"]');
            if (toggle) {
                setFilterState(toggle.closest('[data-ss-settings]'), filter, true);
            }
        }
        if (setting) {
            revealSetting(setting);
        }
    }

    /* ------------------------------------------------------------- clicks */

    function onClick(event) {
        var target = event.target;

        var navLink = target.closest('a[data-ss-nav]');
        if (navLink && shell.contains(navLink)) {
            if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
                return;
            }
            event.preventDefault();
            var settingName = navLink.dataset.ssNavSetting;
            var filterName = navLink.dataset.ssNavFilter;
            navigate(navLink.dataset.ssNav, {
                push: true,
                setting: settingName || null,
                filter: filterName || null,
                hash: settingName ? '#setting=' + encodeURIComponent(settingName) : (filterName ? '#' + filterName : ''),
            });
            return;
        }
        if (!content || !shell.contains(target) && !target.closest('#ssSearchModal')) {
            return;
        }

        var retry = target.closest('[data-ss-retry]');
        if (retry) {
            navigate(retry.dataset.ssRetry, {});
            return;
        }
        if (target.closest('[data-ss-search-open]')) {
            openSearch();
            return;
        }
        var clear = target.closest('[data-ss-clear]');
        if (clear) {
            clearFilters(clear.closest('[data-ss-settings]'));
            return;
        }
        var apply = target.closest('[data-ss-filter-apply]');
        if (apply) {
            var applyContainer = apply.closest('[data-ss-settings]');
            var field = applyContainer.querySelector('[data-ss-filter]');
            filterState(applyContainer).term = field.value.trim().toLowerCase();
            applyFilter(applyContainer);
            return;
        }
        var toggle = target.closest('[data-ss-toggle]');
        if (toggle) {
            var container = toggle.closest('[data-ss-settings]') || content.querySelector('[data-ss-settings][data-ss-tiered]');
            if (container) {
                var key = toggle.dataset.ssToggle;
                setFilterState(container, key, !filterState(container)[key]);
            }
            return;
        }
        var rerun = target.closest('[data-ss-probe-rerun]');
        if (rerun) {
            rerunProbe(rerun.closest('[data-ss-probe]'));
            return;
        }
        if (target.closest('[data-ss-rerun-tiles]')) {
            content.querySelectorAll('[data-ss-tile]').forEach(function (tile) {
                queueTile(tile);
            });
            return;
        }
        var moduleOpen = target.closest('[data-ss-module-open]');
        if (moduleOpen) {
            openModulePanel(moduleOpen.closest('[data-ss-modules]'), moduleOpen.dataset.ssModuleOpen, true);
            return;
        }
        // Anywhere on a module card opens its settings, bar its switch.
        var moduleCard = target.closest('[data-ss-module]');
        if (moduleCard && !target.closest('.form-switch')) {
            openModulePanel(moduleCard.closest('[data-ss-modules]'), moduleCard.dataset.ssModule, true);
            return;
        }
        var chip = target.closest('[data-ss-module-chip]');
        if (chip) {
            var modules = chip.closest('[data-ss-modules]');
            modules.dataset.ssChip = chip.dataset.ssModuleChip;
            modules.querySelectorAll('[data-ss-module-chip]').forEach(function (other) {
                var on = other === chip;
                other.classList.toggle('active', on);
                other.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
            filterModules(modules);
            return;
        }
        if (handleDiagnosticAction(target)) {
            return;
        }

        var cell = target.closest('.ss-editable');
        if (cell && content.contains(cell) && !target.closest('form')) {
            openEditor(cell);
            return;
        }
        if (openCell && !target.closest('.ss-editing')) {
            closeEditor();
        }
    }

    function onInput(event) {
        var filter = event.target.closest('[data-ss-filter]');
        if (filter) {
            var container = filter.closest('[data-ss-settings]');
            filterState(container).term = filter.value.trim().toLowerCase();
            applyFilter(container);
            return;
        }
        var moduleFilter = event.target.closest('[data-ss-module-filter]');
        if (moduleFilter) {
            filterModules(moduleFilter.closest('[data-ss-modules]'));
        }
    }

    function onChange(event) {
        var advanced = event.target.closest('[data-ss-advanced-switch]');
        if (advanced) {
            setFilterState(advanced.closest('[data-ss-settings]'), 'advanced', advanced.checked);
            return;
        }
        var toggle = event.target.closest('[data-ss-module-toggle]');
        if (toggle) {
            toggleModule(toggle);
        }
    }

    function onContentKeydown(event) {
        if (event.key !== 'Enter' && event.key !== ' ') {
            return;
        }
        var cell = event.target.closest('.ss-editable');
        if (cell && !cell.classList.contains('ss-editing') && event.target === cell) {
            event.preventDefault();
            openEditor(cell);
        }
    }

    function onGlobalKeydown(event) {
        if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            openSearch();
        }
    }

    /* ------------------------------------------------------------ filters */

    function filterState(container) {
        if (!container.__ssFilter) {
            container.__ssFilter = { term: '', problems: false, modified: false, advanced: false };
        }
        return container.__ssFilter;
    }

    function setFilterState(container, key, value) {
        if (!container) {
            return;
        }
        filterState(container)[key] = value;
        container.querySelectorAll('[data-ss-toggle="' + key + '"]').forEach(function (button) {
            if (button.classList.contains('ss-toggle')) {
                button.classList.toggle('active', value);
                button.setAttribute('aria-pressed', value ? 'true' : 'false');
            } else if (button.classList.contains('btn-outline-primary') || button.classList.contains('btn-primary')) {
                // Filter bar buttons read as pressed the way the index bars do.
                button.classList.toggle('btn-primary', value);
                button.classList.toggle('btn-outline-primary', !value);
                button.setAttribute('aria-pressed', value ? 'true' : 'false');
            }
        });
        if (key === 'advanced') {
            container.querySelectorAll('[data-ss-advanced-switch]').forEach(function (input) {
                input.checked = value;
            });
            container.querySelectorAll('.filter-draft-count').forEach(function (badge) {
                badge.textContent = value ? 1 : 0;
                badge.classList.toggle('d-none', !value);
            });
        }
        applyFilter(container);
    }

    function clearFilters(container) {
        var state = filterState(container);
        state.term = '';
        container.querySelectorAll('[data-ss-filter]').forEach(function (input) {
            input.value = '';
        });
        ['problems', 'modified', 'advanced'].forEach(function (key) {
            setFilterState(container, key, false);
        });
    }

    // The "Active filters" line under the bar, as on the indexes.
    function renderActiveFilters(container, state) {
        var row = container.querySelector('[data-ss-active]');
        if (!row) {
            return;
        }
        var chips = [];
        if (state.term !== '') {
            chips.push(L.filterSearch + ': ' + state.term);
        }
        if (state.problems) {
            chips.push(L.onlyProblems);
        }
        if (state.modified) {
            chips.push(L.onlyModified);
        }
        if (state.advanced) {
            chips.push(L.showAdvanced);
        }
        row.querySelector('[data-ss-chips]').innerHTML = chips.map(function (chip) {
            return '<span class="badge bg-primary">' + escapeHtml(chip) + '</span>';
        }).join('');
        row.classList.toggle('d-none', chips.length === 0);
        row.classList.toggle('d-flex', chips.length > 0);
    }

    // Searchable text of a row, computed once from what it renders.
    function haystack(row) {
        if (row.__ssSearch === undefined) {
            row.__ssSearch = row.textContent.toLowerCase().replace(/\s+/g, ' ');
        }
        return row.__ssSearch;
    }

    function applyFilter(container) {
        if (!container) {
            return;
        }
        var state = filterState(container);
        var tiered = container.hasAttribute('data-ss-tiered');
        var filtering = state.term !== '' || state.problems || state.modified;
        var total = 0;

        container.querySelectorAll('[data-ss-section]').forEach(function (section) {
            var visible = 0;
            section.querySelectorAll('tr.ss-row').forEach(function (row) {
                var tier = row.dataset.ssTier;
                var tierHidden = tiered && !state.advanced && !filtering && !row.dataset.ssForce
                    && (tier === 'advanced' || tier === 'deprecated');
                var hit = !tierHidden
                    && (!state.problems || row.dataset.ssError === '1')
                    && (!state.modified || row.dataset.ssModified === '1')
                    && (state.term === '' || haystack(row).indexOf(state.term) !== -1);
                row.classList.toggle('d-none', !hit);
                if (hit) {
                    visible++;
                }
            });
            total += visible;
            section.classList.toggle('d-none', visible === 0);
            var bar = section.querySelector('[data-ss-advanced-bar]');
            if (bar) {
                bar.classList.toggle('d-none', state.advanced || filtering);
            }
        });
        container.querySelectorAll('[data-ss-group]').forEach(function (group) {
            group.classList.toggle('d-none', !group.querySelector('[data-ss-section]:not(.d-none)'));
        });
        var noResult = container.querySelector('[data-ss-no-result]');
        if (noResult) {
            noResult.classList.toggle('d-none', !filtering || total !== 0);
        }
        renderActiveFilters(container, state);
    }

    function revealSetting(name) {
        var selector = 'tr.ss-row[data-setting-name="' + CSS.escape(name) + '"]';
        var row = content.querySelector(selector);
        if (!row) {
            return;
        }
        var panel = row.closest('[data-ss-module-panel]');
        if (panel) {
            openModulePanel(panel.closest('[data-ss-modules]'), panel.dataset.ssModulePanel, false);
        }
        row.dataset.ssForce = '1';
        applyFilter(row.closest('[data-ss-settings]'));
        row.scrollIntoView({ block: 'center' });
        row.classList.add('ss-row-flash');
        setTimeout(function () { row.classList.remove('ss-row-flash'); }, 2400);
    }

    /* -------------------------------------------------------- inline edit */

    function closeEditor() {
        if (!openCell) {
            return;
        }
        var form = openCell.querySelector('form');
        if (form) {
            form.remove();
        }
        openCell.querySelector('.ss-value').classList.remove('d-none');
        openCell.classList.remove('ss-editing');
        openCell = null;
    }

    function editUrl(setting, id) {
        return baseurl + '/servers/serverSettingsEdit/' + encodeURIComponent(setting) + '/' + encodeURIComponent(id);
    }

    function fetchEditForm(setting, id) {
        return fetch(editUrl(setting, id), { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            });
    }

    function postForm(form) {
        return fetch(form.action, {
            method: 'POST',
            headers: XHR,
            credentials: 'same-origin',
            body: new URLSearchParams(new FormData(form)),
        }).then(function (response) { return response.json(); });
    }

    function openEditor(cell) {
        if (cell.classList.contains('ss-editing')) {
            return;
        }
        closeEditor();
        var setting = cell.dataset.setting;
        var id = cell.dataset.settingId;
        cell.classList.add('ss-editing');
        openCell = cell;

        fetchEditForm(setting, id).then(function (html) {
            if (openCell !== cell) {
                return;
            }
            cell.querySelector('.ss-value').classList.add('d-none');
            cell.insertAdjacentHTML('beforeend', html);
            var form = cell.querySelector('form');
            var field = form.querySelector('.ss-input');
            if (field) {
                field.focus();
                if (field.select) {
                    field.select();
                }
            }
            form.addEventListener('submit', function (event) {
                event.preventDefault();
                saveFromEditor(cell, form);
            });
            form.querySelector('[data-ss-cancel]').addEventListener('click', closeEditor);
            form.addEventListener('keydown', function (event) {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    closeEditor();
                }
            });
        }).catch(function () {
            toast(L.formFailed, 'danger');
            closeEditor();
        });
    }

    function saveFromEditor(cell, form) {
        var submit = form.querySelector('[data-ss-accept]');
        submit.disabled = true;
        postForm(form).then(function (result) {
            if (!result.saved) {
                submit.disabled = false;
                toast(result.errors || L.saveFailed, 'danger');
                return;
            }
            toast(result.success || L.saved, 'success');
            openCell = null;
            var row = cell.closest('tr');
            reloadRow(row).then(function (fresh) {
                syncModuleCard(fresh);
            }).catch(function () {
                closeEditor();
                toast(L.refreshFailed, 'warning');
            });
        }).catch(function () {
            submit.disabled = false;
            toast(L.saveFailed, 'danger');
        });
    }

    // Re-read a setting server-side: saving a value can clear (or raise) its error.
    function reloadRow(row) {
        var setting = row.dataset.settingName;
        var id = row.id.replace(/^setting_row_/, '');
        var params = new URLSearchParams();
        params.set('variant', row.dataset.ssVariant || 'standard');
        if (row.dataset.ssDest) {
            params.set('dest', row.dataset.ssDest);
            params.set('destTitle', row.dataset.ssDestTitle || '');
        }
        if (row.dataset.ssLabel) {
            params.set('label', row.dataset.ssLabel);
        }
        if (row.dataset.ssModuleRow) {
            params.set('module', row.dataset.ssModuleRow);
        }
        var url = baseurl + '/servers/serverSettingsReloadSetting/' + encodeURIComponent(setting) + '/'
            + encodeURIComponent(id) + '?' + params.toString();
        return fetch(url, { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            })
            .then(function (html) {
                var container = row.closest('[data-ss-settings]');
                var forced = row.dataset.ssForce;
                var fresh = parseHtml(html);
                if (forced) {
                    fresh.dataset.ssForce = forced;
                }
                row.replaceWith(fresh);
                applyFilter(container);
                return fresh;
            });
    }

    // Save a value without an editor on screen (the module switches).
    function saveSettingValue(setting, id, value) {
        return fetchEditForm(setting, id).then(function (html) {
            var holder = document.createElement('div');
            holder.className = 'd-none';
            holder.innerHTML = html;
            document.body.appendChild(holder);
            var form = holder.querySelector('form');
            form.querySelector('.ss-input').value = value;
            return postForm(form).finally(function () { holder.remove(); });
        });
    }

    /* ------------------------------------------------------------ modules */

    function initModules(root) {
        root.querySelectorAll('[data-ss-modules]').forEach(function (modules) {
            modules.dataset.ssChip = 'all';
            filterModules(modules);
        });
    }

    function filterModules(modules) {
        if (!modules) {
            return;
        }
        var input = modules.querySelector('[data-ss-module-filter]');
        var term = input ? input.value.trim().toLowerCase() : '';
        var chip = modules.dataset.ssChip || 'all';
        var shown = 0;
        modules.querySelectorAll('[data-ss-module]').forEach(function (card) {
            var hit = (chip !== 'enabled' || card.dataset.ssEnabled === '1')
                && (chip !== 'config' || card.dataset.ssNeedsConfig === '1')
                && (term === '' || card.textContent.toLowerCase().indexOf(term) !== -1);
            card.classList.toggle('d-none', !hit);
            if (hit) {
                shown++;
            }
        });
        var empty = modules.querySelector('[data-ss-module-empty]');
        if (empty) {
            empty.classList.toggle('d-none', shown !== 0);
        }
    }

    function openModulePanel(modules, id, scroll) {
        if (!modules) {
            return;
        }
        var panel = null;
        modules.querySelectorAll('[data-ss-module-panel]').forEach(function (candidate) {
            var match = candidate.dataset.ssModulePanel === id;
            candidate.classList.toggle('d-none', !match);
            if (match) {
                panel = candidate;
            }
        });
        modules.querySelectorAll('[data-ss-module]').forEach(function (card) {
            card.classList.toggle('ss-module-selected', card.dataset.ssModule === id);
        });
        if (panel && scroll && window.matchMedia('(max-width: 1199.98px)').matches) {
            panel.scrollIntoView({ block: 'start', behavior: 'smooth' });
        }
    }

    function moduleCard(modules, id) {
        var found = null;
        modules.querySelectorAll('[data-ss-module]').forEach(function (card) {
            if (card.dataset.ssModule === id) {
                found = card;
            }
        });
        return found;
    }

    function toggleModule(input) {
        var modules = input.closest('[data-ss-modules]');
        var id = input.dataset.ssModuleToggle;
        var enabled = input.checked;
        input.disabled = true;
        saveSettingValue(input.dataset.setting, input.dataset.settingId, enabled ? '1' : '0')
            .then(function (result) {
                if (!result.saved) {
                    throw new Error(result.errors || L.saveFailed);
                }
                toast(result.success || L.saved, 'success');
                setModuleEnabled(modules, id, enabled);
                // Its settings only count as problems while it runs: re-read them all.
                var panel = modules.querySelector('[data-ss-module-panel="' + CSS.escape(id) + '"]');
                var rows = panel ? Array.prototype.slice.call(panel.querySelectorAll('tr.ss-row')) : [];
                return Promise.all(rows.map(reloadRow)).then(function () {
                    updateModuleWarning(modules, id);
                });
            })
            .catch(function (error) {
                input.checked = !enabled;
                toast(error && error.message && error.message.indexOf('HTTP') !== 0 ? error.message : L.saveFailed, 'danger');
            })
            .finally(function () {
                input.disabled = false;
            });
    }

    function setModuleEnabled(modules, id, enabled) {
        var card = moduleCard(modules, id);
        if (!card) {
            return;
        }
        card.dataset.ssEnabled = enabled ? '1' : '0';
        card.classList.toggle('ss-module-off', !enabled);
        var input = card.querySelector('[data-ss-module-toggle]');
        if (input) {
            input.checked = enabled;
        }
    }

    function updateModuleWarning(modules, id) {
        var card = moduleCard(modules, id);
        var panel = modules.querySelector('[data-ss-module-panel="' + CSS.escape(id) + '"]');
        if (!card || !panel) {
            return;
        }
        var needsConfig = card.dataset.ssEnabled === '1' && !!panel.querySelector('tr.ss-row[data-ss-error="1"]');
        card.dataset.ssNeedsConfig = needsConfig ? '1' : '0';
        card.querySelector('[data-ss-module-warn]').classList.toggle('d-none', !needsConfig);
        var enabledCount = modules.querySelectorAll('[data-ss-module][data-ss-enabled="1"]').length;
        var configCount = modules.querySelectorAll('[data-ss-module][data-ss-needs-config="1"]').length;
        var counts = modules.querySelectorAll('[data-ss-module-count]');
        counts.forEach(function (node) {
            node.textContent = node.dataset.ssModuleCount === 'enabled' ? enabledCount : configCount;
        });
        filterModules(modules);
    }

    // An edit made in a module's panel may have been its `_enabled` switch.
    function syncModuleCard(row) {
        var panel = row && row.closest('[data-ss-module-panel]');
        if (!panel) {
            return;
        }
        var modules = panel.closest('[data-ss-modules]');
        var id = panel.dataset.ssModulePanel;
        var card = moduleCard(modules, id);
        var input = card ? card.querySelector('[data-ss-module-toggle]') : null;
        if (input && input.dataset.setting === row.dataset.settingName) {
            var value = row.querySelector('.ss-value').textContent.trim();
            setModuleEnabled(modules, id, value === 'true');
        }
        updateModuleWarning(modules, id);
    }

    /* ------------------------------------------------------------- probes */

    function enqueueProbe(job) {
        probeQueue.push(job);
        pumpProbes();
    }

    function pumpProbes() {
        while (probesRunning < MAX_PARALLEL_PROBES && probeQueue.length) {
            runProbe(probeQueue.shift());
        }
    }

    function runProbe(job) {
        if (job.mode === 'card' && !document.contains(job.el)) {
            return;
        }
        probesRunning++;
        var url = config.diagnosticBase + '/' + encodeURIComponent(job.probe) + (job.mode === 'summary' ? '?summary=1' : '');
        fetch(url, { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return job.mode === 'summary' ? response.json() : response.text();
            })
            .then(function (result) {
                if (job.mode === 'summary') {
                    setVerdict(job.probe, result);
                    return;
                }
                if (!document.contains(job.el)) {
                    return;
                }
                var card = parseHtml(result);
                job.el.replaceWith(card);
                runScripts(card);
                updateAges(card);
                initProbeCard(card);
                setVerdict(job.probe, {
                    level: parseInt(card.dataset.ssLevel, 10),
                    label: card.dataset.ssLabel,
                    summary: card.dataset.ssSummary,
                    at: parseInt(card.dataset.ssAt, 10),
                });
            })
            .catch(function () {
                if (job.mode === 'summary') {
                    markTileFailed(job.probe);
                    return;
                }
                if (document.contains(job.el)) {
                    job.el.removeAttribute('data-ss-probe-pending');
                    var body = job.el.querySelector('.card-body');
                    if (body) {
                        body.innerHTML = '<div class="d-flex align-items-center gap-2 text-danger">'
                            + '<i class="fas fa-triangle-exclamation"></i>' + escapeHtml(L.probeFailed)
                            + '<button type="button" class="btn btn-sm btn-outline-secondary ms-auto" data-ss-probe-rerun="'
                            + escapeHtml(job.probe) + '"><i class="fas fa-rotate me-1"></i>' + escapeHtml(L.retry) + '</button></div>';
                    }
                }
            })
            .finally(function () {
                probesRunning--;
                pumpProbes();
            });
    }

    function rerunProbe(card) {
        if (!card) {
            return;
        }
        card.classList.add('ss-probe-busy');
        card.querySelectorAll('[data-ss-probe-rerun]').forEach(function (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>';
        });
        enqueueProbe({ probe: card.dataset.ssProbe, mode: 'card', el: card });
    }

    function setVerdict(probe, verdict) {
        verdicts[probe] = verdict;
        updateDots();
        content.querySelectorAll('[data-ss-tile="' + CSS.escape(probe) + '"]').forEach(function (tile) {
            paintTile(tile, verdict);
        });
        updateHealthSummary();
    }

    function updateDots() {
        shell.querySelectorAll('[data-ss-dot]').forEach(function (dot) {
            var worst = null;
            dot.dataset.ssDot.split(' ').forEach(function (probe) {
                if (verdicts[probe]) {
                    var level = verdicts[probe].level === 3 ? 2 : verdicts[probe].level;
                    worst = worst === null ? level : Math.min(worst, level);
                }
            });
            dot.className = 'ss-dot ' + (worst === null ? 'ss-dot-unknown' : 'ss-dot-' + worst);
        });
    }

    function initTiles(root) {
        var now = Date.now() / 1000;
        root.querySelectorAll('[data-ss-tile]').forEach(function (tile) {
            var at = parseInt(tile.dataset.ssAt, 10);
            if (!at || now - at > config.staleAfter) {
                queueTile(tile);
            }
        });
        updateHealthSummary();
    }

    function queueTile(tile) {
        tile.className = tile.className.replace(/\bss-tile-(lvl-\d|loading|failed)\b/g, '').trim() + ' ss-tile-loading';
        tile.querySelector('[data-ss-tile-age]').textContent = L.checking;
        enqueueProbe({ probe: tile.dataset.ssTile, mode: 'summary' });
        updateHealthSummary();
    }

    function paintTile(tile, verdict) {
        tile.className = tile.className.replace(/\bss-tile-(lvl-\d|loading|failed)\b/g, '').trim()
            + ' ss-tile-lvl-' + verdict.level;
        tile.dataset.ssAt = verdict.at;
        tile.querySelector('[data-ss-tile-label]').textContent = verdict.label || '';
        tile.querySelector('[data-ss-tile-summary]').textContent = verdict.summary || '';
        tile.querySelector('[data-ss-tile-age]').textContent = relativeAge(verdict.at);
    }

    function markTileFailed(probe) {
        content.querySelectorAll('[data-ss-tile="' + CSS.escape(probe) + '"]').forEach(function (tile) {
            tile.className = tile.className.replace(/\bss-tile-(lvl-\d|loading|failed)\b/g, '').trim() + ' ss-tile-failed';
            tile.querySelector('[data-ss-tile-label]').textContent = L.probeFailed;
            tile.querySelector('[data-ss-tile-age]').textContent = '';
        });
        updateHealthSummary();
    }

    function updateHealthSummary() {
        var summary = content.querySelector('[data-ss-health-summary]');
        if (!summary) {
            return;
        }
        var tiles = content.querySelectorAll('[data-ss-tile]');
        var pending = content.querySelectorAll('[data-ss-tile].ss-tile-loading').length;
        summary.textContent = pending
            ? fmt(L.healthProgress, tiles.length - pending, tiles.length)
            : L.healthDone;
    }

    /* ----------------------------------- diagnostics & maintenance actions */

    function initProbeCard(card) {
        var target = card.querySelector('[data-dg-submodule-target]');
        if (target) {
            loadSubmodules(target);
        }
    }

    function loadSubmodules(target) {
        target.innerHTML = '<div class="text-center p-3"><div class="spinner-border spinner-border-sm"></div></div>';
        fetch(baseurl + '/servers/getSubmodulesStatus/', { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            })
            .then(function (html) { target.innerHTML = html; })
            .catch(function () {
                target.innerHTML = '<div class="text-danger small">' + escapeHtml(L.submodulesFailed) + '</div>';
            });
    }

    window.submitSubmoduleUpdate = function (clicked) {
        var path = clicked.dataset.submodule;
        fetch(baseurl + '/servers/getSubmoduleQuickUpdateForm/' + (path ? btoa(path) : ''), { headers: XHR, credentials: 'same-origin' })
            .then(function (response) { return response.text(); })
            .then(function (html) {
                var holder = document.createElement('div');
                holder.className = 'd-none';
                holder.innerHTML = html;
                var form = holder.querySelector('form');
                if (!form) {
                    throw new Error('no form');
                }
                document.body.appendChild(holder);
                return postForm(form).finally(function () { holder.remove(); });
            })
            .then(function (data) {
                toast(data.status ? (data.output || L.ok) : (data.output || L.checkFailed), data.status ? 'success' : 'danger');
                var target = content.querySelector('[data-dg-submodule-target]');
                if (target) {
                    loadSubmodules(target);
                }
            })
            .catch(function () { toast(L.checkFailed, 'danger'); });
    };

    window.dgConfirm = function (id) {
        var confirmations = {};
        content.querySelectorAll('script[data-ss-confirmations]').forEach(function (node) {
            Object.assign(confirmations, JSON.parse(node.textContent));
        });
        var confirmation = confirmations[id];
        var trigger = document.getElementById(id);
        if (!confirmation || !trigger) {
            return;
        }
        showConfirmModal({
            title: confirmation.title,
            body: confirmation.body,
            confirmLabel: confirmation.label,
            confirmClass: confirmation.cls,
            cancelLabel: L.cancel,
            onConfirm: function () { trigger.click(); },
        });
    };

    var CHECKS = {
        'orphan-attr': { url: '/attributes/checkOrphanedAttributes/', bad: 'recommended' },
        'bad-attachments': { url: '/attributes/checkAttachments/', bad: 'badLinks' },
    };

    function handleDiagnosticAction(target) {
        var scope = target.closest('.dg-scope');
        var check = target.closest('[data-dg-check]');
        if (check && scope) {
            runCheck(scope, check);
            return true;
        }
        var zmq = target.closest('[data-dg-zmq]');
        if (zmq) {
            zmq.disabled = true;
            fetch(baseurl + '/servers/' + zmq.dataset.dgZmq + 'ZeroMQServer/', { headers: XHR, credentials: 'same-origin' })
                .then(function (response) { return response.json(); })
                .then(function (data) {
                    toast(data.saved ? data.success : (data.errors || L.zmqFailed), data.saved ? 'success' : 'danger');
                })
                .catch(function () { toast(L.zmqFailed, 'danger'); })
                .finally(function () { zmq.disabled = false; });
            return true;
        }
        var json = target.closest('[data-dg-update-json]');
        if (json) {
            json.disabled = true;
            fetch(baseurl + '/servers/updateJSON/', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': window.csrfToken || '' },
            })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.json();
                })
                .then(function () { toast(L.jsonLoaded, 'success'); })
                .catch(function () { toast(L.jsonFailed, 'danger'); })
                .finally(function () { json.disabled = false; });
            return true;
        }
        var submodules = target.closest('[data-dg-submodules]');
        if (submodules) {
            var holder = submodules.closest('.dg-scope').querySelector('[data-dg-submodule-target]');
            if (holder) {
                loadSubmodules(holder);
            }
            return true;
        }
        return false;
    }

    function runCheck(scope, button) {
        var name = button.dataset.dgCheck;
        if (name === 'deprecated') {
            var output = scope.querySelector('[data-dg-out="deprecated-body"]');
            button.disabled = true;
            fetch(baseurl + '/api/viewDeprecatedFunctionUse', { headers: XHR, credentials: 'same-origin' })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.text();
                })
                .then(function (html) {
                    output.innerHTML = html;
                    output.classList.remove('d-none');
                })
                .catch(function () { toast(L.checkFailed, 'danger'); })
                .finally(function () { button.disabled = false; });
            return;
        }
        var check = CHECKS[name];
        var slot = scope.querySelector('[data-dg-out="' + name + '"]');
        if (!check || !slot) {
            return;
        }
        button.disabled = true;
        slot.textContent = '…';
        fetch(baseurl + check.url, { headers: XHR, credentials: 'same-origin', cache: 'no-store' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            })
            .then(function (text) {
                var count = text.trim();
                var zero = count === '0';
                slot.innerHTML = '<span class="ss-prio ss-lvl-' + (zero ? 2 : 0) + '">'
                    + '<i class="fas fa-' + (zero ? 'circle-check' : 'circle-xmark') + '"></i>'
                    + escapeHtml(count) + (zero ? '' : ' — ' + escapeHtml(L[check.bad])) + '</span>';
            })
            .catch(function () {
                slot.textContent = L.checkFailed;
                toast(L.checkFailed, 'danger');
            })
            .finally(function () { button.disabled = false; });
    }

    /* ------------------------------------------------------------- search */

    var searchModal, searchInput, searchResults;

    function initSearch() {
        searchModal = document.getElementById('ssSearchModal');
        searchInput = document.getElementById('ssSearchInput');
        searchResults = document.getElementById('ssSearchResults');
        if (!searchModal) {
            return;
        }
        searchModal.addEventListener('shown.bs.modal', function () {
            searchInput.focus();
            searchInput.select();
        });
        searchInput.addEventListener('input', renderSearch);
        searchInput.addEventListener('keydown', function (event) {
            var items = Array.prototype.slice.call(searchResults.querySelectorAll('.ss-search-result'));
            var index = items.indexOf(searchResults.querySelector('.ss-search-result.active'));
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                if (!items.length) {
                    return;
                }
                index = event.key === 'ArrowDown' ? Math.min(index + 1, items.length - 1) : Math.max(index - 1, 0);
                setActiveResult(items, index);
            } else if (event.key === 'Enter' && index >= 0) {
                event.preventDefault();
                items[index].click();
            }
        });
        searchResults.addEventListener('click', function (event) {
            var result = event.target.closest('.ss-search-result');
            if (!result) {
                return;
            }
            bootstrap.Modal.getOrCreateInstance(searchModal).hide();
            navigate(result.dataset.dest, {
                push: true,
                setting: result.dataset.setting,
                hash: '#setting=' + encodeURIComponent(result.dataset.setting),
            });
        });
    }

    function setActiveResult(items, index) {
        items.forEach(function (item, i) {
            item.classList.toggle('active', i === index);
            item.setAttribute('aria-selected', i === index ? 'true' : 'false');
        });
        if (items[index]) {
            items[index].scrollIntoView({ block: 'nearest' });
        }
    }

    function openSearch() {
        if (!searchModal || !window.bootstrap) {
            return;
        }
        bootstrap.Modal.getOrCreateInstance(searchModal).show();
        loadSearchIndex().then(renderSearch);
        renderSearch();
    }

    function loadSearchIndex() {
        if (searchIndex) {
            return Promise.resolve(searchIndex);
        }
        if (!searchIndexLoading) {
            // No Accept: application/json — that makes it a REST call, answered with the legacy report.
            searchIndexLoading = fetch(urlFor('searchIndex'), { headers: XHR, credentials: 'same-origin' })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.json();
                })
                .then(function (index) {
                    searchIndex = index.map(function (entry) {
                        entry.haystack = (entry.name + ' ' + entry.description).toLowerCase();
                        entry.lowerName = entry.name.toLowerCase();
                        return entry;
                    });
                    return searchIndex;
                })
                .catch(function () {
                    searchIndexLoading = null;
                    return null;
                });
        }
        return searchIndexLoading;
    }

    function renderSearch() {
        var query = searchInput.value.trim().toLowerCase();
        if (!query) {
            searchResults.innerHTML = '<p class="text-muted small p-2 mb-0">' + escapeHtml(L.searchHint) + '</p>';
            return;
        }
        if (!searchIndex) {
            searchResults.innerHTML = '<p class="text-muted small p-2 mb-0"><span class="spinner-border spinner-border-sm me-2"></span>'
                + escapeHtml(L.searchLoading) + '</p>';
            return;
        }
        var terms = query.split(/\s+/);
        var tierWeight = { essential: 3, standard: 2, advanced: 1, deprecated: 0 };
        var hits = [];
        searchIndex.forEach(function (entry) {
            for (var i = 0; i < terms.length; i++) {
                if (entry.haystack.indexOf(terms[i]) === -1) {
                    return;
                }
            }
            var score = tierWeight[entry.tier] || 0;
            if (entry.lowerName.indexOf(terms[0]) !== -1) {
                score += 10;
            }
            if (entry.lowerName.split('.').pop().indexOf(terms[0]) === 0) {
                score += 5;
            }
            hits.push({ entry: entry, score: score });
        });
        hits.sort(function (a, b) { return b.score - a.score; });

        if (!hits.length) {
            searchResults.innerHTML = '<p class="text-muted small p-2 mb-0">' + escapeHtml(L.searchEmpty) + '</p>';
            return;
        }

        var groups = [];
        var byDestination = {};
        hits.slice(0, SEARCH_LIMIT).forEach(function (hit) {
            var key = hit.entry.destination;
            if (!byDestination[key]) {
                byDestination[key] = { title: hit.entry.destinationTitle, items: [] };
                groups.push(byDestination[key]);
            }
            byDestination[key].items.push(hit.entry);
        });

        var html = '';
        groups.forEach(function (group) {
            html += '<div class="ss-search-group"><div class="ss-eyebrow px-2 pt-2 pb-1">' + escapeHtml(group.title) + '</div>';
            group.items.forEach(function (entry) {
                html += '<button type="button" class="ss-search-result" role="option" aria-selected="false"'
                    + ' data-dest="' + escapeHtml(entry.destination) + '" data-setting="' + escapeHtml(entry.name) + '">'
                    + '<span class="ss-search-tier ss-tier-' + escapeHtml(entry.tier) + '">' + escapeHtml(L.tiers[entry.tier] || entry.tier) + '</span>'
                    + '<span class="min-w-0 flex-grow-1"><span class="ss-setting-name">' + escapeHtml(entry.name) + '</span>'
                    + (entry.description ? '<span class="d-block text-muted small text-truncate">' + escapeHtml(entry.description) + '</span>' : '')
                    + '</span>'
                    + (entry.error ? '<span class="ss-prio ss-lvl-' + (entry.level < 3 ? entry.level : 3) + '">' + escapeHtml(L.inError) + '</span>' : '')
                    + '</button>';
            });
            html += '</div>';
        });
        if (hits.length > SEARCH_LIMIT) {
            html += '<p class="text-muted small p-2 mb-0">' + escapeHtml(fmt(L.searchMore, hits.length - SEARCH_LIMIT)) + '</p>';
        }
        searchResults.innerHTML = html;
        setActiveResult(Array.prototype.slice.call(searchResults.querySelectorAll('.ss-search-result')), 0);
    }
})();
