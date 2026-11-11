<?php
/**
 * A settings tab rendered as one collapsible card per thematic section, with a
 * search bar filtering every setting of the tab.
 *
 * Sections come from ServerSettingGroups::split(); each row is delegated to
 * `healthElementsBS5/setting_row`, which is also what the reload endpoint
 * renders when a setting has just been edited.
 *
 * Params:
 *  - tab      string
 *  - sections array from ServerSettingGroups::split()
 */

App::uses('ServerSettingGroups', 'Tools');

$uid = 'ss' . dechex(mt_rand());
$levels = ServerSettingGroups::levels();
$autoOpenMaxRows = 30;

$openSections = array();
foreach ($sections as $index => $section) {
    if (!empty($section['errorsByLevel'][0])) {
        $openSections[$index] = true;
    }
}
if (empty($openSections) && !empty($sections) && count($sections[0]['settings']) <= $autoOpenMaxRows) {
    $openSections[0] = true;
}

$rowIndex = 0;
?>
<div class="ss-scope" id="<?= h($uid) ?>">

    <!-- FILTER -->
    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <div class="d-flex flex-wrap gap-2 align-items-center">

                <div class="flex-grow-1" style="max-width: 600px">
                    <div class="input-group">
                        <input class="form-control"
                               type="text"
                               data-ss-search
                               autocomplete="off"
                               placeholder="<?= h(__('Search a setting of this tab by name, value or description')) ?>">
                        <button class="btn btn-primary" type="button" data-ss-search-button>
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>

                <div class="btn-group ms-auto" role="group">
                    <button type="button" class="btn btn-outline-primary" data-ss-expand>
                        <i class="fas fa-angles-down me-1"></i><?= __('Expand all') ?>
                    </button>
                    <button type="button" class="btn btn-outline-primary" data-ss-collapse>
                        <i class="fas fa-angles-up me-1"></i><?= __('Collapse all') ?>
                    </button>
                </div>

            </div>

            <div class="mt-2 d-none align-items-center flex-wrap gap-2" data-ss-active>
                <strong class="me-1"><?= __('Active filters') ?>:</strong>
                <span class="badge bg-primary" data-ss-chip></span>
                <span class="text-muted" style="font-size:.8rem;" data-ss-count></span>
                <button type="button" class="filter-clear-all btn btn-sm btn-outline-danger ms-auto" data-ss-clear>
                    <i class="fas fa-times"></i> <?= __('Clear all') ?>
                </button>
            </div>
        </div>
    </div>

    <!-- SECTIONS -->
    <?php foreach ($sections as $index => $section): ?>
        <?php
            $collapseId = $uid . '_' . $section['id'];
            $isOpen = !empty($openSections[$index]);
        ?>
        <div class="card shadow-sm mb-3 ss-section"
             data-ss-section
             style="--ss-accent: <?= h($section['accent']) ?>;">

            <div class="card-header ss-section-header <?= $isOpen ? '' : 'collapsed' ?>"
                 data-bs-toggle="collapse"
                 data-bs-target="#<?= h($collapseId) ?>"
                 aria-expanded="<?= $isOpen ? 'true' : 'false' ?>"
                 aria-controls="<?= h($collapseId) ?>">

                <span class="ss-section-icon">
                    <i class="fas fa-<?= h($section['icon']) ?>"></i>
                </span>

                <div class="flex-grow-1">
                    <div class="fw-semibold"><?= h($section['title']) ?></div>
                    <div class="text-muted" style="font-size:.78rem;"><?= h($section['description']) ?></div>
                </div>

                <?php // One pill per severity, counting the settings of the section that are not set or set incorrectly. ?>
                <?php foreach ($section['errorsByLevel'] as $level => $errorCount): ?>
                    <?php if (empty($errorCount)) { continue; } ?>
                    <span class="ss-prio ss-lvl-<?= (int)$level ?>"
                          title="<?= h(__('%s %s settings incorrectly or not set', $errorCount, $levels[$level]['label'])) ?>">
                        <i class="fas fa-<?= h($levels[$level]['icon']) ?>"></i>
                        <?= h($errorCount) ?>
                    </span>
                <?php endforeach; ?>

                <i class="fas fa-chevron-up ss-chevron"></i>
            </div>

            <div id="<?= h($collapseId) ?>" class="collapse <?= $isOpen ? 'show' : '' ?>">

                <?php if (!empty($section['errorsByLevel'][0])): ?>
                    <div class="ss-section-alert">
                        <i class="fas fa-triangle-exclamation me-1"></i>
                        <?= __('This section reports some potential critical misconfigurations.') ?>
                    </div>
                <?php endif; ?>

                <div class="table-responsive">
                    <table class="table table-sm align-middle ss-table mb-0">
                        <thead>
                            <tr>
                                <th class="ss-col-priority"><?= __('Priority') ?></th>
                                <th class="ss-col-setting"><?= __('Setting') ?></th>
                                <th class="ss-col-value"><?= __('Value') ?></th>
                                <th class="ss-col-description"><?= __('Description') ?></th>
                                <th class="ss-col-error"><?= __('Error message') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($section['settings'] as $setting): ?>
                                <?= $this->element('healthElementsBS5/setting_row', array(
                                    'setting' => $setting,
                                    'k' => $rowIndex++,
                                )) ?>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="p-3 text-muted d-none" data-ss-empty>
                    <?= __('No setting of this section matches the search.') ?>
                </div>
            </div>
        </div>
    <?php endforeach; ?>

    <div class="card shadow-sm d-none" data-ss-no-result>
        <div class="card-body text-center text-muted py-5">
            <div class="d-flex justify-content-center flex-column align-items-center">
                <i class="fas fa-magnifying-glass fa-2x mb-3 d-block opacity-50"></i>
                <?= __('No setting matches the search.') ?>
            </div>
        </div>
    </div>

</div>

<script>
(function () {
    const root = document.getElementById('<?= h($uid) ?>');
    if (!root || root.dataset.ssWired) return;
    root.dataset.ssWired = '1';

    const L = <?= json_encode(array(
        'search' => __('search'),
        'one' => __('1 setting'),
        'many' => __('%s settings'),
        'formFailed' => __('Could not load the edit form.'),
        'saveFailed' => __('The setting could not be saved.'),
        'saved' => __('Setting updated.'),
        'refreshFailed' => __('The setting was saved but the row could not be refreshed.'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    const XHR = { 'X-Requested-With': 'XMLHttpRequest' };

    const searchInput = root.querySelector('[data-ss-search]');
    const activeRow   = root.querySelector('[data-ss-active]');
    const chip        = root.querySelector('[data-ss-chip]');
    const counter     = root.querySelector('[data-ss-count]');
    const noResult    = root.querySelector('[data-ss-no-result]');
    const sections    = Array.from(root.querySelectorAll('[data-ss-section]'));

    /* -------------------------------------------------------------- search */

    function collapseOf(section) {
        return section.querySelector('.collapse');
    }

    function setCollapsed(section, collapsed) {
        const target = collapseOf(section);
        if (!target) return;
        const instance = bootstrap.Collapse.getOrCreateInstance(target, { toggle: false });
        collapsed ? instance.hide() : instance.show();
    }

    // Searchable text of a row: its own rendered text (priority, name, value,
    // description, error message), computed once and cached on the element —
    // never emitted by the server, which keeps the big tabs light.
    function haystack(row) {
        if (row.__ssSearch === undefined) {
            row.__ssSearch = row.textContent.toLowerCase().replace(/\s+/g, ' ');
        }
        return row.__ssSearch;
    }

    function applyFilter() {
        const term = (searchInput.value || '').trim().toLowerCase();
        let total = 0;

        sections.forEach(function (section) {
            const rows = Array.from(section.querySelectorAll('tr.ss-row'));
            let matches = 0;

            rows.forEach(function (row) {
                const hit = term === '' || haystack(row).indexOf(term) !== -1;
                row.classList.toggle('d-none', !hit);
                if (hit) matches++;
            });

            total += matches;
            section.classList.toggle('d-none', term !== '' && matches === 0);
            section.querySelector('[data-ss-empty]').classList.toggle('d-none', matches !== 0);
            section.querySelector('table').classList.toggle('d-none', matches === 0);

            // While searching, every section holding a hit is opened so the
            // results are readable without a second click.
            if (term !== '') {
                setCollapsed(section, matches === 0);
            }
        });

        const searching = term !== '';
        activeRow.classList.toggle('d-none', !searching);
        activeRow.classList.toggle('d-flex', searching);
        noResult.classList.toggle('d-none', !searching || total !== 0);

        if (searching) {
            chip.textContent = L.search + ': ' + term;
            counter.textContent = total === 1 ? L.one : L.many.replace('%s', total);
        }
    }

    searchInput.addEventListener('input', applyFilter);
    searchInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            applyFilter();
        }
    });
    root.querySelector('[data-ss-search-button]').addEventListener('click', applyFilter);
    root.querySelector('[data-ss-clear]').addEventListener('click', function () {
        searchInput.value = '';
        applyFilter();
    });

    root.querySelector('[data-ss-expand]').addEventListener('click', function () {
        sections.forEach(function (s) { setCollapsed(s, false); });
    });
    root.querySelector('[data-ss-collapse]').addEventListener('click', function () {
        sections.forEach(function (s) { setCollapsed(s, true); });
    });

    /* --------------------------------------------------------- inline edit */

    let openCell = null;

    function closeEditor() {
        if (!openCell) return;
        const form = openCell.querySelector('form');
        if (form) form.remove();
        openCell.querySelector('.ss-value').classList.remove('d-none');
        openCell.classList.remove('ss-editing');
        openCell = null;
    }

    async function openEditor(cell) {
        if (cell.classList.contains('ss-editing')) return;
        closeEditor();

        const setting = cell.dataset.setting;
        const id = cell.dataset.settingId;

        cell.classList.add('ss-editing');
        openCell = cell;

        let html;
        try {
            const response = await fetch(
                baseurl + '/servers/serverSettingsEdit/' + encodeURIComponent(setting) + '/' + encodeURIComponent(id),
                { headers: XHR }
            );
            if (!response.ok) throw new Error('HTTP ' + response.status);
            html = await response.text();
        } catch (e) {
            showToast(L.formFailed, 'danger');
            closeEditor();
            return;
        }

        cell.querySelector('.ss-value').classList.add('d-none');
        cell.insertAdjacentHTML('beforeend', html);

        const form = cell.querySelector('form');
        const field = form.querySelector('.ss-input');
        if (field) {
            field.focus();
            if (field.select) field.select();
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            save(cell, form, setting, id);
        });
        form.querySelector('[data-ss-cancel]').addEventListener('click', closeEditor);
        form.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                closeEditor();
            }
        });
    }

    async function save(cell, form, setting, id) {
        const submit = form.querySelector('[data-ss-accept]');
        submit.disabled = true;

        let result;
        try {
            const response = await fetch(form.action, {
                method: 'POST',
                headers: XHR,
                body: new URLSearchParams(new FormData(form))
            });
            result = await response.json();
        } catch (e) {
            submit.disabled = false;
            showToast(L.saveFailed, 'danger');
            return;
        }

        if (!result.saved) {
            submit.disabled = false;
            showToast(result.errors || L.saveFailed, 'danger');
            return;
        }

        showToast(result.success || L.saved, 'success');

        // Re-read the setting server-side: saving a value can clear (or raise)
        // its error state, which the row renders.
        const row = cell.closest('tr');
        try {
            const response = await fetch(
                baseurl + '/servers/serverSettingsReloadSetting/' + encodeURIComponent(setting) + '/' + encodeURIComponent(id),
                { headers: XHR }
            );
            if (!response.ok) throw new Error('HTTP ' + response.status);
            openCell = null;
            row.outerHTML = await response.text();
            applyFilter();
        } catch (e) {
            closeEditor();
            showToast(L.refreshFailed, 'warning');
        }
    }

    root.addEventListener('click', function (e) {
        const cell = e.target.closest('.ss-editable');
        if (cell && root.contains(cell) && !e.target.closest('form')) {
            openEditor(cell);
            return;
        }
        // A click anywhere else closes a pending editor.
        if (openCell && !e.target.closest('.ss-editing')) {
            closeEditor();
        }
    });

    root.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const cell = e.target.closest('.ss-editable');
        if (cell && !cell.classList.contains('ss-editing')) {
            e.preventDefault();
            openEditor(cell);
        }
    });
})();
</script>
