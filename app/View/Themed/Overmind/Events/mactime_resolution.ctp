<?php
/**
 * Forensic analysis (Mactime)
 *
 * The raw Mactime file is parsed CLIENT-SIDE (vanilla port of the legacy
 * processString) into a selectable table; "Create objects" serialises the
 * checked rows into SelectedData.mactime_data and AJAX-POSTs the tokened form
 * back to /events/upload_analysis_file/{id} (POST 2), which creates one
 * mactime-timeline-analysis object per row.
 *
 * Vars: $eventId, $file_uploaded, $file_name, $file_content.
 */
$eventId = (int)$eventId;
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Forensic analysis · Mactime'),
    'title' => __('Select timeline entries'),
    'titleBadge' => empty($file_name) ? '' : sprintf(
        '<span class="badge rounded-pill text-bg-light border fw-normal">'
            . '<i class="fas fa-file me-1"></i>%s</span>',
        h($file_name)
    ),
    'icon' => 'fas fa-microscope',
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4" style="background:var(--bs-tertiary-bg, #f8f9fa);">

    <p class="text-muted">
        <?= __('Each selected line below becomes a Mactime timeline object (the uploaded file is attached to each one). Pick the entries you want to import.') ?>
    </p>

    <?php
    // Tokened form holds only what the object-creation POST reads. The table is
    // rendered/scanned by JS (name-less), so FormData posts just these + token.
    // mactime_file_content is a textarea (preserves newlines; CakePHP does not
    // value-lock textareas the way it locks hidden fields).
    echo $this->Form->create('SelectedData', [
        'url' => $baseurl . '/events/upload_analysis_file/' . $eventId,
        'id'  => 'mactimeForm',
    ]);
    echo $this->Form->input('mactime_data', [
        'label' => false, 'div' => false, 'type' => 'text',
        'id' => 'mactimeData', 'value' => '', 'style' => 'display:none;',
    ]);
    echo $this->Form->input('mactime_file_content', [
        'label' => false, 'div' => false, 'type' => 'textarea',
        'id' => 'mactimeFileContent', 'value' => $file_content ?? '', 'style' => 'display:none;',
    ]);
    echo $this->Form->input('mactime_file_name', [
        'label' => false, 'div' => false, 'type' => 'text',
        'id' => 'mactimeFileName', 'value' => $file_name ?? '', 'style' => 'display:none;',
    ]);
    echo $this->Form->end();
    ?>

    <!-- toolbar: filter + select-all + count -->
    <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
        <div class="input-group input-group-sm" style="max-width:320px;">
            <span class="input-group-text bg-white"><i class="fas fa-magnifying-glass text-muted"></i></span>
            <input type="text" class="form-control" id="mactimeFilter" placeholder="<?= __('Filter by file path…') ?>">
        </div>
        <div class="form-check ms-1 mb-0">
            <input type="checkbox" class="form-check-input" id="mactimeCheckAll">
            <label class="form-check-label small" for="mactimeCheckAll"><?= __('Select all') ?></label>
        </div>
        <span class="text-muted small ms-auto">
            <span id="mactimeSelCount">0</span> / <span id="mactimeTotal">0</span> <?= __('selected') ?>
        </span>
    </div>

    <div class="card border-0 shadow-sm">
        <div style="max-height:55vh; overflow-y:auto;">
            <table class="table table-sm table-hover align-middle mb-0">
                <thead class="table-light" style="position:sticky; top:0; z-index:1;">
                    <tr>
                        <th style="width:2.2rem;"></th>
                        <th><?= __('File path') ?></th>
                        <th><?= __('Activity') ?></th>
                        <th><?= __('Time accessed') ?></th>
                        <th><?= __('Size') ?></th>
                        <th><?= __('Permissions') ?></th>
                    </tr>
                </thead>
                <tbody id="mactimeRows"></tbody>
            </table>
        </div>
        <div id="mactimeEmpty" class="p-4 text-center text-muted d-none">
            <i class="fas fa-inbox me-1"></i><?= __('No timeline entries were found in this file.') ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'meta' => [['label' => __('Event'), 'id' => $eventId]],
        'buttons' => [[
            'label' => __('Back'),
            'icon' => 'fas fa-arrow-left',
            'attrs' => ['onclick' => sprintf("openModalChained('%s/events/populateFrom/%s');", $baseurl, $eventId)],
        ]],
        'submit' => [
            'label' => __('Create objects'),
            'icon' => 'fas fa-cubes',
            'id' => 'mactimeCreate',
            'type' => 'button',
            'disabled' => true,
        ],
    ]) ?>
</div>

<script>
(function () {
    var EVENT_ID  = <?= $eventId ?>;
    var FILE_NAME = document.getElementById('mactimeFileName').value;

    var rowsEl   = document.getElementById('mactimeRows');
    var emptyEl  = document.getElementById('mactimeEmpty');
    var formEl   = document.getElementById('mactimeForm');
    var createBtn = document.getElementById('mactimeCreate');
    var checkAll = document.getElementById('mactimeCheckAll');
    var filterEl = document.getElementById('mactimeFilter');
    var selCount = document.getElementById('mactimeSelCount');
    var totalEl  = document.getElementById('mactimeTotal');

    if (formEl) { formEl.addEventListener('submit', function (e) { e.preventDefault(); }); }

    // ── Parse one Mactime line (vanilla port of the legacy processString) ──
    var reFull = /(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\d\d?).+?(\d\d\d\d)\s([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]/;
    var reTime = /([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]/;
    function parseLine(text) {
        if (!reTime.test(text)) { return null; }
        var timeAccessed = '';
        var full = reFull.exec(text);
        if (full) { timeAccessed = full[0]; text = text.replace(full[0], '').trim(); }
        text = text.replace(/[\n\r]/g, '').trim();
        var parts = text.split(/\s+/);
        var activityType = parts[1] || '';
        var activity = [];
        if (activityType.indexOf('a') !== -1) { activity.push('Accessed'); }
        if (activityType.indexOf('b') !== -1) { activity.push('Created'); }
        if (activityType.indexOf('c') !== -1) { activity.push('Changed'); }
        if (activityType.indexOf('m') !== -1) { activity.push('Modified'); }
        var filepath = parts[6] || '';
        if (parts[7]) { filepath += parts[7]; }
        return {
            filepath: filepath,
            size: parts[0] || '',
            activity: activity.join(','),
            time: timeAccessed,
            permissions: parts[2] || ''
        };
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    // ── Build the table from the uploaded file content ──
    var lines = (document.getElementById('mactimeFileContent').value || '').split('\n');
    var html = '';
    lines.forEach(function (line) {
        var p = parseLine(line);
        if (!p) { return; }
        var badges = p.activity
            ? p.activity.split(',').map(function (a) {
                  return '<span class="badge bg-light text-dark border me-1">' + escapeHtml(a) + '</span>';
              }).join('')
            : '<span class="text-muted">—</span>';
        html +=
            '<tr class="mt-row"' +
                ' data-filepath="' + escapeHtml(p.filepath) + '"' +
                ' data-size="' + escapeHtml(p.size) + '"' +
                ' data-activity="' + escapeHtml(p.activity) + '"' +
                ' data-time="' + escapeHtml(p.time) + '"' +
                ' data-permissions="' + escapeHtml(p.permissions) + '">' +
                '<td><input type="checkbox" class="form-check-input mt-check"></td>' +
                '<td class="font-monospace small text-break">' + escapeHtml(p.filepath) + '</td>' +
                '<td>' + badges + '</td>' +
                '<td class="small text-nowrap">' + escapeHtml(p.time) + '</td>' +
                '<td class="small text-nowrap">' + escapeHtml(p.size) + '</td>' +
                '<td class="small text-nowrap font-monospace">' + escapeHtml(p.permissions) + '</td>' +
            '</tr>';
    });
    rowsEl.innerHTML = html;

    var allRows = Array.prototype.slice.call(rowsEl.querySelectorAll('.mt-row'));
    totalEl.textContent = allRows.length;
    if (allRows.length === 0) { emptyEl.classList.remove('d-none'); }

    function refreshCount() {
        var n = rowsEl.querySelectorAll('.mt-check:checked').length;
        selCount.textContent = n;
        createBtn.disabled = (n === 0);
    }

    rowsEl.addEventListener('change', function (e) {
        if (e.target.classList.contains('mt-check')) { refreshCount(); }
    });

    if (checkAll) {
        checkAll.addEventListener('change', function () {
            allRows.forEach(function (r) {
                if (r.style.display !== 'none') { r.querySelector('.mt-check').checked = checkAll.checked; }
            });
            refreshCount();
        });
    }

    if (filterEl) {
        filterEl.addEventListener('input', function () {
            var q = filterEl.value.toLowerCase();
            allRows.forEach(function (r) {
                r.style.display = r.dataset.filepath.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
            });
        });
    }

    if (createBtn) {
        createBtn.addEventListener('click', function () {
            var selected = [];
            allRows.forEach(function (r) {
                if (!r.querySelector('.mt-check').checked) { return; }
                selected.push({
                    filepath: r.dataset.filepath,
                    file_size: r.dataset.size,
                    activity_type: r.dataset.activity,
                    time_accessed: r.dataset.time,
                    permissions: r.dataset.permissions,
                    file_name: FILE_NAME
                });
            });
            if (selected.length === 0) { return; }
            document.getElementById('mactimeData').value = JSON.stringify(selected);
            createBtn.disabled = true;
            fetch(formEl.getAttribute('action'), {
                method: 'POST',
                body: new FormData(formEl),
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            })
            .then(function (r) { return r.text(); })
            .then(function () { window.location = baseurl + '/events/view2/' + EVENT_ID; })
            .catch(function () { createBtn.disabled = false; });
        });
    }
})();
</script>
