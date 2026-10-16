<?php

App::uses('ClassRegistry', 'Utility');

$eventId   = h($data['Event']['id'] ?? '');
$eventUuid = $data['Event']['uuid'] ?? '';
if ($eventUuid === '') {
    return;
}

$uid       = 'evt-analyst-' . $eventId;
$fetchUrl  = $baseurl . '/analystData/viewForObject/Event/'
    . rawurlencode($eventUuid) . '?embedded=1';
$analystCount = (int)ClassRegistry::init('Note')
    ->countForObjectRecursive($me, $eventUuid);

$canAdd = !empty($me['Role']['perm_analyst_data']);

$types = [
    'Note'         => [
        'color' => 'primary',
        'icon'  => 'misp-icon misp-icon-analyst-note misp-simple',
        'label' => __('Add note'),
    ],
    'Opinion'      => [
        'color' => 'success',
        'icon'  => 'misp-icon misp-icon-analyst-opinion misp-simple',
        'label' => __('Add opinion'),
    ],
    'Relationship' => [
        'color' => 'correlation',
        'icon'  => 'fas fa-diagram-project',
        'label' => __('Add relationship'),
    ],
];
?>

<div class="card shadow-sm mb-3 flex-grow-1" id="analyst-data-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">

            <!-- Icon + title + count -->
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:rgba(143,45,86,.12);">
                    <i class="fas fa-comment-dots text-analystData" style="font-size:1rem;"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Analyst data') ?></div>
                    <div class="small text-muted mt-1">
                        <?= $analystCount === 0
                            ? __('No analyst data')
                            : __n('%s entry', '%s entries', $analystCount, $analystCount) ?>
                    </div>
                </div>
            </div>

            <!-- Search -->
            <div class="input-group input-group-sm" style="max-width:260px;">
                <span class="input-group-text border-end-0 bg-white">
                    <i class="fas fa-search text-muted small"></i>
                </span>
                <input type="search"
                       id="<?= $uid ?>-search"
                       class="form-control border-start-0 ps-0"
                       placeholder="<?= __('Filter analyst data…') ?>"
                       autocomplete="off"
                       aria-label="<?= __('Filter analyst data') ?>">
            </div>

            <div class="d-flex align-items-center gap-2 flex-shrink-0" data-card-actions>
                <?php if ($canAdd): ?>
                    <?php foreach ($types as $type => $meta): ?>
                        <?php $addUrl = h($baseurl . '/analystData/add/' . $type . '/'
                            . rawurlencode($eventUuid) . '/Event'); ?>
                        <button type="button"
                                class="btn btn-sm btn-outline-<?= h($meta['color']) ?> flex-shrink-0 d-flex align-items-center gap-1"
                                onclick="openModal('<?= $addUrl ?>')">
                            <i class="<?= h($meta['icon']) ?>"></i>
                            <?= h($meta['label']) ?>
                        </button>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <?= $this->element('genericElementsBS5/Cards/actions_overflow_menu') ?>

        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body"
         data-collapse-tall="400">
        <div class="text-center py-4 text-muted">
            <div class="misp-loader misp-loader-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var body     = document.getElementById(uid + '-body');
    if (!body) { return; }

    fetch(fetchUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.text();
        })
        .then(function (html) {
            body.innerHTML = html;
            wireSearch();
        })
        .catch(function () {
            body.innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load analyst data.')) ?>
                + '</div>';
        });

    /* Filters the top-level entries on their text; a section left empty
       disappears with them. */
    function wireSearch() {
        var search = document.getElementById(uid + '-search');
        if (!search) { return; }
        var noResult = document.createElement('div');
        noResult.className = 'text-center text-muted small py-4 d-none';
        noResult.innerHTML = '<i class="fas fa-filter-circle-xmark me-1 opacity-50"></i>';
        noResult.appendChild(document.createTextNode(<?= json_encode(__('No analyst data matches this filter.')) ?>));
        body.appendChild(noResult);

        function apply() {
            var q = search.value.toLowerCase().trim();
            var shown = 0;
            body.querySelectorAll('[data-ad-section]').forEach(function (section) {
                var visible = 0;
                section.querySelectorAll('[data-ad-entry]').forEach(function (entry) {
                    var match = q === '' || entry.textContent.toLowerCase().indexOf(q) !== -1;
                    entry.classList.toggle('d-none', !match);
                    if (match) { visible++; }
                });
                section.classList.toggle('d-none', visible === 0);
                shown += visible;
            });
            noResult.classList.toggle('d-none', shown !== 0 || q === '');
        }
        search.addEventListener('input', apply);
        if (search.value) { apply(); }
    }
}());
</script>
