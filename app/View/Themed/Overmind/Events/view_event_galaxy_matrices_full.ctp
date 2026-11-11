<?php
$uid = 'matrixFull' . (int)$eventId;
$base = $baseurl . '/events/viewEventGalaxyMatrices/' . (int)$eventId
    . ($extensionSuffix ?? '') . '/full:1';
$galaxyId = $matrix['galaxy']['id'] ?? 0;
$platformUrl = function ($position) use ($base, $galaxyId) {
    return $base . '/galaxy:' . $galaxyId . '/platform:' . $position;
};

/* The busiest platforms are tabs (at most three), the rest wait behind "More";
 * the selected one is always a tab, even when it was picked from the menu. */
$tabs = [];
$more = [];
if ($matrix) {
    $ranked = $matrix['platforms'];
    uksort($ranked, function ($a, $b) use ($ranked) {
        return [$ranked[$b]['used'], $ranked[$b]['size'], $a] <=> [$ranked[$a]['used'], $ranked[$a]['size'], $b];
    });
    $top = reset($ranked)['used'];
    foreach ($ranked as $position => $platform) {
        $isTab = $position === $matrix['platform']
            || (count($tabs) < 3 && ($top === 0 || $platform['used'] === $top));
        if ($isTab) {
            $tabs[$position] = $platform;
        } else {
            $more[$position] = $platform;
        }
    }
}

$renderCell = function (array $cell) use ($baseurl) {
    $classes = 'd-flex align-items-center gap-2 flex-grow-1 overflow-hidden px-2 py-1 rounded-1 small text-body text-decoration-none';
    $style = '';
    $tipState = '';
    if ($cell['state'] === 'event') {
        $classes .= ' border-start border-3 border-galaxy bg-galaxy bg-opacity-10';
        $tipState = __('On the event');
    } elseif ($cell['state'] === 'indicator') {
        $classes .= ' border border-galaxy';
        $style = '--bs-border-style: dashed;';
    }
    if ($cell['indicators']) {
        $onIndicators = __n('On %s indicator', 'On %s indicators', $cell['indicators'], $cell['indicators']);
        $tipState = $tipState === '' ? $onIndicators : $tipState . ' · ' . $onIndicators;
    }
    return sprintf(
        '<a href="%s" target="_blank" rel="noopener" class="%s" style="%s" data-tip-name="%s" data-tip-id="%s" data-tip-state="%s">'
            . '<span class="idx-clamp-2 lh-sm">%s</span>'
            . '<span class="ms-auto font-monospace fw-semibold text-body-secondary flex-shrink-0" style="font-size:.7rem;">%s</span>'
            . '</a>',
        h($baseurl . '/galaxy_clusters/view/' . $cell['id']),
        $classes,
        $style,
        h($cell['name']),
        h($cell['external_id']),
        h($tipState),
        h($cell['name']),
        h($cell['external_id'])
    );
};
?>
<div id="<?= $uid ?>" class="position-absolute top-0 bottom-0 start-0 end-0 d-flex flex-column bg-body">

    <div class="d-flex align-items-center gap-3 px-3 py-2 border-bottom flex-wrap">
        <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0 bg-galaxy bg-opacity-10"
             style="width:36px;height:36px;">
            <i class="<?= h($this->FontAwesome->getClass(($matrix['galaxy']['icon'] ?? '') ?: 'map')) ?> text-galaxy"></i>
        </div>
        <h5 class="mb-0 text-truncate"><?= h($matrix['galaxy']['name'] ?? __('Galaxy matrix')) ?></h5>

        <?php if (count($matrices) > 1): ?>
        <div class="d-flex align-items-center gap-1">
            <?php foreach ($matrices as $candidate):
                $on = $candidate['id'] === $galaxyId;
            ?>
            <button type="button"
                    class="btn btn-sm <?= $on ? 'border bg-body fw-semibold shadow-sm' : 'border-0 text-body-secondary' ?>"
                    data-matrix-url="<?= h($base . '/galaxy:' . $candidate['id']) ?>"
                    aria-pressed="<?= $on ? 'true' : 'false' ?>">
                <?= h($candidate['name']) ?>
            </button>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <div class="ms-auto d-flex align-items-center gap-3 small text-body-secondary">
            <span class="d-flex align-items-center gap-1">
                <span class="d-inline-block rounded-1 bg-galaxy" style="width:10px;height:10px;"></span>
                <?= __('On the event') ?>
            </span>
            <span class="d-flex align-items-center gap-1">
                <span class="d-inline-block rounded-1 border border-galaxy" style="width:10px;height:10px;--bs-border-style:dashed;"></span>
                <?= __('Only on indicators') ?>
            </span>
            <div class="form-check form-switch form-switch-galaxy mb-0">
                <input class="form-check-input" type="checkbox" role="switch"
                       id="<?= $uid ?>-hide" <?= $hideUnused ? 'checked' : '' ?>>
                <label class="form-check-label" for="<?= $uid ?>-hide"><?= __('Hide unused columns') ?></label>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
        </div>
    </div>

    <?php if ($matrix && count($matrix['platforms']) > 1): ?>
    <div class="d-flex align-items-center gap-1 px-3 py-2 border-bottom flex-wrap">
        <?php foreach ($tabs as $position => $platform):
            $on = $position === $matrix['platform'];
        ?>
        <button type="button"
                class="btn btn-sm d-flex align-items-center gap-2 <?= $on ? 'border bg-body fw-semibold shadow-sm' : 'border-0 text-body-secondary' ?>"
                data-matrix-url="<?= h($platformUrl($position)) ?>"
                aria-pressed="<?= $on ? 'true' : 'false' ?>">
            <?= h($platform['label']) ?>
            <?php if ($platform['used']): ?>
                <span class="badge rounded-pill bg-galaxy bg-opacity-10 text-galaxy"><?= $platform['used'] ?></span>
            <?php endif; ?>
        </button>
        <?php endforeach; ?>

        <?php if ($more): ?>
        <div class="dropdown">
            <button type="button" class="btn btn-sm border-0 text-body-secondary dropdown-toggle"
                    data-bs-toggle="dropdown" aria-expanded="false">
                <?= __('More') ?>
            </button>
            <ul class="dropdown-menu" style="max-height:60vh;overflow-y:auto;">
                <?php foreach ($more as $position => $platform): ?>
                <li>
                    <button type="button" class="dropdown-item d-flex align-items-center gap-3"
                            data-matrix-url="<?= h($platformUrl($position)) ?>">
                        <?= h($platform['label']) ?>
                        <?php if ($platform['used']): ?>
                            <span class="ms-auto badge rounded-pill bg-galaxy bg-opacity-10 text-galaxy"><?= $platform['used'] ?></span>
                        <?php endif; ?>
                    </button>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <div class="flex-grow-1 overflow-auto p-2" data-matrix-scroll>
    <?php if (!$matrix): ?>
        <div class="text-center text-body-secondary py-5">
            <?= __('None of this event\'s galaxy clusters belongs to a matrix.') ?>
        </div>
    <?php else: ?>
        <div class="d-flex align-items-start gap-2" style="min-width:max-content;">
        <?php foreach ($matrix['columns'] as $column): ?>
            <div class="border rounded-2 bg-body flex-shrink-0" style="width:176px;"
                 data-matrix-column data-used="<?= $column['used'] ?>">
                <div class="d-flex align-items-center gap-2 px-2 py-2 border-bottom small fw-bold lh-sm">
                    <span><?= h($column['label']) ?></span>
                    <span class="ms-auto fw-normal text-body-secondary text-nowrap">
                        <?= $column['used'] ? $column['used'] . ' / ' . $column['total'] : $column['total'] ?>
                    </span>
                </div>
                <div class="d-flex flex-column gap-1 p-1">
                <?php foreach ($column['cells'] as $cell):
                    $open = $cell['subs_used'] > 0;
                ?>
                    <div data-matrix-cell>
                        <div class="d-flex align-items-center">
                            <?php if ($cell['subs']): ?>
                            <button type="button"
                                    class="btn btn-sm p-0 border-0 flex-shrink-0 <?= $open ? 'text-galaxy' : 'text-body-secondary' ?>"
                                    style="width:14px;"
                                    data-matrix-toggle aria-expanded="<?= $open ? 'true' : 'false' ?>"
                                    title="<?= h(__n('%s sub-technique', '%s sub-techniques', count($cell['subs']), count($cell['subs']))) ?>">
                                <i class="fas fa-chevron-right <?= $open ? 'fa-rotate-90' : '' ?>" style="font-size:.6rem;"></i>
                            </button>
                            <?php else: ?>
                            <span class="flex-shrink-0" style="width:14px;"></span>
                            <?php endif; ?>
                            <?= $renderCell($cell) ?>
                        </div>
                        <?php if ($cell['subs']): ?>
                        <div class="flex-column gap-1 mt-1 ps-3 <?= $open ? 'd-flex' : 'd-none' ?>" data-matrix-subs>
                            <?php foreach ($cell['subs'] as $sub): ?>
                                <?= $renderCell($sub) ?>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>
    </div>

    <div class="position-fixed d-none bg-body border rounded-2 shadow px-2 py-1 small"
         style="z-index:1090;pointer-events:none;max-width:260px;" data-matrix-tip>
        <div class="fw-semibold" data-tip-field="name"></div>
        <div class="font-monospace fw-semibold text-body-secondary" style="font-size:.7rem;" data-tip-field="id"></div>
        <div class="text-galaxy" style="font-size:.7rem;" data-tip-field="state"></div>
    </div>
</div>

<script>
(function () {
    var root = document.getElementById(<?= json_encode($uid) ?>);
    var hide = document.getElementById(<?= json_encode($uid . '-hide') ?>);
    var tip = root.querySelector('[data-matrix-tip]');
    var current = null;

    function applyHide() {
        root.querySelectorAll('[data-matrix-column]').forEach(function (column) {
            column.classList.toggle('d-none', hide.checked && column.getAttribute('data-used') === '0');
        });
    }
    hide.addEventListener('change', applyHide);
    applyHide();

    root.addEventListener('click', function (event) {
        var nav = event.target.closest('[data-matrix-url]');
        if (nav) {
            if (nav.getAttribute('aria-pressed') !== 'true') {
                openModal(nav.getAttribute('data-matrix-url') + (hide.checked ? '/hide:1' : ''), 'fullscreen');
            }
            return;
        }
        var toggle = event.target.closest('[data-matrix-toggle]');
        if (toggle) {
            var subs = toggle.closest('[data-matrix-cell]').querySelector('[data-matrix-subs]');
            var open = subs.classList.contains('d-none');
            subs.classList.toggle('d-none', !open);
            subs.classList.toggle('d-flex', open);
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            toggle.querySelector('i').classList.toggle('fa-rotate-90', open);
        }
    });

    function hideTip() {
        current = null;
        tip.classList.add('d-none');
    }
    root.addEventListener('mouseover', function (event) {
        var cell = event.target.closest('[data-tip-name]');
        if (cell === current) { return; }
        if (!cell) { hideTip(); return; }
        current = cell;
        ['name', 'id', 'state'].forEach(function (field) {
            var value = cell.getAttribute('data-tip-' + field);
            var line = tip.querySelector('[data-tip-field="' + field + '"]');
            line.textContent = value;
            line.classList.toggle('d-none', !value);
        });
        tip.classList.remove('d-none');
        var box = cell.getBoundingClientRect();
        var left = Math.min(box.left + 24, window.innerWidth - tip.offsetWidth - 8);
        var top = box.bottom + 4;
        if (top + tip.offsetHeight > window.innerHeight - 8) {
            top = box.top - tip.offsetHeight - 4;
        }
        tip.style.left = Math.max(8, left) + 'px';
        tip.style.top = top + 'px';
    });
    root.addEventListener('mouseleave', hideTip);
    root.querySelector('[data-matrix-scroll]').addEventListener('scroll', hideTip);
}());
</script>
