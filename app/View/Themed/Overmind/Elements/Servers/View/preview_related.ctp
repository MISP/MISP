<?php
$related = $data['RelatedEvent'] ?? [];

$ctx = $previewContext ?? [];
$eventUrl = $ctx['eventUrl']
    ?? ($baseurl . '/servers/previewEvent/' . (int)($server['Server']['id'] ?? 0) . '/%id%');
$eventKey = $ctx['eventKey'] ?? 'id';

$uid = 'preview-related-' . h($data['Event']['id'] ?? $data['Event']['uuid'] ?? '0');

// Normalise each related row to a flat Event array (remote JSON may nest a list).
$rows = [];
foreach ($related as $relatedEvent) {
    $ev = $relatedEvent['Event'] ?? [];
    if (isset($ev[0])) {
        $ev = $ev[0];
    }
    if (!empty($ev[$eventKey])) {
        $rows[] = $ev;
    }
}
$total = count($rows);
$limit = 5;

$distMap = $this->DistributionLevel->all();
?>

<div class="card shadow-sm mb-3" id="preview-related-card">

    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#E67F0D40;">
                <i class="fas fa-link" style="color:#E67F0D;font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Related Events') ?></div>
                <div class="small text-muted mt-1">
                    <?php
                    if ($total === 0) {
                        echo __('No correlations');
                    } else {
                        echo $total . ' ' . ($total === 1 ? __('related event') : __('related events'));
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>

    <div id="<?= $uid ?>-body">
        <?php if ($total === 0): ?>
            <div class="d-flex flex-column align-items-center justify-content-center text-muted py-4">
                <i class="fas fa-link fa-2x mb-2 opacity-50"></i>
                <p class="mb-0 small fw-semibold"><?= __('No correlated events found.') ?></p>
            </div>
        <?php else: ?>
            <div class="d-flex flex-column">
                <?php foreach ($rows as $i => $ev):
                    $evUrl   = str_replace('%id%', rawurlencode((string)$ev[$eventKey]), $eventUrl);
                    $info    = h($ev['info'] ?? '');
                    $date    = h($ev['date'] ?? '');
                    $orgName = h($ev['Orgc']['name'] ?? $ev['Org']['name'] ?? '');
                    $distId  = (int)($ev['distribution'] ?? 0);
                    $dist    = $distMap[$distId] ?? $distMap[0];
                    $hidden  = $i >= $limit;
                    ?>
                    <a href="<?= h($evUrl) ?>"
                       class="d-flex align-items-start gap-3 px-3 py-2 text-decoration-none text-dark border-bottom related-event-row <?= $hidden ? 'd-none' : '' ?>"
                       style="transition:background .15s;">

                        <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0 mt-1"
                             style="width:34px;height:34px;background:<?= $dist['bg'] ?>;border:1px solid <?= $dist['color'] ?>33;"
                             title="<?= h($dist['label']) ?>">
                            <i class="<?= h($dist['icon']) ?>" style="color:<?= $dist['color'] ?>;font-size:.85rem;"></i>
                        </div>

                        <div class="flex-fill overflow-hidden">
                            <div class="fw-semibold text-truncate small lh-sm"><?= $info ?></div>
                            <div class="d-flex align-items-center gap-2 mt-1 flex-wrap">
                                <span class="text-muted" style="font-size:.75rem;"><?= $orgName ?></span>
                                <?php if ($date !== ''): ?>
                                    <span class="text-muted" style="font-size:.75rem;">·</span>
                                    <time class="text-muted" style="font-size:.75rem;"><?= $date ?></time>
                                <?php endif; ?>
                            </div>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php if ($total > $limit): ?>
<script>
(function () {
    var body = document.getElementById(<?= json_encode($uid . '-body') ?>);
    if (!body) { return; }
    var rows = body.querySelectorAll('.related-event-row');
    var limit = <?= (int)$limit ?>;

    var more = document.createElement('button');
    more.type = 'button';
    more.className = 'btn btn-sm btn-link w-100 text-muted py-2';
    more.innerHTML = '<i class="fas fa-chevron-down me-1"></i>'
        + <?= json_encode(__('Show all')) ?> + ' (' + rows.length + ')';
    more.addEventListener('click', function () {
        rows.forEach(function (r) { r.classList.remove('d-none'); });
        more.remove();
        body.parentNode.appendChild(less);
    });

    var less = document.createElement('button');
    less.type = 'button';
    less.className = 'btn btn-sm btn-link w-100 text-muted py-2';
    less.innerHTML = '<i class="fas fa-chevron-up me-1"></i>' + <?= json_encode(__('Show less')) ?>;
    less.addEventListener('click', function () {
        for (var k = limit; k < rows.length; k++) { rows[k].classList.add('d-none'); }
        less.remove();
        body.parentNode.appendChild(more);
    });

    body.parentNode.appendChild(more);
}());
</script>
<?php endif; ?>
