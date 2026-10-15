<?php
/*
 * The cluster's elements at a glance, grouped by key. A key can carry hundreds
 * of values (refs, external ids), so each shows its first few and the rest is
 * left to the Elements tab.
 */
$perKey = 6;
$elements = $data['GalaxyElement'] ?? [];
$palette = $this->GalaxyColour->palette($data['Galaxy']['name'] ?? $data['Galaxy']['type'] ?? '');

$groups = [];
foreach ($elements as $element) {
    $key = (string)($element['key'] ?? '');
    $value = (string)($element['value'] ?? '');
    if ($key === '' || $value === '') {
        continue;
    }
    $groups[$key][] = $value;
}
uksort($groups, function ($a, $b) use ($groups) {
    return [count($groups[$a]), $a] <=> [count($groups[$b]), $b];
});
$total = count($elements);
?>

<div class="card mb-3 shadow-sm" data-cluster-elements>
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:<?= h($palette['tintBg']) ?>;color:<?= h($palette['tintIcon']) ?>;">
                    <i class="fas fa-list-ul"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Elements') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s value', '%s values', $total, $total)) ?>
                        &middot;
                        <?= h(__n('%s key', '%s keys', count($groups), count($groups))) ?>
                    </div>
                </div>
            </div>
            <a href="#tab-elements" class="btn btn-sm btn-outline-primary flex-shrink-0" data-ce-tab="elements"
               title="<?= h(__('Open the full element index')) ?>">
                <i class="fas fa-list me-1"></i><?= __('Index') ?>
            </a>
        </div>
    </div>

    <?php if (empty($groups)): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-list-ul me-1 opacity-50"></i><?= __('This cluster has no element.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;">
            <?php foreach ($groups as $key => $values): ?>
                <?php $extra = count($values) - $perKey; ?>
                <li class="list-group-item d-flex flex-column flex-md-row gap-1 gap-md-3 py-2 px-3">
                    <div class="flex-shrink-0 small fw-semibold text-body-secondary text-break" style="width:11rem;" title="<?= h($key) ?>">
                        <?= h(Inflector::humanize($key)) ?>
                        <?php if (count($values) > 1): ?>
                            <span class="fw-normal opacity-75">(<?= h(count($values)) ?>)</span>
                        <?php endif; ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center gap-1 min-w-0">
                        <?php foreach (array_slice($values, 0, $perKey) as $value): ?>
                            <?php $isUrl = preg_match('/^https?:\/\//i', $value); ?>
                            <?php if ($isUrl): ?>
                                <a class="badge rounded-pill border bg-body text-body-secondary fw-normal text-decoration-none text-truncate" style="max-width:20rem;"
                                   href="<?= h($value) ?>" rel="noreferrer noopener" target="_blank" title="<?= h($value) ?>">
                                    <i class="fas fa-arrow-up-right-from-square me-1 opacity-50"></i><?= h(preg_replace('#^https?://(www\.)?#i', '', $value)) ?>
                                </a>
                            <?php else: ?>
                                <span class="badge rounded-pill fw-normal text-truncate" style="max-width:20rem;background:<?= h($palette['badgeBg']) ?>;color:<?= h($palette['badgeText']) ?>;"
                                      title="<?= h($value) ?>"><?= h($value) ?></span>
                            <?php endif; ?>
                        <?php endforeach; ?>
                        <?php if ($extra > 0): ?>
                            <a href="#tab-elements" class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal text-decoration-none" data-ce-tab="elements"
                               title="<?= h(__('See them all in the Elements tab')) ?>">
                                +<?= h(number_format($extra, 0, ',', ' ')) ?>
                            </a>
                        <?php endif; ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>

<script>
(function () {
    document.querySelectorAll('[data-cluster-elements]:not([data-ce-bound])').forEach(function (card) {
        card.setAttribute('data-ce-bound', '');
        card.querySelectorAll('[data-ce-tab]').forEach(function (link) {
            link.addEventListener('click', function (event) {
                var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.ceTab + '"]');
                if (tab && window.bootstrap) {
                    event.preventDefault();
                    bootstrap.Tab.getOrCreateInstance(tab).show();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }
            });
        });
    });
})();
</script>
