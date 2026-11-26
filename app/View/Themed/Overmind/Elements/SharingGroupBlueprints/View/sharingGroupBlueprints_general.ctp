<?php
$blueprint = $data['SharingGroupBlueprint'] ?? [];
$owner = $data['Organisation'] ?? [];
$sharingGroup = $data['SharingGroup'] ?? [];
$rules = json_decode((string)($blueprint['rules'] ?? ''), true);
$matching = $matchingOrgCount ?? null;

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

// Same wording as the rule editor in SharingGroupBlueprints/add.ctp.
$filterHints = [
    'org_id' => __('Organisation id'),
    'org_uuid' => __('Organisation UUID'),
    'org_name' => __('Organisation name'),
    'org_nationality' => __('Country the organisation belongs to'),
    'org_sector' => __('Sector the organisation works in'),
    'org_type' => __('Organisation type'),
    'sharing_group_id' => __('Members of a sharing group, by id'),
    'sharing_group_uuid' => __('Members of a sharing group, by UUID'),
];
$knownFilters = [];
foreach (($validFilters ?? []) as $group) {
    $knownFilters = array_merge($knownFilters, array_keys($group));
}
$operandList = $operands ?? ['OR', 'AND', 'NOT'];
$operandGlosses = [
    'OR' => __('any of these'),
    'AND' => __('all of these'),
    'NOT' => __('none of these'),
];

// Walks the rules the way SharingGroupBlueprint::__recursiveEvaluate() does.
$renderTree = function (array $node, $depth) use (&$renderTree, $operandList, $operandGlosses, $knownFilters, $filterHints) {
    $out = '<div class="d-flex flex-column gap-1' . ($depth > 0 ? ' ms-3 ps-2 border-start' : '') . '">';
    foreach ($node as $key => $value) {
        if (in_array($key, $operandList, true)) {
            $out .= '<div class="d-flex align-items-center gap-2">'
                . '<span class="badge rounded-pill font-monospace ' . ($key === 'NOT' ? 'text-bg-danger' : 'text-bg-primary') . '">' . h($key) . '</span>'
                . '<span class="small text-body-secondary">' . h($operandGlosses[$key] ?? '') . '</span></div>';
            if (is_array($value)) {
                $out .= $renderTree($value, $depth + 1);
            }
            continue;
        }
        $known = in_array($key, $knownFilters, true);
        $values = is_array($value) ? $value : [$value];
        $chips = '';
        foreach ($values as $item) {
            $chips .= '<span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal font-monospace">'
                . h(is_scalar($item) ? (string)$item : json_encode($item)) . '</span>';
        }
        $out .= '<div class="d-flex flex-wrap align-items-center gap-1 small">'
            . '<span class="' . ($known ? 'fw-semibold' : 'fw-semibold text-warning-emphasis') . '" title="' . h($key) . '">'
            . ($known ? h($filterHints[$key] ?? $key) : '<i class="fas fa-triangle-exclamation me-1"></i>' . h(__('Unknown filter "%s"', $key)))
            . '</span><span class="text-body-secondary">' . h(count($values) > 1 ? __('is one of') : __('is')) . '</span>'
            . $chips . '</div>';
    }
    return $out . '</div>';
};
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="misp-icon misp-icon-sharing-group misp-simple text-primary me-1"></i><?= __('Generated sharing group') ?>
            </div>
            <?php if (!empty($sharingGroup['id'])): ?>
                <div class="d-flex align-items-center gap-2">
                    <a href="<?= h($baseurl . '/sharing_groups/view/' . $sharingGroup['id']) ?>"
                       class="d-flex align-items-center gap-3 p-2 rounded-3 border bg-body-tertiary text-decoration-none link-body-emphasis ov-mini-card flex-grow-1 min-w-0">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-primary-subtle text-primary"
                              style="width:2.25rem;height:2.25rem;"><i class="misp-icon misp-icon-sharing-group misp-simple"></i></span>
                        <div class="min-w-0 flex-grow-1">
                            <div class="fw-semibold lh-sm text-truncate"><?= h($sharingGroup['name'] ?? '') ?></div>
                            <div class="small text-body-secondary">#<?= h($sharingGroup['id']) ?> &middot; <?= __('Kept in step with the rules on each regeneration') ?></div>
                        </div>
                        <i class="fas fa-arrow-right flex-shrink-0 text-body-secondary"></i>
                    </a>
                    <?php if (!empty($isSiteAdmin)): ?>
                        <button type="button" class="btn btn-sm btn-outline-danger flex-shrink-0"
                                onclick="openModal('<?= h($baseurl . '/sharing_group_blueprints/detach/' . (int)$blueprint['id']) ?>', 'md');"
                                title="<?= h(__('Detach Sharing Group')) ?>" aria-label="<?= h(__('Detach Sharing Group')) ?>">
                            <i class="fas fa-link-slash"></i>
                        </button>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="d-flex align-items-center gap-2 p-2 rounded-3 border bg-body-tertiary" style="border-style:dashed !important;">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-body-secondary text-body-secondary"
                          style="width:2.25rem;height:2.25rem;"><i class="fas fa-recycle"></i></span>
                    <div class="small">
                        <div class="fw-semibold"><?= __('Not generated yet') ?></div>
                        <div class="text-body-secondary"><?= __('Generating the blueprint creates the sharing group from its rules.') ?></div>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>"><?= __('Rules') ?></span>
                <?php if ($matching !== null): ?>
                    <a href="#tab-organisations" class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-normal text-decoration-none"
                       data-bp-tab="organisations" title="<?= h(__('See the organisations')) ?>">
                        <i class="fas fa-building-user me-1"></i><?= h(__n('Selects %s organisation', 'Selects %s organisations', $matching, $matching)) ?>
                    </a>
                <?php else: ?>
                    <span class="badge rounded-pill bg-danger-subtle text-danger-emphasis border border-danger-subtle fw-normal">
                        <i class="fas fa-triangle-exclamation me-1"></i><?= __('These rules cannot be evaluated') ?>
                    </span>
                <?php endif; ?>
            </div>
            <?php if (!is_array($rules) || empty($rules)): ?>
                <span class="text-body-secondary fst-italic small"><?= __('No rule — the blueprint selects nothing.') ?></span>
            <?php else: ?>
                <div class="p-2 rounded-3 border bg-body-tertiary">
                    <div class="small text-body-secondary mb-1"><?= __('An organisation is selected when it matches any of:') ?></div>
                    <?= $renderTree($rules, 0) ?>
                </div>
                <details class="mt-2 small">
                    <summary class="text-body-secondary"><?= __('Raw rules') ?></summary>
                    <pre class="bg-body-tertiary border rounded p-2 mt-1 mb-0 small"><code><?= h(json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></code></pre>
                </details>
            <?php endif; ?>
        </div>

        <?php if (!empty($owner['name'])): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Owner') ?></div>
                <div class="d-flex align-items-center gap-2 min-w-0">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden" style="<?= $tileStyle ?>">
                        <?= $this->OrgImg->getOrgLogoV2($owner, 20, false) ?: '<i class="fas fa-building text-body-secondary"></i>' ?>
                    </span>
                    <div class="min-w-0">
                        <a class="d-block fw-semibold lh-sm text-truncate text-decoration-none" href="<?= h($baseurl . '/organisations/view/' . $owner['id']) ?>"><?= h($owner['name']) ?></a>
                        <div class="small text-body-secondary"><?= __('Sharing group rules only reach the groups it can see') ?></div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-bp-tab]:not([data-bp-bound])').forEach(function (link) {
        link.setAttribute('data-bp-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.bpTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
