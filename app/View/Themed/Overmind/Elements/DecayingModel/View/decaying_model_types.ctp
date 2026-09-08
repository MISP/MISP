<?php
$dm = $data['DecayingModel'];
$types = is_array($dm['attribute_types'] ?? null) ? $dm['attribute_types'] : [];
sort($types);

$categoryDefinitions = $categoryDefinitions ?? [];
$typeDefinitions = $typeDefinitions ?? [];
$catHue = [];
foreach (array_keys($categoryDefinitions) as $i => $cat) {
    $catHue[$cat] = (int)round(fmod($i * 137.508, 360));
}
$hueOfType = function ($type) use ($typeDefinitions, $catHue) {
    $cat = $typeDefinitions[$type]['default_category'] ?? null;
    return ($cat !== null && isset($catHue[$cat])) ? $catHue[$cat] : 210;
};
?>

<div class="card shadow-sm mb-3 dm-types">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#97CC0440;">
                <i class="misp-icon misp-icon-attribute misp-simple text-attribute" style="font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Assigned attribute types') ?></div>
                <div class="small text-muted mt-1"><?= count($types) ?> <?= __('type(s)') ?></div>
            </div>
        </div>
    </div>

    <!-- BODY -->
    <div class="p-3">
        <?php if (empty($types)): ?>
            <div class="d-flex flex-column align-items-center text-secondary py-4">
                <i class="misp-icon misp-icon-attribute misp-hexagone fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No attribute type is assigned to this model yet.') ?>
            </div>
        <?php else: ?>
            <div class="d-flex flex-wrap gap-2">
                <?php foreach ($types as $type): ?>
                    <?php
                        $hue = $hueOfType($type);
                        $cat = $typeDefinitions[$type]['default_category'] ?? null;
                        $title = $cat !== null
                            ? sprintf(__('Default category: %s'), $cat)
                            : __('MISP object attribute');
                    ?>
                    <span class="dm-chip font-monospace" style="--h: <?= $hue ?>;"
                          title="<?= h($title) ?>">
                        <span class="dm-chip-dot"></span><?= h($type) ?>
                    </span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

</div>
