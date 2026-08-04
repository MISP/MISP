<?php

$fp    = $warninglistHits['false_positive'] ?? [];
$known = $warninglistHits['known'] ?? [];
$total = count($fp) + count($known);

$sections = [
    [
        'items'   => $fp,
        'label'   => __('Potential false positives'),
        'icon'    => 'fas fa-times-circle',
        'bg'      => '#fff1f2',
        'border'  => '#fecdd3',
        'iconCol' => '#dc2626',
    ],
    [
        'items'   => $known,
        'label'   => __('Known identifiers'),
        'icon'    => 'fas fa-info-circle',
        'bg'      => '#fef3c7',
        'border'  => '#fde68a',
        'iconCol' => '#d97706',
    ],
];
?>

<div data-wl-count="<?= $total ?>">

<?php if ($total === 0): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4">
        <i class="fas fa-shield-alt fa-2x mb-2 opacity-50"></i>
        <p class="mb-0 small fw-semibold">
            <?= __('No warning list hits for this event.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="d-flex flex-column gap-0">
    <?php foreach ($sections as $section):
        if (empty($section['items'])) { continue; }
    ?>
        <!-- Section header -->
        <div class="d-flex align-items-center gap-2 px-3 py-2
                    border-bottom"
             style="background:<?= $section['bg'] ?>;
                    border-left:3px solid
                        <?= $section['border'] ?> !important;">
            <i class="<?= $section['icon'] ?> small"
               style="color:<?= $section['iconCol'] ?>;
                      font-size:.85rem;"></i>
            <span class="fw-semibold small"
                  style="color:<?= $section['iconCol'] ?>;">
                <?= $section['label'] ?>
            </span>
            <span class="badge rounded-pill ms-auto"
                  style="background:<?= $section['border'] ?>;
                         color:<?= $section['iconCol'] ?>;
                         font-size:.7rem;">
                <?= count($section['items']) ?>
            </span>
        </div>

        <!-- Items -->
        <?php foreach ($section['items'] as $id => $name): ?>
        <a href="<?= h($baseurl) ?>/warninglists/view/<?= (int)$id ?>"
           class="d-flex align-items-center gap-2 px-3 py-2
                  border-bottom text-decoration-none text-dark
                  wl-item-row"
           style="transition:background .15s;">
            <i class="fas fa-list-ul text-muted"
               style="font-size:.8rem;width:14px;"></i>
            <span class="small flex-fill text-truncate">
                <?= h($name) ?>
            </span>
            <i class="fas fa-chevron-right text-muted opacity-50"
               style="font-size:.7rem;"></i>
        </a>
        <?php endforeach; ?>

    <?php endforeach; ?>
    </div>

<?php endif; ?>

</div>

<style>
.wl-item-row:hover { background: #f8fafc; }
</style>
