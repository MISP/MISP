<?php
/*
 * One page of a warninglist's values, swapped into the Values card by its
 * script. Pager buttons carry data-wl-page; nothing here binds any event.
 */
$pages = max(1, (int)ceil($total / $limit));
$from = $total === 0 ? 0 : ($page - 1) * $limit + 1;
$to = min($total, $page * $limit);
?>
<?php if (empty($entries)): ?>
    <div class="text-center text-body-secondary small py-4">
        <i class="fas fa-filter-circle-xmark me-1 opacity-50"></i>
        <?= $query !== '' ? __('No value matches this filter.') : __('This warninglist holds no value.') ?>
    </div>
<?php else: ?>
    <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;">
        <?php foreach ($entries as $entry): ?>
            <?php $e = $entry['WarninglistEntry']; ?>
            <li class="list-group-item d-flex align-items-center gap-3 py-2 px-3">
                <span class="font-monospace small text-break flex-grow-1"><?= h($e['value']) ?></span>
                <?php if (trim((string)$e['comment']) !== ''): ?>
                    <span class="small text-body-secondary fst-italic text-truncate" style="max-width:45%;" title="<?= h($e['comment']) ?>">
                        <i class="fas fa-comment fa-xs opacity-50 me-1"></i><?= h($e['comment']) ?>
                    </span>
                <?php endif; ?>
            </li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
<div class="card-footer bg-body d-flex align-items-center justify-content-between gap-2 py-2 px-3 small text-body-secondary">
    <span>
        <?= h(__('%s–%s of %s', number_format($from, 0, ',', ' '), number_format($to, 0, ',', ' '), number_format($total, 0, ',', ' '))) ?>
    </span>
    <?php if ($pages > 1): ?>
        <span class="d-flex align-items-center gap-1">
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0 px-1"
                    data-wl-page="<?= $page - 1 ?>" <?= $page <= 1 ? 'disabled' : '' ?>
                    title="<?= h(__('Previous page')) ?>" aria-label="<?= h(__('Previous page')) ?>">
                <i class="fas fa-chevron-left"></i>
            </button>
            <span><?= h(__('Page %s of %s', number_format($page, 0, ',', ' '), number_format($pages, 0, ',', ' '))) ?></span>
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0 px-1"
                    data-wl-page="<?= $page + 1 ?>" <?= $page >= $pages ? 'disabled' : '' ?>
                    title="<?= h(__('Next page')) ?>" aria-label="<?= h(__('Next page')) ?>">
                <i class="fas fa-chevron-right"></i>
            </button>
        </span>
    <?php endif; ?>
</div>
