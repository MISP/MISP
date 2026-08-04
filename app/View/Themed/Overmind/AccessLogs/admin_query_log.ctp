<div class="p-3 border-bottom d-flex align-items-center gap-2">
    <i class="fas fa-database text-primary"></i>
    <span class="fw-bold"><?= __('SQL queries') ?></span>
    <?php if (!empty($queryLog['log'])): ?>
        <span class="badge text-bg-secondary"><?= count($queryLog['log']) ?></span>
    <?php endif; ?>
    <button type="button" class="btn-close ms-auto" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
</div>
<div class="p-3">
    <div class="table-responsive" style="max-height:65vh;">
        <table class="table table-sm table-striped table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th><?= __('Query') ?></th>
                    <th class="text-end text-nowrap"><?= __('Num. rows') ?></th>
                    <th class="text-end text-nowrap"><?= __('Took (ms)') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (($queryLog['log'] ?? []) as $query): ?>
                    <tr>
                        <td class="font-monospace small"><?= h($query['query']) ?></td>
                        <td class="text-end"><?= h($query['numRows']) ?></td>
                        <td class="text-end"><?= h($query['took']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
