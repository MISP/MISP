<?php
$total = count($matrices);
$summary = function (array $matrix) {
    return __n('%s technique', '%s techniques', $matrix['techniques'], $matrix['techniques'])
        . ' · ' . __n('%s tactic', '%s tactics', $matrix['covered'], $matrix['covered']);
};
?>
<div data-matrix-count="<?= $total ?>"
     data-matrix-title="<?= h(__n('%s matrix galaxy', '%s matrix galaxies', $total, $total)) ?>">
<?php if ($total > 0): ?>

    <div class="px-3 pt-3">
        <div class="d-flex flex-column gap-1 p-1 border rounded-2 bg-body-tertiary">
        <?php foreach ($matrices as $i => $matrix): ?>
            <button type="button"
                    class="btn btn-sm border-0 d-flex align-items-center gap-2 w-100 text-start
                           <?= $i === 0 ? 'bg-body shadow-sm fw-semibold' : 'text-body-secondary' ?>"
                    data-matrix-switch="<?= $matrix['id'] ?>"
                    aria-pressed="<?= $i === 0 ? 'true' : 'false' ?>"
                    title="<?= h($matrix['description']) ?>">
                <i class="<?= h($this->FontAwesome->getClass($matrix['icon'] ?: 'table-cells')) ?> text-galaxy"></i>
                <span class="text-truncate"><?= h($matrix['name']) ?></span>
                <span class="ms-auto small text-body-secondary fw-normal"><?= $matrix['techniques'] ?></span>
            </button>
        <?php endforeach; ?>
        </div>
    </div>

    <?php foreach ($matrices as $i => $matrix):
        $covered = array_values(array_filter($matrix['tactics'], function ($tactic) {
            return !empty($tactic['clusters']);
        }));
        $placements = array_sum(array_map(function ($tactic) {
            return count($tactic['clusters']);
        }, $covered));
    ?>
    <div class="<?= $i === 0 ? '' : 'd-none' ?>"
         data-matrix-panel="<?= $matrix['id'] ?>"
         data-matrix-summary="<?= h($summary($matrix)) ?>">

        <div class="progress-stacked mx-3 my-3" style="height:6px;">
        <?php foreach ($covered as $j => $tactic):
            $count = count($tactic['clusters']);
        ?>
            <div class="progress" role="progressbar"
                 style="width:<?= round(100 * $count / max(1, $placements), 2) ?>%;"
                 aria-label="<?= h($tactic['label']) ?>"
                 aria-valuenow="<?= $count ?>" aria-valuemin="0" aria-valuemax="<?= $placements ?>"
                 title="<?= h($tactic['label'] . ' · ' . $count) ?>">
                <div class="progress-bar bg-galaxy <?= $j % 2 ? 'bg-opacity-50' : '' ?>"></div>
            </div>
        <?php endforeach; ?>
        </div>

        <div class="border-top pb-2">
        <?php foreach ($covered as $tactic): ?>
            <div class="px-3 pt-2">
                <div class="d-flex align-items-center small fw-semibold mb-1">
                    <span><?= h($tactic['label']) ?></span>
                    <span class="ms-auto text-body-secondary fw-normal"><?= count($tactic['clusters']) ?></span>
                </div>
                <div class="d-flex flex-column gap-1">
                <?php foreach ($tactic['clusters'] as $cluster): ?>
                    <a href="<?= h($baseurl . '/galaxy_clusters/view/' . $cluster['id']) ?>"
                       class="d-flex align-items-center gap-2 ps-2 pe-2 py-1 small rounded-1
                              border-start border-3 border-galaxy bg-galaxy bg-opacity-10
                              text-body text-decoration-none"
                       title="<?= h($cluster['description']) ?>">
                        <?php if ($cluster['local']): ?>
                            <i class="fas fa-user text-body-secondary" title="<?= __('Local cluster') ?>"></i>
                        <?php endif; ?>
                        <span class="text-truncate"><?= h($cluster['name']) ?></span>
                        <?php if ($cluster['external_id'] !== ''): ?>
                            <span class="ms-auto font-monospace fw-semibold text-body-secondary flex-shrink-0">
                                <?= h($cluster['external_id']) ?>
                            </span>
                        <?php endif; ?>
                    </a>
                <?php endforeach; ?>
                </div>
            </div>
        <?php endforeach; ?>
        </div>

    </div>
    <?php endforeach; ?>

<?php endif; ?>
</div>
