<?php
/*
 * Phase 2.4 placeholder. Phase 3.2 replaces with a BS5-flavoured
 * summary card view (installed / updated / skipped sections).
 */
?>
<div class="container-fluid mt-3">
    <div class="card mb-3 shadow-sm">
        <div class="card-body">
            <h2 class="fw-semibold mb-3">
                <?= __('Library update — Event Templates') ?>
            </h2>
            <p class="text-muted">
                <?= __('Walked the bundled misp-event-templates submodule and reconciled with this instance.') ?>
            </p>
            <pre class="bg-light border rounded p-3"
                 style="max-height:600px;overflow:auto;font-size:0.85rem;"><?=
                h(JsonTool::encode($summary, true))
            ?></pre>
            <a href="<?= h($baseurl . '/event_templates/index') ?>" class="btn btn-primary">
                <i class="fas fa-arrow-left me-1"></i><?= __('Back to event templates') ?>
            </a>
        </div>
    </div>
</div>
