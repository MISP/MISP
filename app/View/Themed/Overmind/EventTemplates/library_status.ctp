<?php /* Phase 2.4 placeholder. Phase 3.2 replaces with a BS5 status view. */ ?>
<div class="container-fluid mt-3">
    <div class="card mb-3 shadow-sm">
        <div class="card-body">
            <h2 class="fw-semibold mb-3">
                <?= __('Library status — Event Templates') ?>
            </h2>
            <p class="text-muted">
                <?= __('Dry-run snapshot of the bundled misp-event-templates submodule and the local DB state. No writes.') ?>
            </p>
            <pre class="bg-light border rounded p-3"
                 style="max-height:600px;overflow:auto;font-size:0.85rem;"><?=
                h(JsonTool::encode($summary, true))
            ?></pre>
        </div>
    </div>
</div>
