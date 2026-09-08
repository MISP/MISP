<?php
/*
 * Rendered by WorkflowsController::beforeFilter() when the workflow system
 * cannot run (background workers off, Plugin.Workflow_enable off, redis
 * unreachable). It replaces whichever workflow action was requested, so it is
 * still served under that action's route — /workflows/index being the one
 * allowlisted for Bootstrap 5.
 */
$this->set('headerTitle', __('Workflows'));
$this->set('headerDescription', __('The workflow system is not available on this instance.'));
$this->set('headerCountText', '');
?>

<div class="container-fluid pb-4">
    <div class="card border-0 shadow-sm">
        <div class="card-body p-4">

            <div class="d-flex align-items-start gap-3">
                <i class="fas fa-plug-circle-xmark text-danger" style="font-size:1.75rem;"></i>
                <div class="flex-grow-1">
                    <h2 class="h6 fw-bold mb-1"><?= __('Could not access the workflow system') ?></h2>
                    <p class="text-muted mb-0" style="font-size:.85rem;">
                        <?= __('Some components are essential for the workflow system to run.') ?>
                    </p>
                </div>
            </div>

            <hr class="my-3">

            <div class="fw-semibold mb-2" style="font-size:.82rem;">
                <?= __n('Error:', 'Errors:', count($requirementErrors)) ?>
            </div>
            <ul class="list-group list-group-flush mb-0">
                <?php foreach ($requirementErrors as $error): ?>
                    <li class="list-group-item px-0 d-flex gap-2 align-items-start" style="font-size:.85rem;">
                        <i class="fas fa-circle-exclamation fa-fw text-danger mt-1"></i>
                        <span><?= h($error) ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>

            <a href="<?= $baseurl ?>/servers/serverSettings/Plugin"
               class="btn btn-outline-primary btn-sm fw-semibold mt-3">
                <i class="fas fa-gears me-1"></i><?= __('Open plugin settings') ?>
            </a>

        </div>
    </div>
</div>
