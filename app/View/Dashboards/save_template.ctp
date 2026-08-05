<?php
/**
 * Save / edit dashboard template form (PRD §5.4, Phase 4 task 5).
 *
 * Renders inside Layouts/dashboard.ctp (DD-08) — same chrome as the
 * template gallery view. Replaces the v1 modal flow
 * (openGenericModal('/dashboards/saveTemplate/...')) with an in-page
 * surface; the controller's POST handling and REST response shape
 * stay unchanged so the action's wire shape is preserved (Phase 4
 * task 7 wire ratification rides along).
 *
 * Data contract (set by DashboardsController::saveTemplate):
 *   - options: { org_id => [id => label, ...],
 *                role_id => [id => label, ...],
 *                role_perms => [flag => label, ...] }
 *     Each pre-fixed with `0 => "Unrestricted"` so the SQL value 0
 *     round-trips through the dropdown without re-indexing.
 *   - isSiteAdmin (bool): site-admins see the restrict_to_* fields
 *     and the "Default" checkbox; non-site-admins do not (the model
 *     enforces the same gate on save via editableFields).
 *   - isUpdate (bool), updateRef (id|uuid|false): drives the form's
 *     action attribute and the page title.
 *   - request->data['Dashboard']: pre-fill payload when editing.
 */
$baseurl = Configure::read('MISP.baseurl') ?: rtrim(Router::url('/', true), '/');
?>
<header class="misp-dashboard-header misp-template-form-header">
    <div class="misp-template-gallery-title-block">
        <h1 class="misp-dashboard-title">
            <?= $isUpdate
                ? __('Edit dashboard template')
                : __('Save dashboard template') ?>
        </h1>
        <p class="misp-template-gallery-subtitle">
            <?= $isUpdate
                ? __('Update this template\'s metadata. The widget layout itself is unchanged — use "Save current dashboard as template" to capture a new layout.')
                : __('Save your current dashboard layout as a template that you or other users can reuse.') ?>
        </p>
    </div>
    <div class="misp-dashboard-modecontrols">
        <a href="<?= h($baseurl) ?>/dashboards/listTemplates"
           class="misp-dashboard-btn"
           data-misp-template-form-action="cancel"
           title="<?= __('Return to the template gallery without saving') ?>">
            <?= __('← Back to gallery') ?>
        </a>
    </div>
</header>

<main class="misp-dashboard-page-main misp-template-form-page">
    <section class="misp-template-form-card" aria-labelledby="misp-template-form-title">
        <h2 id="misp-template-form-title" class="visually-hidden">
            <?= $isUpdate
                ? __('Edit dashboard template')
                : __('Save dashboard template') ?>
        </h2>
        <?= $this->element('dashboard/save_template_form') ?>
    </section>
</main>
