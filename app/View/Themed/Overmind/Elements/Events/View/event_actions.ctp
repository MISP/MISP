<?php

$eventId = h($data['Event']['id']);
$base = $this->request->base;

?>

<div class="card shadow-sm border-0">
    <div class="card-body">
        <h5 class="fw-bold d-flex align-items-center gap-2 mb-3">
            <i class="fas fa-forward text-primary"></i>
            <?= __('Quick action') ?>
        </h5>

        <div class="d-flex flex-column gap-2">
            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/events/edit/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-pen text-secondary"></i>
                    <?= __('Edit Event') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/attributes/add/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-inbox text-secondary"></i>
                    <?= __('Add Attribute') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/objects/add/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-cube text-secondary"></i>
                    <?= __('Add Object') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/event_reports/add/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-file-alt text-secondary"></i>
                    <?= __('Add Event Report') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/attributes/add_attachment/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-copy text-secondary"></i>
                    <?= __('Add Attachment') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="#">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-tag text-secondary"></i>
                    <?= __('Add Tag') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="#">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-bullseye text-secondary"></i>
                    <?= __('Add Cluster') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="#"
               onclick="event.preventDefault();getPopup(<?= $eventId ?>, 'events', 'importChoice')">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-sign-in-alt text-secondary"></i>
                    <?= __('Populate from') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="quick-action btn btn-light d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
               href="<?= $base ?>/events/export/<?= $eventId ?>">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-sign-out-alt text-secondary"></i>
                    <?= __('Export as') ?>
                </span>
                <i class="fas fa-chevron-right text-muted"></i>
            </a>

            <a class="btn btn-danger-subtle text-danger d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
                href="<?= $base ?>/events/delete/<?= $eventId ?>"
                onclick="event.preventDefault(); openModal('<?= $base ?>/events/delete/<?= $eventId ?>');">
                <span class="d-flex align-items-center gap-3">
                    <i class="fas fa-trash "></i>
                    <?= __('Delete Event') ?>
                </span>
                <i class="fas fa-chevron-right"></i>
            </a>
        </div>
    </div>
</div>
