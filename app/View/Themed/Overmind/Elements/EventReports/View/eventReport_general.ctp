<?php

$report = $data['EventReport'] ?? [];
$event = $data['Event'] ?? [];

$eventId = $report['event_id'] ?? ($event['id'] ?? null);
$eventUrl = $baseurl . '/events/view/' . $eventId;
$published = !empty($parentEvent['Event']['published']);
$labelStyle = 'font-size:.7rem;';
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body py-2">
        <div class="d-flex align-items-center justify-content-between gap-2 mb-1">
            <span class="text-body-secondary text-uppercase fw-bold" style="<?= $labelStyle ?>">
                <?= __('Part of event') ?>
            </span>
            <?php if (!empty($report['deleted'])): ?>
                <span class="badge rounded-pill text-bg-danger d-inline-flex align-items-center gap-1">
                    <i class="fas fa-trash-alt"></i><?= __('Deleted report') ?>
                </span>
            <?php endif; ?>
        </div>

        <?php if (empty($eventId)): ?>
            <span class="text-body-secondary fst-italic small"><?= __('Event not visible to you') ?></span>
        <?php else: ?>
            <a href="<?= h($eventUrl) ?>"
               class="d-flex align-items-center gap-3 p-2 rounded-3 border bg-body-tertiary text-decoration-none link-body-emphasis ov-mini-card">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-primary-subtle text-primary"
                      style="width:2.5rem;height:2.5rem;">
                    <i class="misp-icon misp-icon-event misp-simple fs-5"></i>
                </span>
                <div class="min-w-0 flex-grow-1">
                    <div class="fw-semibold lh-sm text-break"><?= h($event['info'] ?? __('Event #%s', $eventId)) ?></div>
                    <div class="d-flex flex-wrap align-items-center column-gap-3 row-gap-1 small text-body-secondary mt-1">
                        <span class="font-monospace">#<?= h($eventId) ?></span>
                        <?php if (!empty($event['date'])): ?>
                            <span><i class="fas fa-calendar-day me-1 opacity-50"></i><?= h($event['date']) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($parentEvent)): ?>
                            <?php if ($published): ?>
                                <span class="badge rounded-pill text-bg-success fw-normal">
                                    <i class="fas fa-check me-1"></i><?= __('Published') ?>
                                </span>
                            <?php else: ?>
                                <span class="badge rounded-pill border bg-body text-body-secondary fw-normal">
                                    <i class="fas fa-pen me-1"></i><?= __('Unpublished') ?>
                                </span>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
                <i class="fas fa-arrow-right flex-shrink-0 text-body-secondary"></i>
            </a>
        <?php endif; ?>
    </div>
</div>
