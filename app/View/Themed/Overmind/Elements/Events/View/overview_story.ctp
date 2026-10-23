<?php
$event = $data['Event'] ?? [];
$eventId = (int)($event['id'] ?? 0);
$report = $data['EventReport'] ?? null;
$others = $data['OtherEventReports'] ?? [];
$reportCount = (int)($report_count ?? (empty($report) ? 0 : 1 + count($others)));
$canAddReport = $this->Acl->canModifyEvent($data);
$addReportUrl = $baseurl . '/event_reports/add/' . $eventId;
$addObjectUrl = $baseurl . '/objects/add/' . $eventId;
$hasObjects = (int)($object_count ?? 0) > 0;
$structureEmpty = !($has_object_references ?? true);
$graphFoldable = !empty($report);
$graphCompact = $structureEmpty && $graphFoldable;
$graphHint = $hasObjects
    ? [
        'title' => __('No objects are linked yet'),
        'text' => __('References say how the objects relate: which file dropped which, where a domain resolved. Draw them in the Pivot Explorer.'),
        'reader' => __('No object in this event references another.'),
    ]
    : [
        'title' => __('No objects yet'),
        'text' => __('Gather related attributes into objects, then link the objects to show how they relate.'),
        'reader' => __('This event has no objects.'),
    ];
$graphHintAction = function () use ($hasObjects, $addObjectUrl) {
    if ($hasObjects) {
        return '<button type="button" class="btn btn-sm btn-correlation" data-eo-tab="pivot-explorer">'
            . '<i class="fas fa-link me-1"></i>' . __('Link objects') . '</button>';
    }
    return sprintf(
        '<a href="%s" class="btn btn-sm btn-correlation" onclick="event.preventDefault(); openModal(\'%s\');">'
            . '<i class="fas fa-plus me-1"></i>%s</a>',
        h($addObjectUrl), h($addObjectUrl), __('Add an object')
    );
};
$reportEventId = (int)($report['event_id'] ?? $eventId);
$pickable = empty($report) ? [] : array_merge([$report], $others);
$unlisted = max(0, $reportCount - count($pickable));
$extensionEvents = $extensionEvents ?? [];
$reportSub = function (array $row) use ($extensionEvents, $data, $eventId) {
    $originId = (int)($row['event_id'] ?? $eventId);
    return $this->element('Events/View/report_meta', [
        'event_id' => $originId,
        'org' => $extensionEvents[$originId]['Orgc']['name'] ?? ($data['Orgc']['name'] ?? ''),
        'timestamp' => $row['timestamp'] ?? 0,
    ]);
};
?>
<div class="row g-3 mb-3 eo-row">

    <div class="col-12<?= $graphCompact ? '' : ' col-xl-5' ?> d-flex" data-eo-col="report">
        <div class="card shadow-sm eo-card w-100" id="eo-report-card"
             <?php if (!empty($report)): ?>
             data-eo-report-id="<?= (int)$report['id'] ?>"
             data-eo-event-id="<?= $reportEventId ?>"
             data-eo-report-content="<?= h($report['content'] ?? '') ?>"
             <?php endif; ?>>
            <div class="eo-card-head">
                <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-report);--tile-bg:color-mix(in srgb, var(--bs-report) 12%, transparent);">
                    <i class="misp-icon misp-icon-report misp-simple"></i>
                </div>
                <div class="min-w-0 me-auto">
                    <?php if (!empty($report)): ?>
                        <div class="eo-card-title text-truncate" data-eo-report-name title="<?= h($report['name']) ?>"><?= h($report['name']) ?></div>
                        <div class="eo-card-sub text-truncate" data-eo-report-sub><?= $reportSub($report) ?></div>
                    <?php else: ?>
                        <div class="eo-card-title"><?= __('Report') ?></div>
                    <?php endif; ?>
                </div>
                <?php if (count($pickable) > 1): ?>
                    <div class="dropdown flex-shrink-0">
                        <button type="button" class="eo-figure eo-report-toggle" data-bs-toggle="dropdown" aria-expanded="false"
                                title="<?= h(__('Choose the report to read')) ?>">
                            <b><?= $reportCount ?></b> <?= h(__n('report', 'reports', $reportCount)) ?><i class="fas fa-chevron-down eo-report-caret"></i>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end eo-report-pick">
                            <?php foreach ($pickable as $i => $row): ?>
                                <li>
                                    <button type="button" class="dropdown-item" aria-current="<?= $i === 0 ? 'true' : 'false' ?>"
                                            title="<?= h($row['name']) ?>"
                                            data-eo-report-pick="<?= (int)$row['id'] ?>"
                                            data-report-name="<?= h($row['name']) ?>"
                                            data-report-sub="<?= h($reportSub($row)) ?>">
                                        <span class="eo-report-pick-mark"><i class="fas fa-check"></i></span>
                                        <span class="eo-report-pick-name"><?= h($row['name']) ?></span>
                                        <?= $this->element('Events/View/extension_origin', [
                                            'event_id' => (int)($row['event_id'] ?? $eventId),
                                            'compact' => true,
                                            'only_foreign' => true,
                                            'static' => true,
                                            'class' => 'flex-shrink-0',
                                        ]) ?>
                                        <span class="eo-report-pick-date"><?= $this->Time->date($row['timestamp']) ?></span>
                                    </button>
                                </li>
                            <?php endforeach; ?>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <button type="button" class="dropdown-item eo-report-pick-all" data-eo-tab="reports">
                                    <span class="eo-report-pick-mark"><i class="fas fa-table-list"></i></span>
                                    <?= $unlisted > 0
                                        ? h(__('%s more in the Reports tab', $unlisted))
                                        : h(__('Open the Reports tab')) ?>
                                </button>
                            </li>
                        </ul>
                    </div>
                <?php else: ?>
                    <div class="eo-figure"><b><?= $reportCount ?></b> <?= h(__n('report', 'reports', $reportCount)) ?></div>
                <?php endif; ?>
            </div>

            <?php if (!empty($report)): ?>
                <div class="eo-report-body">
                    <div class="eo-report-clamp">
                        <div class="markdown-preview-body" data-eo-report-preview>
                            <div class="text-center text-muted py-4"><div class="misp-loader misp-loader-sm" role="status"></div></div>
                        </div>
                    </div>
                </div>
                <div class="eo-card-foot">
                    <button type="button" class="btn btn-sm btn-report"
                            data-report-read="<?= (int)$report['id'] ?>"
                            data-report-name="<?= h($report['name']) ?>"
                            data-report-sub="<?= h($reportSub($report)) ?>">
                        <i class="fas fa-book-open me-1"></i><?= __('Read in full') ?>
                    </button>
                </div>
            <?php else: ?>
                <?php if ($canAddReport): ?>
                    <div class="eo-prompt" style="--eo-prompt:var(--bs-report);">
                        <div class="eo-prompt-text">
                            <div class="eo-prompt-title"><?= __('No report yet') ?></div>
                            <p><?= __('A report tells the story behind the indicators: what happened, how it was found and what to do about it.') ?></p>
                        </div>
                        <a href="<?= h($addReportUrl) ?>" class="btn btn-sm btn-report"
                           onclick="event.preventDefault(); openModal('<?= h($addReportUrl) ?>');">
                            <i class="fas fa-pen me-1"></i><?= __('Write a report') ?>
                        </a>
                    </div>
                <?php else: ?>
                    <p class="eo-empty"><?= __('This event has no report.') ?></p>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <div class="col-12<?= $graphCompact ? '' : ' col-xl-7' ?> d-flex" data-eo-col="graph">
        <?php if ($graphFoldable && $canAddReport): ?>
            <div class="eo-prompt eo-graph-strip w-100<?= $graphCompact ? '' : ' d-none' ?>" style="--eo-prompt:var(--bs-correlation);" data-eo-graph-strip>
                <div class="misp-icon-tile eo-tile eo-tile-sm" style="--tile:var(--bs-correlation);--tile-bg:color-mix(in srgb, var(--bs-correlation) 12%, transparent);">
                    <i class="fas fa-circle-nodes"></i>
                </div>
                <div class="eo-prompt-text">
                    <div class="eo-prompt-title"><?= h($graphHint['title']) ?></div>
                    <p><?= h($graphHint['text']) ?></p>
                </div>
                <?= $graphHintAction() ?>
            </div>
        <?php elseif ($graphFoldable): ?>
            <div class="card shadow-sm eo-card eo-graph-strip w-100<?= $graphCompact ? '' : ' d-none' ?>" data-eo-graph-strip>
                <div class="misp-icon-tile eo-tile eo-tile-sm" style="--tile:var(--bs-correlation);--tile-bg:color-mix(in srgb, var(--bs-correlation) 12%, transparent);">
                    <i class="fas fa-circle-nodes"></i>
                </div>
                <span class="eo-card-title"><?= __('Event graph') ?></span>
                <span class="eo-muted"><?= h($graphHint['reader']) ?></span>
            </div>
        <?php endif; ?>
        <div class="card shadow-sm eo-card w-100<?= $graphCompact ? ' d-none' : '' ?>" id="eo-graph-card"
             data-eo-structure-empty="<?= $structureEmpty ? '1' : '0' ?>"
             data-eo-graph-foldable="<?= $graphFoldable ? '1' : '0' ?>"
             data-eo-graph-url="<?= h($baseurl . '/events/viewEventOverviewGraph/' . $eventId . ($extensionSuffix ?? '') . '.json') ?>"
             data-eo-event-id="<?= $eventId ?>"
             data-eo-event-uuid="<?= h($event['uuid'] ?? '') ?>"
             data-eo-text-summary="<?= h(__('%s linked objects and attributes — too many to draw here.')) ?>"
             data-eo-text-failed="<?= h(__('The graph could not be drawn.')) ?>"
             data-eo-text-counts="<?= h(__('%1$s objects, %2$s references')) ?>"
             data-eo-text-saved="<?= h(__('Workspace: %s')) ?>"
             data-eo-text-saved-count="<?= h(__('%s workspaces')) ?>"
             data-eo-text-node-count="<?= h(__('%s nodes')) ?>">
            <div class="eo-card-head">
                <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-correlation);--tile-bg:color-mix(in srgb, var(--bs-correlation) 12%, transparent);">
                    <i class="fas fa-circle-nodes"></i>
                </div>
                <div class="min-w-0 me-auto">
                    <div class="eo-card-title"><?= __('Event graph') ?></div>
                    <div class="eo-card-sub text-truncate" data-eo-graph-sub>&nbsp;</div>
                </div>
                <div class="eo-switch" role="group" aria-label="<?= h(__('Graph source')) ?>">
                    <div class="dropdown d-inline-flex">
                        <button type="button" data-eo-graph-mode="saved" disabled
                                title="<?= h(__('No workspace on this event')) ?>"
                                data-eo-title-ready="<?= h(__('Show a workspace')) ?>"
                                data-eo-title-pick="<?= h(__('Choose a workspace')) ?>">
                            <i class="fas fa-bookmark"></i><?= __('Workspace') ?>
                            <i class="fas fa-caret-down d-none" data-eo-graph-caret></i>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end eo-graph-pick" data-eo-graph-pick></ul>
                    </div>
                    <button type="button" class="active" data-eo-graph-mode="structure"
                            title="<?= h(__('Show how the objects reference each other')) ?>">
                        <i class="fas fa-sitemap"></i><?= __('Structure') ?>
                    </button>
                </div>
            </div>
            <div class="eo-graph-stage">
                <div class="eo-graph-loader" data-eo-graph-loader>
                    <div class="misp-loader misp-loader-sm" role="status"></div>
                </div>
                <div class="eo-graph-canvas" data-eo-graph-canvas="structure"></div>
                <div class="eo-graph-canvas d-none" data-eo-graph-canvas="saved"></div>
                <div class="eo-graph-message d-none" data-eo-graph-message></div>
                <?php if ($canAddReport): ?>
                    <div class="eo-prompt d-none" style="--eo-prompt:var(--bs-correlation);" data-eo-graph-empty>
                        <div class="eo-prompt-text">
                            <div class="eo-prompt-title"><?= h($graphHint['title']) ?></div>
                            <p><?= h($graphHint['text']) ?></p>
                        </div>
                        <?= $graphHintAction() ?>
                    </div>
                <?php else: ?>
                    <p class="eo-empty d-none" data-eo-graph-empty><?= h($graphHint['reader']) ?></p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
