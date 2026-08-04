<div id="eventReportQuickIndex" class="beta-reports-list beta-reports-compact">
    <div class="beta-reports-toolbar">
        <div class="btn-group btn-group-sm">
            <?php if ($canModify): ?>
                <a href="<?php echo $baseurl; ?>/eventReports/add/<?php echo h($event_id); ?>" class="btn btn-primary modal-open" title="<?php echo __('Add Event Report'); ?>">
                    <i class="fa fa-plus"></i> <?php echo __('Add'); ?>
                </a>
                <?php if ($importModuleEnabled && $unsafeUrlSettingEnabled): ?>
                    <a href="<?php echo $baseurl; ?>/eventReports/importReportFromUrl/<?php echo h($event_id); ?>" class="btn btn-default modal-open" title="<?php echo __('Content for this URL will be downloaded and converted to Markdown'); ?>">
                        <i class="fa fa-link"></i> <?php echo __('Import URL'); ?>
                    </a>
                <?php endif; ?>
                <a href="<?php echo $baseurl; ?>/eventReports/reportFromEvent/<?php echo h($event_id); ?>" class="btn btn-default modal-open" title="<?php echo __('Based on filters, create a report summarizing the event'); ?>">
                    <i class="fa fa-list-alt"></i> <?php echo __('Auto-generate'); ?>
                </a>
            <?php endif; ?>
        </div>
        <div id="eventReportSelectors" class="btn-group btn-group-sm">
            <?php
                $contexts = [
                    'all' => __('All'),
                    'default' => __('Default'),
                    'deleted' => __('Deleted')
                ];
                foreach ($contexts as $ctx => $label):
                    $active = ($context === $ctx);
                    $url = sprintf('%s/eventReports/index/event_id:%s/index_for_event:1/context:%s', $baseurl, h($event_id), h($ctx));
            ?>
                <a href="<?php echo $url; ?>" class="btn btn-default <?php echo $active ? 'active' : ''; ?> <?php echo $ctx === 'default' ? 'defaultContext' : ''; ?>"><?php echo $label; ?></a>
            <?php endforeach; ?>
        </div>
    </div>

    <?php if ($extendedEvent || $extendingEvent): ?>
        <div class="alert alert-info" style="margin: 8px 0 10px 0;">
            <i class="fa fa-info-circle"></i>
            <?php echo $extendedEvent ? __('Viewing reports in extended mode event view') : __('Viewing reports in extending mode event view'); ?>
        </div>
    <?php endif; ?>

    <?php if (empty($reports)): ?>
        <div class="alert alert-info" style="margin: 0;">
            <i class="fa fa-info-circle"></i> <?php echo __('No reports found.'); ?>
        </div>
    <?php else: ?>
        <table class="table table-condensed table-hover beta-report-table" style="margin-bottom: 0;">
            <tbody>
                <?php foreach ($reports as $report): ?>
                    <?php
                        $r = $report['EventReport'];
                        $snippet = '';
                        if (!empty($r['content'])) {
                            $snippet = trim(strip_tags($r['content']));
                            $snippet = mb_strimwidth($snippet, 0, 180, '...');
                        }
                    ?>
                    <tr class="beta-report-row" data-report-id="<?php echo h($r['id']); ?>">
                        <td class="beta-report-main">
                            <div class="beta-report-name">
                                <span class="beta-report-id text-muted">#<?php echo h($r['id']); ?></span>
                                <div class="dist-widget dist-<?php echo intval($r['distribution']); ?> beta-report-dist"
                                     title="<?php echo $r['distribution'] == 4 ? h($report['SharingGroup']['name'] ?? '') : (isset($distributionLevels[$r['distribution']]) ? h($distributionLevels[$r['distribution']]) : ''); ?>">
                                </div>
                                <a href="#" onclick="viewFullReport(<?php echo h($r['id']); ?>); return false;" title="<?php echo __('View report summary'); ?>">
                                    <?php echo h($r['name']); ?>
                                </a>
                                <?php if (!empty($r['deleted'])): ?>
                                    <span class="label label-important"><?php echo __('Deleted'); ?></span>
                                <?php endif; ?>
                            </div>
                            <?php if ($snippet !== ''): ?>
                                <div class="beta-report-snippet"><?php echo h($snippet); ?></div>
                            <?php endif; ?>
                            <div class="beta-report-meta">
                                <span class="beta-relative-timestamp"
                                      data-timestamp="<?php echo h($r['timestamp']); ?>"
                                      data-absolute="<?php echo h(date('Y-m-d H:i:s', $r['timestamp'])); ?>"
                                      title="<?php echo h(date('Y-m-d H:i:s', $r['timestamp'])); ?>">
                                    <?php echo $this->Time->time($r['timestamp']); ?>
                                </span>
                            </div>
                        </td>
                        <td class="beta-report-actions">
                            <div class="btn-group btn-group-xs">
                                <a class="btn btn-default" href="#" onclick="viewFullReport(<?php echo h($r['id']); ?>); return false;" title="<?php echo __('View Summary'); ?>">
                                    <i class="fa fa-eye"></i>
                                </a>
                                <a class="btn btn-default" href="<?php echo $baseurl; ?>/eventReports/view/<?php echo h($r['id']); ?>" title="<?php echo __('Splitscreen Editor'); ?>">
                                    <i class="fa fa-columns"></i>
                                </a>
                                <?php if ($canModify): ?>
                                    <a class="btn btn-default modal-open" href="<?php echo $baseurl; ?>/eventReports/edit/<?php echo h($r['id']); ?>" title="<?php echo __('Edit Metadata'); ?>">
                                        <i class="fa fa-edit"></i>
                                    </a>
                                    <?php if (!$r['deleted']): ?>
                                        <a class="btn btn-default" href="#" onclick="simplePopup('<?php echo $baseurl; ?>/event_reports/delete/<?php echo h($r['id']); ?>'); return false;" title="<?php echo __('Delete'); ?>">
                                            <i class="fa fa-trash"></i>
                                        </a>
                                    <?php else: ?>
                                        <?php echo $this->Form->postLink('<i class="fa fa-trash-restore"></i>', ['controller' => 'event_reports', 'action' => 'restore', $r['id']], ['escape' => false, 'class' => 'btn btn-default', 'title' => __('Restore report'), 'confirm' => __('Are you sure you want to restore the Report?')]); ?>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<script>
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

    function getEventReportContainer() {
        var summaryContainer = $('#summary-reports-content');
        if (summaryContainer.length) {
            return summaryContainer;
        }
        return $('#event-reports-tab-content');
    }

    $(function() {
        $('#eventReportSelectors a').off('click').on('click', function(e) {
            e.preventDefault();
            var container = getEventReportContainer();
            container.empty().append(
                $('<div class="text-center" style="padding: 10px 0;"></div>')
                    .append(loadingSpanAnimation)
            );
            $.get($(this).attr('href'), function(data) {
                container.html(data);
                if (window.eventTimestamps && typeof window.eventTimestamps.update === 'function') {
                    window.eventTimestamps.update();
                }
            });
        });

        if (window.eventTimestamps && typeof window.eventTimestamps.update === 'function') {
            window.eventTimestamps.update();
        }
    });

    function reloadEventReportTable() {
        var url = $('#eventReportSelectors a.defaultContext').attr('href');
        var container = getEventReportContainer();
        $.ajax({
            dataType: 'html',
            beforeSend: function() {
                container.empty().append(
                    $('<div class="text-center" style="padding: 10px 0;"></div>').append(loadingSpanAnimation)
                );
            },
            success: function(data) {
                container.html(data);
                if (window.eventTimestamps && typeof window.eventTimestamps.update === 'function') {
                    window.eventTimestamps.update();
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                container.empty().text('<?php echo __('Failed to load Event report table'); ?>');
                showMessage('fail', textStatus + ': ' + errorThrown);
            },
            url: url
        });
    }
</script>

<style>
    .beta-reports-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 8px;
    }
    .beta-report-table td {
        vertical-align: middle;
        padding: 8px 6px;
    }
    .beta-report-main {
        width: 100%;
    }
    .beta-report-name {
        display: flex;
        align-items: center;
        gap: 6px;
        font-weight: 600;
        line-height: 1.3;
    }
    .beta-report-id {
        font-weight: 600;
        font-size: 11px;
        min-width: 34px;
    }
    .beta-report-dist {
        margin-right: 4px;
        transform: scale(0.82);
        transform-origin: left center;
    }
    .beta-report-snippet {
        color: #6f6f6f;
        font-size: 12px;
        margin-top: 2px;
        line-height: 1.35;
    }
    .beta-report-meta {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 2px;
        font-size: 11px;
    }
    .beta-report-actions {
        white-space: nowrap;
        text-align: right;
        width: 1%;
    }
    @media (max-width: 900px) {
        .beta-report-actions .btn-group {
            display: flex;
        }
        .beta-report-actions .btn {
            padding-left: 7px;
            padding-right: 7px;
        }
    }
</style>
