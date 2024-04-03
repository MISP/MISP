<div id="eventReportQuickIndex">
    <?php if ($extendedEvent): ?>
        <div class="alert alert-info"><?= __('Viewing reports in extended event view') ?></div>
    <?php endif; ?>
    <?php
        echo $this->element('/genericElements/IndexTable/index_table', array(
            'containerId' => 'eventreport',
            'data' => array(
                'data' => $reports,
                'top_bar' => array(
                    'children' => array(
                        array(
                            'type' => 'simple',
                            'children' => array(
                                array(
                                    'url' => $baseurl . '/eventReports/add/' . h($event_id),
                                    'active' => true,
                                    'text' => __('Add Event Report'),
                                    'fa-icon' => 'plus',
                                    'class' => 'modal-open',
                                    'requirement' => $canModify,
                                ),
                                array(
                                    'url' => $baseurl . '/eventReports/importReportFromUrl/' . h($event_id),
                                    'active' => true,
                                    'text' => __('Import from URL'),
                                    'title' => __('Content for this URL will be downloaded and converted to Markdown'),
                                    'fa-icon' => 'link',
                                    'class' => 'modal-open',
                                    'requirement' => $canModify && $importModuleEnabled,
                                ),
                                array(
                                    'url' => $baseurl . '/eventReports/reportFromEvent/' . h($event_id),
                                    'active' => true,
                                    'text' => __('Generate report from Event'),
                                    'title' => __('Based on filters, create a report summarizing the event'),
                                    'fa-icon' => 'list-alt',
                                    'class' => 'modal-open',
                                    'requirement' => $canModify,
                                ),
                            )
                        ),
                        array(
                            'type' => 'simple',
                            'id' => 'eventReportSelectors',
                            'children' => array(
                                array(
                                    'active' => $context === 'all',
                                    'url' => sprintf('%s/eventReports/index/event_id:%s/index_for_event:1/context:all', $baseurl, h($event_id)),
                                    'text' => __('All'),
                                ),
                                array(
                                    'active' => $context === 'default',
                                    'class' => 'defaultContext',
                                    'url' => sprintf('%s/eventReports/index/event_id:%s/index_for_event:1/context:default', $baseurl, h($event_id)),
                                    'text' => __('Default'),
                                ),
                                array(
                                    'active' => $context === 'deleted',
                                    'url' => sprintf('%s/event_reports/index/event_id:%s/index_for_event:1/context:deleted', $baseurl, h($event_id)),
                                    'text' => __('Deleted'),
                                ),
                            )
                        )
                    )
                ),
                'primary_id_path' => 'EventReport.id',
                'skip_pagination' => count($reports) < 10,
                'fields' => array(
                    array(
                        'name' => __('ID'),
                        'sort' => 'id',
                        'class' => 'short',
                        'data_path' => 'EventReport.id',
                    ),
                    array(
                        'name' => __('Context'),
                        'sort' => 'uuid',
                        'class' => 'short',
                        'data_path' => 'EventReport.uuid',
                        'notes_data_path' => 'Note',
                        'opinions_data_path' => 'Opinion',
                        'relationships_data_path' => 'Relationship',
                        'relationships_inbound_data_path' => 'RelationshipInbound',
                        'element' => 'shortUUIDWithNotes',
                        'object_type' => 'EventReport',
                    ),
                    array(
                        'name' => __('Name'),
                        'class' => 'useCursorPointer',
                        'data_path' => 'EventReport.name',
                    ),
                    array(
                        'name' => __('Event ID'),
                        'requirement' => $extendedEvent,
                        'class' => 'short',
                        'element' => 'links',
                        'data_path' => 'EventReport.event_id',
                        'url' => $baseurl . '/events/view/%s'
                    ),
                    array(
                        'name' => __('Last update'),
                        'sort' => 'timestamp',
                        'class' => 'short',
                        'element' => 'datetime',
                        'data_path' => 'EventReport.timestamp',
                    ),
                    array(
                        'name' => __('Distribution'),
                        'element' => 'distribution_levels',
                        'class' => 'short',
                        'data_path' => 'EventReport.distribution',
                    )
                ),
                'actions' => array(
                    array(
                        'url' => '/eventReports/view',
                        'url_params_data_paths' => array(
                            'EventReport.id'
                        ),
                        'icon' => 'eye',
                        'dbclickAction' => true
                    ),
                    array(
                        'title' => __('Delete'),
                        'icon' => 'trash',
                        'onclick' => 'simplePopup(\'' . $baseurl . '/event_reports/delete/[onclick_params_data_path]\');',
                        'onclick_params_data_path' => 'EventReport.id',
                        'complex_requirement' =>  function (array $row) use ($canModify) {
                            return $canModify && !$row['EventReport']['deleted'];
                        },
                    ),
                    array(
                        'title' => __('Restore report'),
                        'url' => $baseurl . '/event_reports/restore',
                        'url_params_data_paths' => array('EventReport.id'),
                        'icon' => 'trash-restore',
                        'postLink' => true,
                        'postLinkConfirm' => __('Are you sure you want to restore the Report?'),
                        'complex_requirement' => function (array $row) use ($canModify) {
                            return $canModify && $row['EventReport']['deleted'];
                        }
                    ),
                )
            )
        ));
    ?>
</div>
<script>
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';
    $(function() {
        $('#eventReportQuickIndex td[data-path="EventReport.name"]').click(function() {
            var reportId = $(this).closest('tr').data('primary-id')
            openGenericModal(baseurl + '/eventReports/viewSummary/' + reportId)
        })

        $('#eventReportSelectors a.btn').click(function(e) {
            e.preventDefault()
            $("#eventreport_content").empty()
                .append(
                    $('<div></div>')
                        .css({'text-align': 'center', 'font-size': 'large', 'margin': '5px 0'})
                        .append(loadingSpanAnimation)
                )
            var url = $(this).attr('href')
            $.get(url, function(data) {
                $("#eventreport_content").html(data);
            });
        });
    })

    function reloadEventReportTable() {
        var url = $("#eventReportSelectors a.defaultContext").attr('href')
        $.ajax({
            dataType: "html",
            beforeSend: function() {
                $("#eventreport_content").empty()
                .append(
                    $('<div></div>')
                        .css({'text-align': 'center', 'font-size': 'large', 'margin': '5px 0'})
                        .append(loadingSpanAnimation)
                )
            },
            success:function (data) {
                $("#eventreport_content").html(data);
            },
            error: function (jqXHR, textStatus, errorThrown) {
                $("#eventreport_content").empty().text('<?= __('Failed to load Event report table')?>')
                showMessage('fail', textStatus + ": " + errorThrown);
            },
            url:url
        });
    }
</script>
