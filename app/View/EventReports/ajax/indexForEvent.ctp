<div id="eventReportQuickIndex">
    <?php if ($extendedEvent): ?>
        <div class="alert alert-info"><?= __('Viewing reports in extended event view') ?></div>
    <?php endif; ?>
    <div style="margin-bottom: 10px;">
        <button class="btn btn-small btn-primary" onclick="openGenericModal(baseurl + '/eventReports/add/<?= h($event_id) ?>')">
            <i class="<?= $this->FontAwesome->getClass('plus') ?>"></i> <?= __('Add Event Report') ?>
        </button>
        <?php if ($importModuleEnabled): ?>
            <button class="btn btn-small btn-primary" onclick="openGenericModal(baseurl + '/eventReports/importReportFromUrl/<?= h($event_id) ?>')" title="<?= __('Content for this URL will be downloaded and converted to Mardown') ?>">
                <i class="<?= $this->FontAwesome->getClass('link') ?>"></i> <?= __('Import from URL') ?>
            </button>
        <?php endif; ?>
    </div>
    <?php
        echo $this->element('/genericElements/IndexTable/index_table', array(
            'paginatorOptions' => array(
                'update' => '#eventreport_index_div',
            ),
            'data' => array(
                'data' => $reports,
                'top_bar' => array(
                    'children' => array(
                        array(
                            'type' => 'simple',
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
                        'name' => __('Id'),
                        'sort' => 'id',
                        'class' => 'short',
                        'data_path' => 'EventReport.id',
                    ),
                    array(
                        'name' => __('Name'),
                        'class' => 'useCursorPointer',
                        'data_path' => 'EventReport.name',
                    ),
                    array(
                        'name' => __('Event ID'),
                        'requirement' => $extendedEvent,
                        'data_path' => 'EventReport.event_id',
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
                        'complex_requirement' => array(
                            'function' => function ($row, $options) {
                                return ($options['me']['Role']['perm_site_admin'] || $options['me']['org_id'] == $options['datapath']['orgc']) && !$options['datapath']['deleted'];
                            },
                            'options' => array(
                                'me' => $me,
                                'datapath' => array(
                                    'orgc' => 'EventReport.orgc_id',
                                    'deleted' => 'EventReport.deleted'
                                )
                            )
                        ),
                    ),
                    array(
                        'title' => __('Restore report'),
                        'url' => $baseurl . '/event_reports/restore',
                        'url_params_data_paths' => array('EventReport.id'),
                        'icon' => 'trash-restore',
                        'postLink' => true,
                        'postLinkConfirm' => __('Are you sure you want to restore the Report?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) {
                                return ($options['me']['Role']['perm_site_admin'] || $options['me']['org_id'] == $options['datapath']['orgc']) && $options['datapath']['deleted'];
                            },
                            'options' => array(
                                'me' => $me,
                                'datapath' => array(
                                    'orgc' => 'EventReport.orgc_id',
                                    'deleted' => 'EventReport.deleted'
                                )
                            )
                        ),
                    ),
                )
            )
        ));
    ?>
</div>

<script>
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';
    $(document).ready(function() {
        $('#eventReportQuickIndex td[data-path="EventReport.name"]').click(function() {
            var reportId = $(this).closest('tr').data('primary-id')
            openGenericModal('/eventReports/viewSummary/' + reportId)

        })

        $('#eventReportQuickIndex .btn-toolbar a.btn').click(function(e) {
            e.preventDefault()
            $("#eventreport_index_div").empty()
                .append(
                    $('<div></div>')
                        .css({'text-align': 'center', 'font-size': 'large', 'margin': '5px 0'})
                        .append(loadingSpanAnimation)
                )
            var url = $(this).attr('href')
            $.get(url, function(data) {
                $("#eventreport_index_div").html(data);
            });
        });
    })

    function reloadEventReportTable() {
        var url = $("#eventReportQuickIndex a.defaultContext").attr('href')
        $.ajax({
            dataType:"html",
            beforeSend: function() {
                $("#eventreport_index_div").empty()
                .append(
                    $('<div></div>')
                        .css({'text-align': 'center', 'font-size': 'large', 'margin': '5px 0'})
                        .append(loadingSpanAnimation)
                )
            },
            success:function (data) {
                $("#eventreport_index_div").html(data);
            },
            error: function (jqXHR, textStatus, errorThrown) {
                $("#eventreport_index_div").empty().text('<?= __('Failed to load Event report table')?>')
                showMessage('fail', textStatus + ": " + errorThrown);
            },
            url:url
        });
    }
</script>
