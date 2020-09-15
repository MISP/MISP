<div id="eventReportQuickIndex">
    <button class="btn btn-small btn-primary" onclick="openGenericModal(baseurl + '/eventReports/add/<?= h($eventid) ?>')">
        <i class="<?= $this->FontAwesome->getClass('plus') ?>"></i> <?= __('Add Event Report') ?>
    </button>
    <?php
        echo $this->element('/genericElements/IndexTable/index_table', array(
            'data' => array(
                'data' => $reports,
                'skip_pagination' => true,
                'primary_id_path' => 'id',
                'fields' => array(
                    array(
                        'name' => __('Name'),
                        'class' => 'short blue useCursorPointer',
                        'data_path' => 'name',
                    ),
                    array(
                        'name' => __('Last update'),
                        'sort' => 'timestamp',
                        'class' => 'short',
                        'element' => 'datetime',
                        'data_path' => 'timestamp',
                    ),
                    array(
                        'name' => __('Distribution'),
                        'class' => 'short',
                        'element' => 'distribution_levels',
                        'data_path' => 'distribution',
                    ),
                ),
                'actions' => array(
                    array(
                        'url' => $baseurl . '/eventReports/view',
                        'url_params_data_paths' => array('id'),
                        'icon' => 'eye'
                    ),
                    array(
                        'url' => '/eventReports/edit',
                        'url_params_data_paths' => array('id'),
                        'icon' => 'edit'
                    ),
                    array(
                        'title' => __('Delete'),
                        'url' => $baseurl . '/event_reports/delete',
                        'url_params_data_paths' => array('id'),
                        'postLink' => true,
                        'postLinkConfirm' => __('Are you sure you want to delete the report?'),
                        'icon' => 'trash'
                    ),
                )
            )
        ));
    ?>
</div>

<script>
    $(document).ready(function() {
        $('#eventReportQuickIndex td[data-path="name"]').click(function() {
            var reportId = $(this).closest('tr').data('primary-id')
            openGenericModal('/eventReports/viewSummary/' + reportId)
        })
    })
</script>