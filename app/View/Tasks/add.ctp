<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit scheduled task') : __('Add scheduled task'),
        'description' => __('Scheduled tasks are used to run jobs such as Server pull/push/cache or Feed fetch/cache in the background. You can set the frequency for each task. Be aware that if the Server has not pull/push enabled or the Feed is not enabled, the selected action will not be executed.'),
        'fields' => [
            [
                'field' => 'type',
                'label' => __('Type'),
                'options' => [
                    'Server' => 'Server',
                    'Feed' => 'Feed',
                    'Workflow' => 'Workflow',
                    'Periodic Summary' => 'Periodic Summary',
                    'TAXII' => 'TAXII',
                    'Admin' => 'Admin'
                ],
                'type' => 'dropdown',
                'class' => 'form-control span6',
            ],
            [
                'field' => 'server_action',
                'label' => __('Action'),
                'options' => [
                    'pull' => 'Pull',
                    'push' => 'Push',
                    'cache' => 'Cache'
                ],
                'type' => 'dropdown',
                'class' => 'span6',
                'div' => ['id' => 'ServerAction', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'server_id',
                'label' => __('Server'),
                'options' => $dropdownData['servers'],
                'type' => 'dropdown',
                'picker' => true,
                '_chosenOptions' => [
                    'width' => '460px',
                ],
                'class' => 'span6',
                'div' => ['id' => 'Server', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'server_technique',
                'label' => __('Technique'),
                'options' => [
                    'full' => 'Full',
                    'update' => 'Update',
                    'incremental' => 'Incremental'
                ],
                'type' => 'dropdown',
                'class' => 'span6',
                'div' => ['id' => 'ServerTechnique', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'feed_action',
                'label' => __('Action'),
                'options' => [
                    'fetch' => 'Fetch',
                    'cache' => 'Cache'
                ],
                'type' => 'dropdown',
                'class' => 'span6',
                'div' => ['id' => 'FeedAction', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'feed_id',
                'label' => __('Feed'),
                'options' => $dropdownData['feeds'],
                'type' => 'dropdown',
                'picker' => true,
                '_chosenOptions' => [
                    'width' => '460px',
                ],
                'class' => 'span6',
                'div' => ['id' => 'Feed', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'feed_scope',
                'label' => __('Scope'),
                'options' => [
                    'freetext' => 'Freetext',
                    'csv' => 'CSV',
                    'misp' => 'MISP',
                    'all' => 'All'
                ],
                'type' => 'dropdown',
                'class' => 'span6',
                'div' => ['id' => 'FeedScope', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'workflow',
                'label' => __('Ad-hoc Workflow'),
                'options' => $dropdownData['workflows'],
                'type' => 'dropdown',
                'picker' => true,
                '_chosenOptions' => [
                    'width' => '460px',
                ],
                'class' => 'span6',
                'div' => ['id' => 'Workflow', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'taxii_server_id',
                'label' => __('TAXII Server'),
                'options' => $dropdownData['taxii_servers'],
                'type' => 'dropdown',
                'picker' => true,
                '_chosenOptions' => [
                    'width' => '460px',
                ],
                'class' => 'span6',
                'div' => ['id' => 'TaxiiServer', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'admin_action',
                'label' => __('Action'),
                'options' => [
                    'updateGalaxies' => 'Update Galaxies',
                    'updateTaxonomies' => 'Update Taxonomies',
                    'updateWarningLists' => 'Update Warninglists',
                    'updateNoticeLists' => 'Update Noticelists',
                    'updateObjectTemplates' => 'Update Object Templates',
                    'checkUserValidity' => 'Check User Validity (report only)',
                    'blockInvalidUsers' => 'Check User Validity (disable invalid users)'
                ],
                'type' => 'dropdown',
                'class' => 'span6',
                'div' => ['id' => 'AdminAction', 'style' => 'display:none', 'class' => 'optionalField'],
            ],
            [
                'field' => 'user_id',
                'label' => __('User'),
                'options' => $dropdownData['users'],
                'type' => 'dropdown',
                'default' => Configure::read('CurrentUserId'),
                'picker' => true,
                '_chosenOptions' => [
                    'width' => '460px',
                ],
                'class' => 'span6'
            ],
            [
                'field' => 'time_multiplier',
                'label' => __('Runs every'),
                'class' => 'span2',
                'stayInLine' => 1,
                'default' => 1,
                'value' => isset($edit) && isset($this->request->data['Task']['time_multiplier']) ? $this->request->data['Task']['time_multiplier'] : null,
            ],
            [
                'field' => 'time_unit',
                'label' => __('Period'),
                'options' => [
                    1 => __('second(s)'),
                    60 => __('minute(s)'),
                    3600 => __('hour(s)'),
                    86400 => __('day(s)'),
                ],
                'type' => 'dropdown',
                'class' => 'span2',
                'default' => 86400,
                'value' => isset($edit) && isset($this->request->data['Task']['time_unit']) ? $this->request->data['Task']['time_unit'] : null,
                'placeholder' => __('e.g. 60 for every minute')
            ],
            [
                'field' => 'next_execution_date',
                'label' => __('Next Execution Date') . '<span class="fas fa-calendar label-icon"></span>',
                'class' => 'datepicker span6',
                'type' => 'text',
                'placeholder' => __('Leave blank for immediate execution'),
                'type' => 'text'
            ],
            [
                'field' => 'next_execution_time',
                'label' => __('Next Execution Time') . '<span class="fas fa-clock label-icon"></span>',
                'type' => 'text',
                'placeholder' => __('HH:MM:SS'),
                'description' => __("Current server time: %s", date('H:i:s')),
            ],
            [
                'field' => 'description',
                'label' => __('Description'),
                'type' => 'text',
                'class' => 'span6'
            ],
            [
                'field' => 'enabled',
                'label' => __('Enabled'),
                'type' => 'checkbox',
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
echo $this->Js->writeBuffer();
?>
<style>
    .modal-body-long {
        max-height: 70vh;
        overflow-y: auto;
    }

    .modal-footer {
        position: sticky;
        bottom: 0;
        background: #f9f9f9;
        padding-top: 10px;
        border-top: 1px solid #ddd;
    }
</style>

<script type="text/javascript">
    $(document).ready(function() {
        function refreshTaskForm() {
            taskFormUpdate();
            if ($("#TaskType").val() === "TAXII") {
                $("#TaxiiServer").show();
            }
            $("#TaxiiServer select, #Workflow select, #Server select, #Feed select").trigger("chosen:updated");
        }

        $(".datepicker").datepicker({
            preventMultipleSet: true,
            format: 'yyyy-mm-dd',
            todayHighlight: true
        });
        refreshTaskForm();
        $("#TaskType, #TaskRunAfterCreation, #TaskFeedAction, #TaskServerAction, #TaskFeedId").change(function() {
            refreshTaskForm();
        });

        // Keep the displayed times ticking. The server time is seeded with the
        // server's wall-clock at page load and advanced by elapsed real time, so
        // it stays in the server's timezone instead of the browser's.
        var serverSecondsAtLoad = parseInt("<?= date('H') * 3600 + date('i') * 60 + date('s') ?>", 10);
        var loadTimestamp = Date.now();
        $("#TaskNextExecutionTime").closest('.input').nextAll('.form-field-description').first().html(
            "<?= __('Current server time') ?>: <span id=\"TaskServerTime\"></span>"
        );
        function pad(n) {
            return (n < 10 ? '0' : '') + n;
        }
        function formatSeconds(totalSeconds) {
            totalSeconds = ((totalSeconds % 86400) + 86400) % 86400;
            return pad(Math.floor(totalSeconds / 3600)) + ':' +
                pad(Math.floor((totalSeconds % 3600) / 60)) + ':' +
                pad(totalSeconds % 60);
        }
        function updateTime() {
            var elapsed = Math.floor((Date.now() - loadTimestamp) / 1000);
            $("#TaskServerTime").text(formatSeconds(serverSecondsAtLoad + elapsed));
        }
        updateTime();
        setInterval(updateTime, 1000);
    });
</script>
