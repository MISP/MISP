<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data,
            'skip_pagination' => true,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'fa-icon' => 'trash',
                                'text' => __('Purge all Non referenced pictures'),
                                'class' => 'btn btn-primary',
                                'onClick' => "purgeUnusedPictures",
                                'requirement' => $me['Role']['perm_site_admin']
                            ]
                        ]
                    ],
                ],
            ],
            'title' => __('Manage Imported Picture on Instance'),
            'primary_id_path' => 'filename',
            'fields' => [
                [
                    'name' => __('Filename'),
                    'data_path' => 'filename',
                ],
                [
                    'name' => __('Picture Alias'),
                    'element' => 'custom',
                    'data_path' => 'alias',
                    'function' => function($entry) use ($baseurl) {
                        return sprintf('<input id="alias_input" value="%s" class="span3" type="text" style="margin-bottom: 0;" /><button class="btn btn-sm" data-filename="%s" onclick="saveAlias(this)">Save</button>', h($entry['alias']), h($entry['filename']));
                    },
                ],
                [
                    'name' => __('Image'),
                    'element' => 'custom',
                    'function' => function($entry) use ($baseurl) {
                        return sprintf('<img src="%s/eventReports/viewPicture/%s" class="screenshot useCursorPointer" style="display:block; max-width: 250px; max-height:250px;" width=250 height=250>', $baseurl, h($entry['filename']));
                    },
                ],
                [
                    'name' => __('Is Referenced'),
                    'data_path' => 'is_referenced',
                    'sort' => 'is_referenced',
                    'element' => 'boolean',
                    'class' => 'short',
                ],
                [
                    'name' => __('Reference Count'),
                    'data_path' => 'reference_count',
                ],
            ],
            'actions' => [
                [
                    'title' => __('Delete'),
                    'icon' => 'trash',
                    'url' => $baseurl . '/event_reports/deletePicture',
                    'url_params_data_paths' => array(
                        'filename'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete this picture?'),
                    'requirements' => $me['Role']['perm_site_admin'],
                ],
            ]
        ]
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'eventReports', 'menuItem' => 'managed_imported_pictures'));
    }
?>

<script>
    function purgeUnusedPictures(on, cache) {
        $.get(baseurl + "/eventReports/purgeUnusedPictures", function() {
            showMessage('success', '<?= __('Purged unused images') ?>')
            window.location.reload()
        }).fail(xhrFailCallback);
    }

    function saveAlias(clicked) {
        const filename = $(clicked).data('filename')
        const newAlias = $(clicked).parent().find('#alias_input').val()
        var url = baseurl + "/eventReports/setFileAlias"
        fetchFormDataAjax(url, function(formHTML) {
            $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
            var $tmpForm = $('#temp form')
            var formUrl = $tmpForm.attr('action')
            $tmpForm.find('#EventReportFilename').val(filename)
            $tmpForm.find('#EventReportAlias').val(newAlias)

            $.ajax({
                data: $tmpForm.serialize(),
                success:function(saveResult) {
                    showMessage('success', 'Alias set');
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    if (jqXHR.responseJSON) {
                        showMessage('fail', jqXHR.responseJSON.errors);
                    } else {
                        showMessage('fail', 'Error setting alias: ' + errorThrown);
                    }
                },
                complete:function() {
                    $('#temp').remove();
                },
                type:"post",
                url: formUrl
            })
        })
    }
</script>