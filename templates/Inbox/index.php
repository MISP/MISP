<?php
echo $this->Html->scriptBlock(sprintf(
    'var csrfToken = %s;',
    json_encode($this->request->getAttribute('csrfToken'))
));
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'multi_select_actions',
                    'children' => [
                        [
                            'text' => __('Discard message'),
                            'variant' => 'danger',
                            'onclick' => 'discardMessages',
                        ]
                    ],
                    'data' => [
                        'id' => [
                            'value_path' => 'id'
                        ]
                    ]
                ],
                [
                    'type' => 'context_filters',
                    'context_filters' => !empty($filteringContexts) ? $filteringContexts : []
                ],
                [
                    'type' => 'search',
                    'button' => __('Search'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value',
                    'allowFilering' => true
                ],
                [
                    'type' => 'table_action',
                    'table_setting_id' => 'inbox_index',
                ]
            ]
        ],
        'fields' => [
            [
                'name' => '#',
                'sort' => 'Inbox.id',
                'data_path' => 'id',
            ],
            [
                'name' => 'created',
                'sort' => 'Inbox.created',
                'data_path' => 'created',
                'element' => 'datetime'
            ],
            [
                'name' => 'severity',
                'sort' => 'severity',
                'data_path' => 'severity',
                'element' => 'function',
                'function' => function ($entry, $context) {
                    return $context->Bootstrap->badge([
                        'text' => $entry->severity_variant,
                        'variant' => $entry->severity_variant,
                    ]);
                }
            ],
            [
                'name' => 'scope',
                'sort' => 'scope',
                'data_path' => 'scope',
            ],
            [
                'name' => 'action',
                'sort' => 'action',
                'data_path' => 'action',
            ],
            [
                'name' => 'title',
                'sort' => 'title',
                'data_path' => 'title',
            ],
            [
                'name' => 'origin',
                'sort' => 'origin',
                'data_path' => 'origin',
            ],
            [
                'name' => 'user',
                'sort' => 'Inbox.user_id',
                'data_path' => 'user',
                'element' => 'user'
            ],
            [
                'name' => 'message',
                'sort' => 'message',
                'data_path' => 'message',
            ],
        ],
        'title' => __('Inbox'),
        'description' => __('A list of requests to be manually processed'),
        'actions' => [
            [
                'url' => '/inbox/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye',
                'title' => __('View request')
            ],
            [
                'open_modal' => '/inbox/process/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'cogs',
                'title' => __('Process request')
            ],
            [
                'open_modal' => '/inbox/delete/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'trash',
                'title' => __('Discard message')
            ],
        ]
    ]
]);
?>

<script>
    function discardMessages(idList, selectedData, $table) {
        const successCallback = function([data, modalObject]) {
            UI.reload('/inbox/index', UI.getContainerForTable($table), $table)
        }
        const failCallback = ([data, modalObject]) => {
            const tableData = selectedData.map(row => {
                entryInError = data.filter(error => error.data.id == row.id)[0]
                $faIcon = $('<i class="fa"></i>').addClass(entryInError.success ? 'fa-check text-success' : 'fa-times text-danger')
                return [row.id, row.scope, row.action, row.title, entryInError.message, JSON.stringify(entryInError.errors), $faIcon]
            });
            handleMessageTable(
                modalObject.$modal,
                ['<?= __('ID') ?>', '<?= __('Scope') ?>', '<?= __('Action') ?>', '<?= __('Title') ?>', '<?= __('Message') ?>', '<?= __('Error') ?>', '<?= __('State') ?>'],
                tableData
            )
            const $footer = $(modalObject.ajaxApi.statusNode).parent()
            modalObject.ajaxApi.statusNode.remove()
            const $cancelButton = $footer.find('button[data-bs-dismiss="modal"]')
            $cancelButton.text('<?= __('OK') ?>').removeClass('btn-secondary').addClass('btn-primary')
        }
        UI.submissionModal('/inbox/delete', successCallback, failCallback).then(([modalObject, ajaxApi]) => {
            const $idsInput = modalObject.$modal.find('form').find('input#ids-field')
            $idsInput.val(JSON.stringify(idList))
            const tableData = selectedData.map(row => {
                return [row.id, row.scope, row.action, row.title]
            });
            handleMessageTable(
                modalObject.$modal,
                ['<?= __('ID') ?>', '<?= __('Scope') ?>', '<?= __('Action') ?>', '<?= __('Title') ?>'],
                tableData
            )
        })

        function constructMessageTable(header, data) {
            return HtmlHelper.table(
                header,
                data,
                {
                    small: true,
                    borderless: true,
                    tableClass: ['message-table', 'mt-4 mb-0'],
                }
            )
        }

        function handleMessageTable($modal, header, data) {
            const $modalBody = $modal.find('.modal-body')
            const $messageTable = $modalBody.find('table.message-table')
            const messageTableHTML = constructMessageTable(header, data)[0].outerHTML
            if ($messageTable.length) {
                $messageTable.html(messageTableHTML)
            } else {
                $modalBody.append(messageTableHTML)
            }
        }
    }
</script>