<?php
$form = $this->element('genericElements/Form/genericForm', [
    'entity' => null,
    'ajax' => false,
    'raw' => true,
    'data' => [
        'fields' => [
            [
                'type' => 'text',
                'field' => 'ids',
                'default' => !empty($id) ? json_encode([$id]) : ''
            ]
        ],
        'submit' => [
            'action' => $this->request->getParam('action')
        ]
    ]
]);
$formHTML = sprintf('<div class="d-none">%s</div>', $form);

if (!empty($id)) {
    $bodyMessage = !empty($deletionText) ? h($deletionText) : __('Are you sure you want to delete {0} #{1}?', h(Cake\Utility\Inflector::singularize($this->request->getParam('controller'))), h($id));
} else {
    $bodyMessage = !empty($deletionText) ? h($deletionText) : __('Are you sure you want to delete the given {0}?', h(Cake\Utility\Inflector::singularize($this->request->getParam('controller'))));
}
$bodyHTML = sprintf('%s%s', $formHTML, $bodyMessage);

echo $this->Bootstrap->modal([
    'size' => 'lg',
    'title' => !empty($deletionTitle) ? $deletionTitle : __('Delete {0}', h(Cake\Utility\Inflector::singularize(Cake\Utility\Inflector::humanize($this->request->getParam('controller'))))),
    'type' => 'confirm-danger',
    'confirmText' => !empty($deletionConfirm) ? $deletionConfirm : __('Delete'),
    'bodyHtml' => $bodyHTML,
]);
?>
