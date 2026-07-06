<?php
/*
 * Overmind — Application logs (index / admin_index share this view)
 * Day-grouped timeline built server-side from the paginated $data.
 */

$this->set('headerTitle', __('Application logs'));
$this->set('headerDescription', __('System activity: authentication, imports, background tasks and more.'));

$filterFields = [
    [
        'name' => 'title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('Filter this page...'), 'col' => 6,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'text',
        'placeholder' => __('e.g. login, add, edit'), 'col' => 3,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'text',
        'placeholder' => __('e.g. User, Event'), 'col' => 3,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number', 'col' => 3,
    ],
    [
        'name' => 'email', 'label' => __('E-mail'), 'type' => 'text', 'col' => 3,
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text', 'col' => 3,
    ],
    [
        'name' => 'ip', 'label' => __('IP'), 'type' => 'text', 'col' => 3,
        'requirement' => (bool)Configure::read('MISP.log_client_ip'),
    ],
    [
        'name' => 'created', 'label' => __('Created after'), 'type' => 'date', 'col' => 3,
    ],
];

$prettyAction = function ($action) {
    return ucfirst(str_replace('_', ' ', (string)$action));
};

// Only admins can reach /admin/users/view — avoid dangling links for others.
$canLinkUser = !empty($isSiteAdmin) || !empty($me['Role']['perm_admin']);

$entries = [];
foreach (($data ?? []) as $item) {
    $log = $item['Log'];

    $userLink = ($canLinkUser && !empty($log['email']) && !empty($log['user_id']))
        ? $baseurl . '/admin/users/view/' . $log['user_id']
        : null;

    $modelEyebrow = ($log['model'] ?? '');
    if (!empty($log['model_id'])) {
        $modelEyebrow .= ' #' . $log['model_id'];
    }

    $changeText = '';
    if (!empty($log['change'])) {
        $changeText = $log['change'];
    } elseif (!empty($log['description'])) {
        $changeText = $log['description'];
    }
    $changeHtml = $changeText !== '' ? nl2br(h($changeText)) : '';

    $entries[] = [
        'created'      => $log['created'] ?? '',
        'action'       => $log['action'] ?? '',
        'action_label' => $prettyAction($log['action'] ?? ''),
        'title'        => $log['title'] ?? '',
        'model'        => $modelEyebrow,
        'user'         => !empty($log['email']) ? $log['email'] : null,
        'user_link'    => $userLink,
        'org'          => !empty($log['org']) ? $log['org'] : null,
        'change_html'  => $changeHtml,
    ];
}
?>

<div class="container-fluid">

    <?= $this->element('Logs/filter_card', [
        'item_url'      => '/logs',
        'search'        => ['placeholder' => __('Filter this page…')],
        'fields'        => $filterFields,
        'pager_element' => 'Logs/pager_prevnext',
    ]) ?>

    <?= $this->element('Logs/timeline', [
        'entries'    => $entries,
        'title'      => __('Application activity'),
        'icon'       => 'fas fa-clipboard-list',
        'empty_text' => __('No application log entries match your filters.'),
    ]) ?>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <?= $this->element('genericElementsBS5/IndexTable/pagination') ?>
        </div>
    </div>

</div>
