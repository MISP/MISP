<?php
/*
 * Overmind — Application logs (index / admin_index share this view)
 * Day-grouped timeline built server-side from the paginated $data.
 */

$this->set('headerTitle', __('Application logs'));
$this->set('headerDescription', __('System activity: authentication, imports, background tasks and more.'));

// 'auth_fail' → 'Auth fail', 'attachTagToObject' → 'Attach tag to object'.
// Used both for the dropdown labels and for the timeline's action badges.
$prettyAction = function ($action) {
    $words = preg_replace('/(?<!^)[A-Z]/', ' $0', str_replace('_', ' ', (string)$action));
    return ucfirst(mb_strtolower($words));
};

// Action and model are closed sets on the application log too, so they get a
// dropdown rather than a free-text box you have to spell right.
$actionOptions = ['' => __('All actions')];
foreach (($actions ?? []) as $a) {
    $actionOptions[$a] = $prettyAction($a);
}
$modelOptions = ['' => __('All models')];
foreach (($models ?? []) as $m) {
    $modelOptions[$m] = $m;
}

$what = __('What');
$who = __('Who');
$filterFields = [
    [
        'name' => 'title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('e.g. a user or an event name'), 'group' => $what,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'select',
        'options' => $actionOptions, 'group' => $what,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'select',
        'options' => $modelOptions, 'group' => $what,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number',
        'placeholder' => __('e.g. 42'), 'group' => $what,
    ],
    [
        'name' => 'email', 'label' => __('E-mail'), 'type' => 'text',
        'placeholder' => __('e.g. alice@example.com'), 'group' => $who,
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text',
        'placeholder' => __('e.g. CIRCL'), 'group' => $who,
    ],
    [
        'name' => 'ip', 'label' => __('IP'), 'type' => 'text',
        'placeholder' => __('e.g. 10.0.0.1'), 'group' => $who,
        'requirement' => (bool)Configure::read('MISP.log_client_ip'),
    ],
    [
        'name' => 'created', 'label' => __('Created'), 'type' => 'date', 'group' => __('When'),
    ],
];

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

<div class="container-fluid" data-ifp-scope="/logs">

    <?= $this->element('Logs/filter_bar', [
        'item_url' => '/logs',
        'search'   => ['placeholder' => __('Search title, description, change, model, action, user, org…')],
        'fields'   => $filterFields,
        'rows'     => $entries,
        'pager'    => 'Logs/pager_prevnext',
    ]) ?>

    <!-- Swapped by the filter bar when filters apply (index-filters.js) -->
    <div id="log-index-results" class="index-results" data-ifp-results>
        <?= $this->element('Logs/timeline', [
            'entries'    => $entries,
            'title'      => __('Application activity'),
            'icon'       => 'fas fa-clipboard-list',
            'empty_text' => __('No application log entries match your filters.'),
        ]) ?>

        <?= $this->element('genericElementsBS5/IndexTable/pagination_bottom', [
            'rows' => count($entries),
            'pager' => 'Logs/pager_prevnext',
        ]) ?>
    </div>

</div>
