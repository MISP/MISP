<?php
/**
 * The view's action card: whom the profile scores and what can be done
 * with it, from the same ProfileActionsTool the index's row menu reads.
 * Every write opens its confirmation in #mainModal.
 *
 * @var array $profile
 * @var array|null $standing This profile's row of the index board
 * @var bool $may_edit
 * @var array $bench
 */
App::uses('ProfileActionsTool', 'Tools/AnalystProfile');

$focus = $bench['focus'];
// A reader who arrived to see one value wants to edit and compare against it.
$query = $focus === null ? array() : array('value' => $focus);
$modal = function ($url) {
    return 'event.preventDefault(); openModal(' . json_encode($url) . ", 'md');";
};
$asAction = function (array $write) use ($modal) {
    $url = $this->Html->url($write['url']);
    return array(
        'url' => $url,
        'onclick' => $modal($url),
        'icon' => 'fas fa-' . $write['icon'],
        'label' => $write['label'],
        'short' => $write['short'],
    );
};

$writes = $standing === null ? null : ProfileActionsTool::writes($standing, array(
    'org' => !empty($me['Role']['perm_admin']),
    'instance' => !empty($me['Role']['perm_site_admin']),
    'fork_org' => !empty($me['Role']['perm_admin'])
        || !empty($me['Role']['perm_site_admin']),
));
$uses = $writes === null ? array() : array_values(array_filter(
    $writes['use'],
    function ($write) {
        return !$write['disabled'];
    }
));

$actions = array();
foreach ($uses as $i => $write) {
    $actions[] = $asAction($write) + array('pinned' => $i === 0);
}
if ($may_edit) {
    $actions[] = array(
        'url' => $this->Html->url(array('action' => 'edit', $profile['id'],
            '?' => $query)),
        'icon' => 'fas fa-pen',
        'label' => __('Edit'),
        'pinned' => true,
    );
}
$actions[] = array(
    'url' => $this->Html->url(array('action' => 'simulate', $profile['id'],
        '?' => $query)),
    'onclick' => "event.preventDefault(); analystProfileCompare(this.getAttribute('href'));",
    'icon' => 'fas fa-flask',
    'label' => __('Open the full comparison'),
    'short' => __('Compare'),
    'pinned' => true,
);
$actions[] = array(
    'url' => $this->Html->url(array('action' => 'export', $profile['id'])),
    'icon' => 'fas fa-file-export',
    'label' => __('Export JSON'),
    'short' => __('Export'),
    'pinned' => true,
);
if ($writes !== null) {
    if (!empty($writes['fork'])) {
        $actions[] = array('divider' => true, 'label' => __('Fork'));
        foreach ($writes['fork'] as $write) {
            $actions[] = $asAction($write);
        }
    }
    foreach ($writes['share'] as $write) {
        $actions[] = $asAction($write);
    }
    foreach ($writes['delete'] as $write) {
        $actions[] = $asAction($write) + array('danger' => true);
    }
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', array(
    'actions' => $actions,
    'maxTiles' => 4,
));
