<?php
App::uses('CakeTime', 'Utility');

$collectiontId = h($data['Collection']['id']);
$mayModify = $this->Acl->canModifyCollection($data);

$actions = [];

// Shared beyond the organisation, the collection reaches partners when
// published; those who may change it are told where that stands
$publish = $publishState ?? null;
$status = null;
$reviewUrl = "$baseurl/collections/publish/$collectiontId";
if (!empty($publish) && (int)$publish['distribution'] !== 0 && (!empty($publish['_canEdit']) || !empty($publish['_canPublish']))) {
    $analysisLabels = [__('Initial'), __('Ongoing'), __('Completed')];
    $ago = function ($stamp) {
        return CakeTime::timeAgoInWords($stamp, ['end' => '+100 years', 'accuracy' => ['year' => 'year', 'month' => 'month', 'week' => 'week', 'day' => 'day', 'hour' => 'hour']]);
    };
    $lastPublished = empty($publish['last_published']) ? 0 : strtotime($publish['last_published']);
    if (!$publish['withheld']) {
        $status = [
            'published' => true,
            'lastPublished' => $lastPublished,
            'label' => __('Published'),
            'sub' => implode(' · ', array_filter([
                $lastPublished ? $ago($lastPublished) : null,
                $analysisLabels[$publish['analysis']] ?? null,
            ])),
            'title' => __('Partners hold this collection as it is.'),
        ];
        if (!empty($publish['_canPublish'])) {
            $unpublishUrl = "$baseurl/collections/unpublish/$collectiontId";
            $actions[] = [
                'url' => $unpublishUrl,
                'onclick' => "event.preventDefault(); openModal('$unpublishUrl', 'md');",
                'icon' => 'fas fa-eye-slash',
                'label' => __('Unpublish collection'),
                'short' => __('Unpublish'),
                'primary' => true,
                'warning' => true,
            ];
        }
    } else {
        $changes = $publish['changes'] ?? ['added' => 0, 'removed' => 0];
        $count = $changes['added'] + $changes['removed'];
        // Nothing counted and nothing changed since the last publish: unpublished by hand
        $handUnpublished = $count === 0 && $lastPublished > 0
            && !empty($publish['modified']) && strtotime($publish['modified']) <= $lastPublished;
        if (!empty($publish['_canPublish'])) {
            $label = $count > 0
                ? __n('%s change not yet shared', '%s changes not yet shared', $count, $count)
                : ($handUnpublished ? __('Unpublished') : __('Changes not yet shared'));
        } else {
            $label = $count > 0
                ? __n('%s change waiting for a publisher', '%s changes waiting for a publisher', $count, $count)
                : __('Waiting for a publisher');
        }
        $counts = array_filter([
            $changes['added'] ? __('+%s added', $changes['added']) : null,
            $changes['removed'] ? __('−%s removed', $changes['removed']) : null,
        ]);
        $status = [
            'published' => false,
            'pending' => $lastPublished > 0,
            'lastPublished' => $lastPublished,
            'label' => $label,
            'sub' => !empty($counts)
                ? implode(', ', $counts)
                : ($lastPublished ? __('Published %s', $ago($lastPublished)) : __('Never published')),
            'title' => __('Partners keep the version they last received until someone with the right to publish publishes it.'),
        ];
        if (!empty($publish['_canPublish'])) {
            $actions[] = [
                'url' => $reviewUrl,
                'onclick' => "event.preventDefault(); openModal('$reviewUrl', 'lg');",
                'icon' => 'fas fa-upload',
                'label' => __('Review and publish'),
                'short' => __('Publish'),
                'primary' => true,
                'success' => true,
                'attributes' => ['data-collection-publish' => ''],
            ];
        }
    }
}

// The workspace follows the collection rule, not the page's
$canWorkspace = !empty($intelGraph) && $this->Acl->canAccess('collections', 'active')
    && ClassRegistry::init('Collection')->canModify($me, $data['Collection']);
if ($canWorkspace) {
    $actions[] = [
        'url' => '#',
        'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
        'label' => __('Make it my workspace'),
        'short' => __('Workspace'),
        'attributes' => ['data-intel-graph-workspace' => strtolower($data['Collection']['uuid'])],
    ];
}

if ($isSiteAdmin || $mayModify) {
    $actions[] = [
        'url' => "$baseurl/CollectionElements/add/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/CollectionElements/add/$collectiontId');",
        'icon' => 'fas fa-file',
        'add' => true,
        'label' => __('Add Element to Collection'),
        'short' => __('Add element')
    ];

    $actions[] = [
        'url' => "$baseurl/collections/edit/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/collections/edit/$collectiontId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Collection'),
        'short' => __('Edit')
    ];

    $actions[] = [
        'url' => "$baseurl/collections/delete/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/collections/deleteSelection/$collectiontId');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Collection'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', array_filter([
    'actions' => $actions,
    'status' => $status,
]));

if ($status !== null && !empty($publish['_canPublish']) && $publish['withheld'] && !empty($this->request->query['review'])):
?>
<script>
document.addEventListener('DOMContentLoaded', function () {
    openModal(<?= json_encode($reviewUrl) ?>, 'lg');
});
</script>
<?php endif; ?>
