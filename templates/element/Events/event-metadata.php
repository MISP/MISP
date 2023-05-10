<?php

use Cake\Core\Configure;

$content = '';

$event = $entity;
$contributors = [];
$instanceFingerprint = '???';
$hostOrgUser = true;


$fields = [
    [
        'key' => __('Event ID'),
        'path' => 'Event.id'
    ],
    [
        'key' => 'UUID',
        'path' => 'Event.uuid',
        'valueClass' => 'quickSelect fw-light fs-7',
        // 'type' => 'uuid',
        'action_buttons' => [
            [
                'url' => $baseurl . '/events/add/extends:' . h($event['Event']['uuid']),
                'icon' => 'plus-square',
                'style' => 'color:black; font-size:15px;padding-left:2px',
                'title' => __('Extend this event'),
                // 'requirement' => $this->Acl->canAccess('events', 'add'),
                'requirement' => true,
            ],
            [
                'url' => $baseurl . '/servers/idTranslator/' . h($event['Event']['id']),
                'icon' => 'server',
                'style' => 'color:black; font-size:15px;padding-left:2px',
                'title' => __('Check this event on different servers'),
                // 'requirement' => $this->Acl->canAccess('servers', 'idTranslator'),
                'requirement' => true,
            ]
        ]
    ],
    [
        'key' => __('Creator org'),
        // 'type' => 'org',
        // 'path' => 'Orgc',
        'path' => 'Event.Orgc.name',
        'element' => 'org',
        'requirement' => empty(Configure::read('MISP.showorgalternate'))
    ],
    [
        'key' => __('Owner org'),
        // 'type' => 'org',
        // 'path' => 'Org',
        'path' => 'Event.Org.name',
        'element' => 'org',
        'requirement' => $isSiteAdmin && empty(Configure::read('MISP.showorgalternate'))
    ],
    [
        'key' => __('Contributors'),
        'type' => 'custom',
        'function' => function (array $event) use ($contributors, $baseurl) {
            $contributorsContent = [];
            foreach ($contributors as $organisationId => $name) {
                $org = ['Organisation' => ['id' => $organisationId, 'name' => $name]];
                if (Configure::read('MISP.log_new_audit')) {
                    $link = $baseurl . "/audit_logs/eventIndex/" . h($event['Event']['id']) . '/' . h($organisationId);
                } else {
                    $link = $baseurl . "/logs/event_index/" . h($event['Event']['id']) . '/' . h($name);
                }
                $contributorsContent[] = $this->OrgImg->getNameWithImg($org, $link);
            }
            return implode('<br>', $contributorsContent);
        },
        'requirement' => !empty($contributors)
    ],
    [
        'key' => __('Creator user'),
        // 'path' => 'User.email',
        'path' => 'Event.event_creator_email',
        'requirement' => isset($event['User']['email'])
    ],
    [
        'key' => __('Protected Event'),
        'key_info' => __(
            "Protected events carry a list of cryptographic keys used to sign and validate the information in transit.\n\nWhat this means in practice, a protected event shared with another instance will only be able to receive updates via the synchronisation mechanism from instances that are able to provide a valid signature from the event's list of signatures.\n\nFor highly critical events in broader MISP networks, this can provide an additional layer of tamper proofing to ensure that the original source of the information maintains control over modifications. Whilst this feature has its uses, it is not required in most scenarios."
        ),
        'path' => 'CryptographicKey',
        'event_path' => 'Event',
        'owner' => ((int)$loggedUser['org_id'] === (int)$event['Event']['orgc_id'] &&
            $hostOrgUser &&
            !$event['Event']['locked']
        ),
        'instanceFingerprint' => $instanceFingerprint,
        // 'type' => 'protectedEvent'
    ],
    [
        'key' => __('Date'),
        'path' => 'Event.date'
    ],
    [
        'key' => __('Distribution'),
        'path' => 'Event.distribution',
        'sg_path' => 'SharingGroup',
        'event_id_path' => 'Event.id',
        // 'type' => 'distribution'
    ],
    [
        'key' => __('Published'),
        // 'path' => 'Event.published',
        'key_class' => ($event['Event']['published'] == 0) ? 'not-published' : 'published',
        'class' => ($event['Event']['published'] == 0) ? 'not-published' : 'published',
        'rowVariant' => $event['Event']['published'] == 0 ? 'warning' : '',
        'type' => 'custom',
        'function' => function (array $event) {
            if (!$event['Event']['published']) {
                $string = '<span class="label label-important label-padding">' . __('No') . '</span>';
                if (!empty($event['Event']['publish_timestamp'])) {
                    $string .= __(' (last published at %s)', $this->Time->time($event['Event']['publish_timestamp']));
                }
                return $string;
            } else {
                return sprintf(
                    '<span class="label label-success label-padding">%s</span> %s',
                    __('Yes'),
                    empty($event['Event']['publish_timestamp']) ? __('N/A') : $this->Time->time($event['Event']['publish_timestamp'])
                );
            }
        }
    ],
];

$tableRandomValue = Cake\Utility\Security::randomString(8);
$listTableOptions = [
    'id' => "single-view-table-{$tableRandomValue}",
    'hover' => false,
    'fluid' => true,
    'tableClass' => ['event-metadata', 'mb-0'],
    'keyClass' => ['event-metadata-key-cell'],
    'elementsRootPath' => '/genericElements/SingleViews/Fields/'
];
$listTable = $this->Bootstrap->listTable($listTableOptions, [
    'item' => $entity,
    'fields' => $fields
]);

// $eventInfo = $this->Bootstrap->node('div', [
//     'id' => 'event-info',
//     'class' => ['py-2 px-1', 'fw-light fs-7'],
// ], h($event['Event']['info']));
$eventInfo = '';
$content = $eventInfo . $listTable;

echo $this->Bootstrap->card([
    'bodyHTML' => $content,
    'bodyClass' => 'p-0',
    'class' => ['shadow-md'],
]);
?>

<style>
    .event-metadata .event-metadata-key-cell {
        min-width: 6em;
    }
</style>