<?php
/*
 * The All / My organisation tabs of Sightings/ajax/advanced.ctp, which also
 * owns the delete buttons' behaviour.
 */
$types = [__('Sighting'), __('False positive'), __('Expiration')];
$typeStyles = [
    ['success', 'fas fa-thumbs-up'],
    ['danger', 'fas fa-thumbs-down'],
    ['warning', 'fas fa-clock'],
];

// The org association only carries the name; the field links by id.
foreach ($sightings as &$item) {
    $item['Organisation']['id'] = $item['Sighting']['org_id'];
}
unset($item);

$Acl = $this->Acl;
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $sightings,
            'skip_pagination' => true,
            'primary_id_path' => 'Sighting.id',
            'fields' => [
                [
                    'name' => __('Date'),
                    'element' => 'datetime',
                    'data_path' => 'Sighting.date_sighting',
                ],
                [
                    'name' => __('Organisation'),
                    'element' => 'organisation',
                    'data_path' => 'Organisation',
                ],
                [
                    'name' => __('Type'),
                    'element' => 'custom',
                    'function' => function ($row) use ($types, $typeStyles) {
                        $type = (int)$row['Sighting']['type'];
                        list($tone, $icon) = $typeStyles[$type] ?? ['secondary', 'fas fa-question'];
                        return sprintf(
                            '<span class="badge rounded-pill text-bg-%s"><i class="%s me-1"></i>%s</span>',
                            $tone,
                            $icon,
                            h($types[$type] ?? $type)
                        );
                    },
                ],
                [
                    'name' => __('Source'),
                    'data_path' => 'Sighting.source',
                ],
                [
                    'name' => __('Event'),
                    'element' => 'event',
                    'data_path' => 'Sighting.event_id',
                    'url' => $baseurl . '/events/view2/%id%',
                ],
                [
                    'name' => __('Attribute'),
                    'element' => 'custom',
                    'function' => function ($row) {
                        return '<span class="font-monospace text-muted">#' . h($row['Sighting']['attribute_id']) . '</span>';
                    },
                ],
                [
                    'name' => '',
                    'element' => 'custom',
                    'display_in' => ['table'],
                    'function' => function ($row) use ($Acl, $rawId) {
                        if (!$Acl->canDeleteSighting($row)) {
                            return '';
                        }
                        return sprintf(
                            '<button type="button" class="btn btn-sm btn-outline-danger" data-sighting-delete="%s" data-raw-id="%s" title="%s" aria-label="%s"><i class="fas fa-trash-alt"></i></button>',
                            h($row['Sighting']['id']),
                            h($rawId),
                            __('Delete sighting'),
                            __('Delete sighting')
                        );
                    },
                ],
            ],
        ],
    ],
]);
