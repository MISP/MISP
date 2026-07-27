<?php
$this->set('headerTitle', __('Registrations'));
$this->set('headerDescription', __('Pending self-registration requests sent to this instance. Process a request to create the user, or discard it.'));

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Inbox.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Inbox.id',
        'data_path' => 'Inbox.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Email'),
        'sort' => 'Inbox.data.email',
        'data_path' => 'Inbox.data.email, Inbox.comment',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'element' => 'custom',
        'function' => function ($row, $viewMode = 'table') {
            $name = $row['Inbox']['data']['org_name'] ?? '';
            $uuid = $row['Inbox']['data']['org_uuid'] ?? '';
            if ($name === '' && $uuid === '') {
                return '<span class="text-body-secondary">&mdash;</span>';
            }
            // Card view lays name + uuid out on one line; table view stacks them.
            $wrapClass = $viewMode === 'card'
                ? 'd-flex flex-row flex-wrap align-items-center gap-2'
                : 'd-flex flex-column gap-1';
            $out = '<div class="' . $wrapClass . '">';
            if ($name !== '') {
                $out .= '<span>' . h($name) . '</span>';
            }
            if ($uuid !== '') {
                $out .= '<span class="badge text-bg-light border font-monospace align-self-start">' . h($uuid) . '</span>';
            }
            $out .= '</div>';
            return $out;
        },
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('PGP'),
        'data_path' => 'Inbox.data.pgp',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Requested role'),
        'element' => 'custom',
        // Role-style chips
        'function' => function ($row, $viewMode = 'table') {
            $chip = function ($color, $icon, $label) {
                return sprintf(
                    '<span class="d-inline-flex align-items-center gap-2">'
                        . '<span class="d-inline-flex align-items-center justify-content-center rounded-2 text-bg-%s text-white flex-shrink-0" style="width:1.5rem; height:1.5rem;">'
                        . '<i class="fas %s" style="font-size:.8rem;"></i></span>'
                        . '<span class="fw-semibold text-body">%s</span></span>',
                    $color,
                    $icon,
                    h($label)
                );
            };
            $d = $row['Inbox']['data'] ?? [];
            if (empty($d['custom_perms'])) {
                return $chip('secondary', 'fa-user', __('Default'));
            }
            $perms = [
                'perm_publish' => ['success', 'fa-upload', __('Publish')],
                'perm_sync'    => ['warning', 'fa-arrows-rotate', __('Sync')],
                'perm_admin'   => ['primary', 'fa-user-shield', __('Org admin')],
            ];
            $chips = [];
            foreach ($perms as $k => $meta) {
                if (!empty($d[$k])) {
                    $chips[] = $chip($meta[0], $meta[1], $meta[2]);
                }
            }
            if (empty($chips)) {
                $chips[] = $chip('dark', 'fa-user-pen', __('Custom'));
            }
            // Card view lays the chips out on one line; table view stacks them.
            $wrapClass = $viewMode === 'card'
                ? 'd-inline-flex flex-row flex-wrap align-items-center gap-2'
                : 'd-inline-flex flex-column gap-1';
            return '<div class="' . $wrapClass . '">' . implode('', $chips) . '</div>';
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('IP / User agent'),
        'element' => 'custom',
        'function' => function ($row, $viewMode = 'table') {
            $ip = $row['Inbox']['ip'] ?? '';
            $ua = $row['Inbox']['user_agent'] ?? '';
            if ($ip === '' && $ua === '') {
                return '<span class="text-body-secondary">&mdash;</span>';
            }
            $isCard = $viewMode === 'card';
            $out = '<div class="d-flex flex-column gap-1">';
            if ($ip !== '') {
                $out .= '<span class="badge text-bg-light border font-monospace align-self-start">' . h($ip) . '</span>';
            }
            if ($ua !== '') {
                if ($isCard) {
                    // Card view has room: show the full, wrapping user agent.
                    $out .= '<span class="text-muted small text-break">' . h($ua) . '</span>';
                } else {
                    // Table view truncates but exposes the full value on hover.
                    $out .= '<span class="text-muted small text-truncate d-inline-block" style="max-width: 280px;" title="' . h($ua) . '">' . h($ua) . '</span>';
                }
            }
            $out .= '</div>';
            return $out;
        },
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Time'),
        'sort' => 'Inbox.timestamp',
        'data_path' => 'Inbox.timestamp',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Inbox.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Process'),
                'icon' => 'check',
                'url' => $baseurl . '/users/acceptRegistrations/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Discard'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'size' => 'sm',
                'url' => $baseurl . '/users/discardRegistrations/%id%',
            ],
        ],
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Inbox.id',
            'filter_bar' => [
                'action' => 'registrations',
                'accept' => '/acceptRegistrations',
                'discard' => '/discardRegistrations',
                'children' => [
                    [
                        'type' => 'search',
                        'mode' => 'legacy',
                        'name' => 'value',
                        'placeholder' => __('Search email, org, IP, comment…'),
                    ],
                ],
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/users',
]);
?>
