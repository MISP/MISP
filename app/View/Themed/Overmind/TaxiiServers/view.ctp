<?php
$server = $data['TaxiiServer'] ?? [];
$serverId = (int)($server['id'] ?? 0);

$this->set('headerIdentity', $server);
$this->set('headerTitle', $server['name'] ?? '');
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'TaxiiServers/View/taxiiServers_general',
            ],
            'right' => [
                'TaxiiServers/View/taxiiServers_actions',
            ],
        ],
        [
            'id' => 'collections',
            'title' => __('Collections'),
            'icon' => 'fas fa-folder',
            'description' => __('The collections advertised by the remote TAXII server.'),
            'left' => [
                ['ajax' => sprintf('%s/taxii_servers/collectionsIndex/%s', $baseurl, $serverId)],
            ],
        ],
        [
            'id' => 'objects',
            'title' => __('Objects in selected Collection'),
            'icon' => 'fas fa-cube',
            'description' => __('STIX objects retrieved from the remote TAXII collection.'),
            'left' => [
                ['ajax' => rtrim(sprintf('%s/taxii_servers/objectsIndex/%s/%s', $baseurl, $serverId, rawurlencode((string)($server['collection'] ?? ''))), '/')],
            ],
        ],
    ],
]);
