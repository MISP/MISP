<?php
$taxiiServerId = h($data['TaxiiServer']['id']);
$taxiiServerEnabled = !empty($data['TaxiiServer']['enabled']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/taxiiServers/edit/$taxiiServerId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/taxiiServers/edit/$taxiiServerId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Server')
    ];
    if ($taxiiServerEnabled) {
        $actions[] = [
            'url' => "$baseurl/taxiiServers/push/$taxiiServerId",
            'onclick' => "event.preventDefault(); openModal('$baseurl/taxiiServers/push/$taxiiServerId', 'sm');",
            'icon' => 'fas fa-arrow-circle-up',
            'label' => __('Push data to TAXII server')
        ];
    }
    $actions[] = [
        'url' => "$baseurl/taxiiServers/delete/$taxiiServerId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/taxiiServers/deleteSelection/$taxiiServerId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Server'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
