<?php

$requester = $delegationRequest['RequesterOrg']['name'] ?? __('another organisation');
$eventId = $delegationRequest['Event']['id'] ?? ($delegationRequest['EventDelegation']['event_id'] ?? null);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'EventDelegation',
    'url' => $this->request->here(false),
    'hiddenField' => false,
    'eyebrow' => __('Delegation'),
    'accent' => 'danger',
    'title' => __('Discard delegation request'),
    'description' => __('Leaves the event where it is.'),
    'message' => __('Discard the request by %s to take ownership of this event?', $requester),
    'submitLabel' => __('Discard'),
    'submitIcon' => 'trash',
    'meta' => $eventId === null ? [] : [['label' => __('Event'), 'id' => $eventId]],
]);
