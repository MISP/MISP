<?php

$requester = $delegationRequest['RequesterOrg']['name'] ?? __('another organisation');
$eventId = $delegationRequest['Event']['id'] ?? ($delegationRequest['EventDelegation']['event_id'] ?? null);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'EventDelegation',
    'url' => $this->request->here(false),
    'hiddenField' => false,
    'eyebrow' => __('Delegation'),
    'accent' => 'event',
    'title' => __('Accept delegation'),
    'description' => __('Transfers the event to your organisation.'),
    'message' => __('Accept the request by %s to take ownership of this event?', $requester),
    'warning' => __('Your organisation becomes the owner and is credited as the creator from then on.'),
    'submitLabel' => __('Accept'),
    'submitIcon' => 'handshake',
    'meta' => $eventId === null ? [] : [['label' => __('Event'), 'id' => $eventId]],
]);
