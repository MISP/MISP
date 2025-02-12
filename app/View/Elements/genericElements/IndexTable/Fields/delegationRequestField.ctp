<?php
    if ($isSiteAdmin) {
        $message = sprintf(
            __('%s has requested that %s take over this event.'),
            h($field['delegationRequest']['RequesterOrg']['name']),
            h($field['delegationRequest']['Org']['name'])
        );
    } else if ($me['org_id'] === $field['delegationRequest']['EventDelegation']['org_id']) {
        $message = sprintf(
            __('%s has requested that you take over this event.'),
            h($field['delegationRequest']['RequesterOrg']['name'])
        );
    } else {
        $message = sprintf(
            __('You have requested that %s take over this event.'),
            h($field['delegationRequest']['Org']['name'])
        );
    }

echo sprintf(
    '%s (%s)',
    $message,
    sprintf (
        '<a href="#" style="color:white;" onClick="genericPopup(%s);">%s</a>',
        sprintf(
            "'%s/eventDelegations/view/%s', '#confirmation_box'",
            $baseurl,
            h($field['delegationRequest']['EventDelegation']['id'])
        ),
        __('View request details')
    )
);
