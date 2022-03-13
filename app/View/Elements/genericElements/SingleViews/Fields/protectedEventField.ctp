<?php
    $keys = Hash::extract($data, $field['path']);
    $event = Hash::extract($data, $field['event_path']);
    if ($event['protected']) {
        echo sprintf(
            '<span class="fas fa-lock green"></span> %s %s %s <br />',
            __('Event is in protected mode.'),
            !$field['owner'] ? '' : sprintf(
                '<br /><a href="#" onClick="%s"><i class="fas fa-unlock"></i> %s</a>',
                sprintf(
                    "openGenericModal('%s/events/unprotect/%s');",
                    $baseurl,
                    h($event['id'])
                ),
                empty($field['text']) ? __('Switch to unprotected mode') : h($field['text'])
            ),
            !$field['owner'] ? '' : sprintf(
                '<br /><a href="#" onClick="%s"><i class="fas fa-key"></i>%s</a>',
                sprintf(
                    "openGenericModal('%s/CryptographicKeys/add/%s/%s');",
                    $baseurl,
                    h('Event'),
                    h($event['id'])
                ),
                empty($field['text']) ? __('Add signing key') : h($field['text'])
            )
        );
        foreach ($keys as $key) {
            echo sprintf(
                '<span class="bold">%s</span> (%s) <a href="#" onClick="%s" title="%s"><i class="fas fa-search"></i></a> %s<br />',
                h($key['type']),
                empty($key['fingerprint']) ? '#' . h($key['id']) : h($key['fingerprint']),
                sprintf(
                    "openGenericModal('%s/cryptographicKeys/view/%s');",
                    $baseurl,
                    h($key['id'])
                ),
                __('Inspect key'),
                !$field['owner'] ? '' : sprintf(
                    '<a href="#" onClick="openGenericModal(\'%s/cryptographicKeys/delete/%s\')" title="%s"><i class="fas fa-trash"></i></a>',
                    $baseurl,
                    h($key['id']),
                    __('Revoke key')
                )
            );
        }
    } else {
        echo sprintf(
            '<span class="red fas fa-unlock"></span> <span class="red">%s</span> %s<br />',
            __('Event is in unprotected mode.'),
            !$field['owner'] ? '' : sprintf(
                '<br /><a href="#" onClick="%s"><i class="fas fa-lock"></i> %s</a>',
                sprintf(
                    "openGenericModal('%s/events/protect/%s');",
                    $baseurl,
                    h($event['id'])
                ),
                empty($field['text']) ? __('Switch to protected mode') : h($field['text'])
            )
        );
    }
    //echo ;
