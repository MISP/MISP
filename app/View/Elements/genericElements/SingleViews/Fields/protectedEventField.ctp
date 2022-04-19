<?php
    $keys = Hash::extract($data, $field['path']);
    $event = Hash::extract($data, $field['event_path']);
    if ($event['protected']) {
        echo sprintf(
            '<span class="fas fa-lock"></span> %s %s %s <br>',
            __('Event is in protected mode. (Limited distribution)'),
            !$field['owner'] ? '' : sprintf(
                '<br><a href="%s" class="modal-open" title="%s"><i class="fas fa-unlock"></i> %s</a>',
                sprintf(
                    '%s/events/unprotect/%s',
                    $baseurl,
                    h($event['id'])
                ),
                __('Revert the event to an unprotected mode event. It will no longer be restricted to be shared by instances that have their signing key listed in the event\'s signing key list. Signing and validation of the event will be disabled.'),
                empty($field['text']) ? __('Switch to unprotected mode') : h($field['text'])
            ),
            !$field['owner'] ? '' : sprintf(
                '<br><a href="%s" class="modal-open"><i class="fas fa-key"></i> %s</a>',
                sprintf(
                    "%s/CryptographicKeys/add/Event/%s",
                    $baseurl,
                    h($event['id'])
                ),
                empty($field['text']) ? __('Add signing key') : h($field['text'])
            )
        );
        $foundInstanceKey = false;
        foreach ($keys as $key) {
            $isInstanceKey = $key['fingerprint'] === $field['instanceFingerprint'];
            if ($isInstanceKey) {
                $foundInstanceKey = true;
            }
            echo sprintf(
                '%s<span class="bold">%s</span> (%s) <a href="%s" class="modal-open" title="%s"><i class="fas fa-search"></i></a> %s<br>',
                !$isInstanceKey ? '' : sprintf(
                    '<i class="fas fa-home blue" title="%s"></i>&nbsp;',
                    __('This is the instance signing key. When synchronising the instance, this will be the key used to validate the event.')
                ),
                h($key['type']),
                empty($key['fingerprint']) ? '#' . h($key['id']) : h($key['fingerprint']),
                sprintf(
                    "%s/cryptographicKeys/view/%s",
                    $baseurl,
                    h($key['id'])
                ),
                __('Inspect key'),
                !$field['owner'] ? '' : sprintf(
                    '<a href="%s/cryptographicKeys/delete/%s" class="modal-open" title="%s"><i class="fas fa-trash"></i></a>',
                    $baseurl,
                    h($key['id']),
                    __('Detach key from the event. This key will no longer be used to sign and validate this event.')
                )
            );
        }
        if (!$foundInstanceKey) {
            echo sprintf(
                '<span class="red bold">%s: %s</span> <i class="fas fa-info-circle" title="%s"></i>',
                __('Warning'),
                __('Instance key not attached to the event. Further synchronisation not supported.'),
                __("In protected mode, the current instance's signing key is used to sign and on the receiving side validate the event. If the current signing key is not attached to the event, MISP by default will not propagate the event further.\n\nIf you feel this is an error, contact the event's creator to add your instance's signing key to the event's signing key list.\n\nWarning: This restriction does NOT constitue a release control, merely a tamper protection for the recipients.")
            );
        }
    } else {
        echo sprintf(
            '<span class="fas fa-unlock"></span> <span>%s</span> %s<br>',
            __('Event is in unprotected mode.'),
            !$field['owner'] ? '' : sprintf(
                '<br><a href="%s" class="modal-open" title="%s"><i class="fas fa-lock"></i> %s</a>',
                sprintf(
                    "%s/events/protect/%s",
                    $baseurl,
                    h($event['id'])
                ),
                __('Convert the event to a protected event. Event signing keys can then be attached to the event, allowing instances to sign the event prior to synchronising it. This allows the recipient instances to validate updates to the event in the future to be only issued by organisations that can sign the event using the listed keys.'),
                empty($field['text']) ? __('Switch to protected mode') : h($field['text'])
            )
        );
    }
