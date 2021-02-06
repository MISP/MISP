<?php
if (!isset($oldPublishTimestamp)) {
    $oldPublishTimestamp = null;
}

if (!isset($contactAlert)) {
    $contactAlert = false;
}

if ($hideDetails) { // Used when GnuPG.bodyonlyencrypted is enabled and e-mail cannot be send in encrypted form
    $eventUrl = $baseurl . "/events/view/" . $event['Event']['id'];
    echo __("A new or modified event was just published on %s", $eventUrl) . PHP_EOL . PHP_EOL;
    echo __("If you would like to unsubscribe from receiving such alert e-mails, simply\ndisable publish alerts via %s", $baseurl . '/users/edit');
    return;
}

$renderAttributes = function(array $attributes, $indent = '  ') use ($oldPublishTimestamp) {
    $appendlen = 20;
    foreach ($attributes as $attribute) {
        $ids = $attribute['to_ids'] ?  ' (IDS)' : '';

        // Defanging URLs (Not "links") emails domains/ips in notification emails
        $value = $attribute['value'];
        if ('url' === $attribute['type'] || 'uri' === $attribute['type']) {
            $value = str_ireplace("http", "hxxp", $value);
            $value = str_ireplace(".", "[.]", $value);
        } elseif (in_array($attribute['type'], ['email-src', 'email-dst', 'whois-registrant-email', 'dns-soa-email', 'email-reply-to'], true)) {
            $value = str_replace("@", "[at]", $value);
        } elseif (in_array($attribute['type'], ['hostname', 'domain', 'ip-src', 'ip-dst', 'domain|ip'], true)) {
            $value = str_replace(".", "[.]", $value);
        }

        $strRepeatCount = $appendlen - 2 - strlen($attribute['type']);
        $strRepeat = ($strRepeatCount > 0) ? str_repeat(' ', $strRepeatCount) : '';
        if (isset($oldPublishTimestamp) && isset($attribute['timestamp']) && $attribute['timestamp'] > $oldPublishTimestamp) {
            $line = '* ' . $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $value . $ids . " *\n";
        } else {
            $line = $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $value . $ids .  "\n";
        }

        if (!empty($attribute['AttributeTag'])) {
            $tags = [];
            foreach ($attribute['AttributeTag'] as $aT) {
                $tags[] = $aT['Tag']['name'];
            }
            $line .= '  - Tags: ' . implode(', ', $tags) . "\n";
        }
        echo $line;
    }
};

$renderObjects = function(array $objects) use ($renderAttributes, $oldPublishTimestamp) {
    foreach ($objects as $object) {
        $body = '';
        if (isset($oldPublishTimestamp) && isset($object['timestamp']) && $object['timestamp'] > $oldPublishTimestamp) {
            $body .= '* ';
        } else {
            $body .= '  ';
        }
        $body .= $object['name'] . '/' . $object['meta-category'] . "\n";
        if (!empty($object['Attribute'])) {
            $body .= $renderAttributes($object['Attribute'], '    ');
        }
        echo $body;
    }
};

$tags = [];
foreach ($event['EventTag'] as $tag) {
    $tags[] = $tag['Tag']['name'];
}
?>
==============================================
URL         : <?= $baseurl ?>/events/view/<?= $event['Event']['id'] . PHP_EOL ?>
Event ID    : <?= $event['Event']['id'] . PHP_EOL ?>
Date        : <?= $event['Event']['date'] . PHP_EOL ?>
<?php if (Configure::read('MISP.showorg')): ?>
Reported by : <?= $event['Orgc']['name'] . PHP_EOL ?>
Local owner of the event : <?= $event['Org']['name'] . PHP_EOL ?>
<?php endif; ?>
Distribution: <?= $distributionLevels[$event['Event']['distribution']] . PHP_EOL ?>
<?php if ($event['Event']['distribution'] == 4): ?>
Sharing Group: <?= $event['SharingGroup']['name'] . PHP_EOL ?>
<?php endif; ?>
Tags: <?= implode(", ", $tags) . PHP_EOL ?>
Threat Level: <?= $event['ThreatLevel']['name'] . PHP_EOL ?>
Analysis    : <?= $analysisLevels[$event['Event']['analysis']] . PHP_EOL ?>
Description : <?= $event['Event']['info'] . PHP_EOL ?>
<?php if (!empty($event['RelatedEvent'])): ?>
==============================================
Related to:
<?php 
foreach ($event['RelatedEvent'] as $relatedEvent) {
    echo $baseurl . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ') ' . "\n";
}
?>
==============================================
<?php endif; ?>

<?php if (!empty($event['Attribute'])): ?>
Attributes<?= isset($oldPublishTimestamp) ? " (* indicates a new or modified attribute since last update):\n" : ":\n" ?>
<?= $renderAttributes($event['Attribute']) ?>
<?php endif; ?>

<?php if (!empty($event['Object'])): ?>
Objects<?= isset($oldPublishTimestamp) ? " (* indicates a new or modified object since last update):\n" : ":\n" ?>
<?= $renderObjects($event['Object']) ?>
<?php endif; ?>

==============================================
You receive this e-mail because the e-mail address <?= $user['email'] ?> is set 
to receive <?= $contactAlert ? 'contact' : 'publish' ?> alerts on the MISP instance at <?= $baseurl ?>.

If you would like to unsubscribe from receiving such alert e-mails, simply
disable <?= $contactAlert ? 'contact' : 'publish' ?> alerts via <?= $baseurl ?>/users/edit
==============================================
