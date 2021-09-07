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

Publish alerts are configured to include summaries only, for the detailed contents, please view the event in MISP directly.

==============================================
You receive this e-mail because the e-mail address <?= $user['email'] ?> is set
to receive <?= $contactAlert ? 'contact' : 'publish' ?> alerts on the MISP instance at <?= $baseurl ?>.

If you would like to unsubscribe from receiving such alert e-mails, simply
disable <?= $contactAlert ? 'contact' : 'publish' ?> alerts via <?= $baseurl ?>/users/edit
==============================================
