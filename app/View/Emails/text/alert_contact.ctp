Hello,

Someone wants to get in touch with you concerning a MISP event.

You can reach them at <?= $requestor['User']['email'] ?>
<?php if (!empty($requestor['User']['gpgkey'])): ?>
Their PGP key is added as attachment to this email.
<?php endif; ?>
<?php if (!empty($requestor['User']['certif_public'])): ?>
Their Public certificate is added as attachment to this email.
<?php endif; ?>

They wrote the following message:
<?= $message ?>


The event is the following:
<?php
if ($hideDetails) {
    echo $baseurl . ' /events/view/' . $event['Event']['id'];
} else {
    require __DIR__ . '/alert.ctp'; // include event details
}
