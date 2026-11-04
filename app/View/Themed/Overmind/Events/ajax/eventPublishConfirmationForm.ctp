<?php
/*
 * Confirmation for the four publication actions of an event. EventsController
 * renders this same view from publish(), alert(), unpublish() and
 * publishSightings(), so everything that differs between them lives in the
 * table below rather than in a chain of ifs around the markup.
 *
 * publish() and alert() are one action to the user — publish, and optionally
 * email the subscribers — so they render the same modal with a switch that is
 * off by default. They stay two controller actions, and the CSRF token is bound
 * to the URL a POST lands on (FormHelper hashes the form's action,
 * SecurityComponent hashes request->here()), so the switch cannot rewrite the
 * action: the modal carries a second, hidden form for the other action and the
 * script submits whichever one matches the switch.
 *
 * Set by the controller:
 *   $id       int     event id (the POST target carries it, so no hidden field)
 *   $type     string  'publish' | 'alert' | 'unpublish' | 'publishSightings'
 *   $servers  array   Event::listServerToPush(), publish() and alert() only
 */

$servers = $servers ?? [];
$uid = 'evt-publish-' . dechex(mt_rand());

$actions = [
    'publish' => [
        'accent' => 'success',
        'title' => __('Publish event'),
        'description' => __('Is this event complete and ready to be shared?'),
        'message' => __('Is this event complete and ready to be shared?'),
        'submitLabel' => __('Publish'),
        'submitIcon' => 'upload',
    ],
    'unpublish' => [
        'accent' => 'warning',
        'title' => __('Unpublish event'),
        'description' => __('Clears the published state of the event.'),
        'message' => __('Unpublish this event?'),
        'warning' => __('The event stays on this instance, and instances that already pulled it are not affected.'),
        'submitLabel' => __('Unpublish'),
        'submitIcon' => 'eye-slash',
    ],
    'publishSightings' => [
        'accent' => 'sighting',
        'title' => __('Publish sightings'),
        'description' => __('Synchronises the sightings attached to this event.'),
        'message' => __('Publish and synchronise every sighting attached to this event?'),
        'submitLabel' => __('Publish sightings'),
        'submitIcon' => 'eye',
    ],
];
/* Same modal as publish, reached when the notifying action is the one asked for
 * — the switch then starts on. */
$actions['alert'] = [
    'submitLabel' => __('Publish & notify'),
    'submitIcon' => 'paper-plane',
] + $actions['publish'];

$action = $actions[$type] ?? $actions['publish'];

/* The two publishing actions are the pair the switch toggles between. */
$notifyPair = ['publish' => 'alert', 'alert' => 'publish'];
$hasNotifyOption = isset($notifyPair[$type]);
$notifyOn = $type === 'alert';

$bodyHtml = '';
if ($hasNotifyOption) {
    if (!empty($servers)) {
        $bodyHtml .= $this->element('Events/publish_targets', [
            'servers' => $servers,
            'accent' => $action['accent'],
        ]);
    }
    $bodyHtml .= $this->element('Events/publish_notify_option', [
        'uid' => $uid,
        'checked' => $notifyOn,
        'accent' => $action['accent'],
    ]);
}

/* The switch renames the button, so the button's label is markup the script can
 * rewrite rather than a plain string. */
$submitLabelHtml = null;
if ($hasNotifyOption) {
    $submitLabelHtml = sprintf(
        '<i id="%1$s-submit-icon" class="fas fa-%2$s me-1"></i><span id="%1$s-submit-label">%3$s</span>',
        h($uid),
        h($action['submitIcon']),
        h($action['submitLabel'])
    );
}

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Event',
    'url' => $baseurl . '/events/' . $type . '/' . $id,
    'hiddenField' => false,
    'eyebrow' => __('Publication'),
    'accent' => $action['accent'],
    'title' => $action['title'],
    'description' => $action['description'],
    'message' => $action['message'],
    'warning' => $action['warning'] ?? null,
    'bodyHtml' => $bodyHtml,
    'submitLabel' => $action['submitLabel'],
    'submitIcon' => $action['submitIcon'],
    'submitLabelHtml' => $submitLabelHtml,
    'icon' => 'fas fa-' . ($hasNotifyOption ? 'upload' : $action['submitIcon']),
    'meta' => [['label' => __('Event'), 'id' => $id]],
]);

if ($hasNotifyOption):
    echo $this->Form->create('Event', [
        'id' => 'PromptFormNotify',
        'url' => $baseurl . '/events/' . $notifyPair[$type] . '/' . $id,
        'class' => 'd-none',
    ]);
    echo $this->Form->end();
?>
<script>
(function () {
    var box = document.getElementById('<?= $uid ?>-notify');
    var form = document.getElementById('PromptForm');
    var twin = document.getElementById('PromptFormNotify');
    if (!box || !form || !twin) {
        return;
    }

    var label = document.getElementById('<?= $uid ?>-submit-label');
    var icon = document.getElementById('<?= $uid ?>-submit-icon');
    var NOTIFY_ON = <?= $notifyOn ? 'true' : 'false' ?>;
    var COPY = <?= json_encode([
        'on' => ['label' => __('Publish & notify'), 'icon' => 'fas fa-paper-plane me-1'],
        'off' => ['label' => __('Publish'), 'icon' => 'fas fa-upload me-1'],
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    // Say on the button what the switch just decided.
    function sync() {
        var copy = box.checked ? COPY.on : COPY.off;
        if (label) {
            label.textContent = copy.label;
        }
        if (icon) {
            icon.className = copy.icon;
        }
    }

    box.addEventListener('change', sync);

    // Submitting the twin when the switch no longer matches the action this form
    // was rendered for — see the header comment on why the action cannot change.
    form.addEventListener('submit', function (event) {
        if (box.checked !== NOTIFY_ON) {
            event.preventDefault();
            twin.submit();
        }
    });

    sync();
})();
</script>
<?php endif; ?>
