<?php
$serverId    = (int)($server['Server']['id'] ?? 0);
$eventId     = h($data['Event']['id'] ?? '');
$isPublished = !empty($data['Event']['published']);
$pullUrl     = $baseurl . '/servers/pull/' . $serverId . '/' . $eventId;
$postLinkId  = 'preview-fetch-postlink-' . $eventId;

$confirmBody = __('This will fetch the event from the remote instance and save it on your instance.');

$actions = [
    [
        'url' => '#',
        'icon' => 'fas fa-arrow-circle-down',
        'label' => __('Fetch this event'),
        'success' => $isPublished,
        'warning' => !$isPublished,
        'onclick' => 'event.preventDefault(); previewFetchEvent();',
    ],
];

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);

// Hidden secure POST trigger — CakePHP generates the CSRF token here.
echo $this->Form->postLink('', $pullUrl, [
    'id' => $postLinkId,
    'class' => 'd-none',
    'escape' => false,
]);
?>

<script>
function previewFetchEvent() {
    var body =
        '<div class="d-flex align-items-start gap-3">'
        + '<i class="fas fa-arrow-circle-down fa-2x mt-1 text-primary"></i>'
        + '<p class="mb-0 text-muted small">' + <?= json_encode($confirmBody) ?> + '</p>'
        + '</div>'
        <?php if (!$isPublished): ?>
        + '<div class="alert alert-warning d-flex align-items-center gap-2 py-2 mt-3 mb-0">'
        + '<i class="fas fa-triangle-exclamation flex-shrink-0"></i>'
        + '<small>' + <?= json_encode(__('This event is not published on the remote end.')) ?> + '</small>'
        + '</div>'
        <?php endif; ?>
        ;

    showConfirmModal({
        title:        <?= json_encode(__('Fetch this event')) ?>,
        body:         body,
        confirmLabel: <?= json_encode(__('Fetch this event')) ?>,
        confirmClass: <?= $isPublished ? "'btn-primary'" : "'btn-warning'" ?>,
        cancelLabel:  <?= json_encode(__('Cancel')) ?>,
        onConfirm:    function () {
            var trigger = document.getElementById(<?= json_encode($postLinkId) ?>);
            if (trigger) { trigger.click(); }
        }
    });
}
</script>
