<?php
/*
 * An event in an index whose rows come from any event: its id and icon,
 * which open the event, and on hover its peek (Events/peek), which
 * mispOvermind.js fetches from /events/peek/<id> the first time.
 *
 * @var int|string $id the event's id
 * @var string|null $info its title, for the link's label
 */
$id = (int)($id ?? 0);
if ($id === 0) {
    return;
}
$info = (string)($info ?? '');

// The peek's org tile, chips and markings, once per page (or AJAX fragment).
if (empty($this->viewVars['_eventPeekAssets'])) {
    $this->viewVars['_eventPeekAssets'] = true;
    echo $this->element('genericElements/assetLoader', ['css' => ['org-tile', 'events-index-cards']]);
}
?>
<a href="<?= h($baseurl . '/events/view/' . $id) ?>" class="ev-ref"
   data-ev-peek="<?= $id ?>" data-ev-peek-url="<?= h($baseurl . '/events/peek/' . $id) ?>"
   aria-label="<?= h($info === '' ? __('Event #%s', $id) : __('Event #%s: %s', $id, $info)) ?>">
    <span class="ev-ref-id"><small>#</small><?= $id ?></span>
    <span class="ev-peek"><i class="misp-icon misp-icon-event misp-simple"></i></span>
</a>
