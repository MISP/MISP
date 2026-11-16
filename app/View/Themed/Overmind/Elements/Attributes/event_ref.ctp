<?php
/**
 * An event named by its id: the id opens the event, the event icon beside
 * it carries the title and facts in a popover (Attributes/event_peek).
 *
 * @var array $event id, info, and whatever event_peek reads
 */
$id = (int)($event['id'] ?? 0);
if ($id === 0) {
    return;
}
?>
<span class="ev-ref"><a class="ev-ref-id" href="<?= h($baseurl . '/events/view/' . $id) ?>"
   title="<?= h($event['info'] ?? '') ?>">#<?= $id ?></a><?= $this->element('Attributes/event_peek', array('event' => $event)) ?></span>
