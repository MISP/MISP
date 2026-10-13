<?php
/**
 * Which event a drawn object comes from, in extended view.
 *
 * @var int $eventId
 * @var bool $link link to the event (default true)
 * @var string $text what follows the icon (default "#<id>")
 * @var bool $corner sit on a tile's edge
 */
$eventId = (int)$eventId;
$text = $text ?? '#' . $eventId;
$class = 'eov-ev' . (!empty($corner) ? ' is-corner' : '');
$title = sprintf(__('From event #%s'), $eventId);
$inner = '<i class="fas fa-link" aria-hidden="true"></i>' . h($text);
if (isset($link) && !$link) {
    printf('<span class="%s" title="%s">%s</span>', $class, h($title), $inner);
    return;
}
printf(
    '<a class="%s" href="%s" title="%s">%s</a>',
    $class,
    h($this->viewVars['baseurl'] . '/events/view2/' . $eventId),
    h($title),
    $inner
);
