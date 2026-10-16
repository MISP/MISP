<?php
// Overmind events index: the last change, relative.
App::uses('EventCardTool', 'Tools/EventOverview');
$timestamp = (int)($row['Event']['timestamp'] ?? 0);
printf(
    '<span title="%s">%s</span>',
    h(__('Last change %s', $this->EventIndex->utc($timestamp))),
    h(EventCardTool::ago($timestamp, time()))
);
