<?php
// Overmind events index: the event date.
$date = $row['Event']['date'] ?? null;
if (empty($date)) {
    return;
}
echo h(date('j M Y', strtotime($date)));
