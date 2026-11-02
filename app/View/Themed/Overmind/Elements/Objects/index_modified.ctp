<?php
/**
 * When an object last changed, in the objects indexes: how long ago, or the
 * day once it is more than a year old.
 *
 * Parameters:
 *   object  array  the row's Object
 */
App::uses('CakeTime', 'Utility');

$ts = (int)$object['timestamp'];
$label = $ts < strtotime('-1 year')
    ? date('Y-m-d', $ts)
    : CakeTime::timeAgoInWords($ts, [
        'accuracy' => ['day' => 'day', 'week' => 'day', 'month' => 'week'],
    ]);
?>
<span class="oi-modified" title="<?= h(date('Y-m-d H:i:s', $ts)) ?>"><?= h($label) ?></span>
