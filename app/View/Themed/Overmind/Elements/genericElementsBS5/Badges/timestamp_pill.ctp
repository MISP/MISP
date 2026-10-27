<?php
/*
 * A record's dates: when it was created, last modified and last published,
 * each an icon and a value that copies the full datetime; the label is in the
 * tooltip. Creation reads as a calendar date (Oct. 10, 2026), the other two
 * as an age (5 min ago). Any of them may be missing.
 *
 *   $record  array  the record; each date is the first non-empty field of
 *                   its `keys` below, a unix timestamp or a datetime string
 *
 * A detail page does not echo this itself: it sets `headerTimestamps` to its
 * record and headerSection puts the dates after the identity pill.
 */
$dates = [
    'created' => [
        'keys' => ['date', 'created', 'date_created'],
        'icon' => 'fas fa-calendar-plus',
        'label' => __('Created'),
    ],
    'modified' => [
        'keys' => ['modified', 'date_modified', 'timestamp'],
        'icon' => 'fas fa-pen',
        'label' => __('Modified'),
    ],
    'published' => [
        'keys' => ['publish_timestamp'],
        'icon' => 'fas fa-paper-plane',
        'label' => __('Published'),
    ],
];

$toTimestamp = function ($value) {
    if (is_numeric($value)) {
        return (int)$value;
    }
    $time = is_string($value) ? strtotime($value) : false;
    return $time === false ? 0 : $time;
};

$calendarDate = function ($time) {
    $month = date('M', $time);
    return ($month === 'May' ? $month : $month . '.') . date(' j, Y', $time);
};

$age = function ($time) {
    $seconds = time() - $time;
    if ($seconds < 60) {
        return __('just now');
    }
    $minutes = intdiv($seconds, 60);
    if ($minutes < 60) {
        return __('%s min ago', $minutes);
    }
    $hours = intdiv($minutes, 60);
    if ($hours < 24) {
        return __('%s h ago', $hours);
    }
    $days = intdiv($hours, 24);
    if ($days < 30) {
        return __('%s d ago', $days);
    }
    if ($days < 365) {
        return __('%s mo ago', intdiv($days, 30));
    }
    return __('%s yr ago', intdiv($days, 365));
};

$copyButton = function ($icon, $label, $time, $text) {
    $absolute = date('Y-m-d H:i:s', $time);
    return sprintf(
        '<button type="button" class="focus-ring rounded-1 d-inline-flex align-items-center gap-1'
        . ' border-0 bg-transparent text-body p-0 mb-0" style="cursor:copy;"'
        . ' title="%s" aria-label="%s" data-copy-value="%s" data-copy-msg="%s"'
        . ' onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">'
        . '<i class="%s opacity-50" aria-hidden="true"></i><time datetime="%s">%s</time></button>',
        h($label . ' ' . $absolute . "\n" . __('Click to copy')),
        h($label . ' ' . $absolute),
        h($absolute),
        h(__('Datetime copied to clipboard')),
        h($icon),
        h(date('c', $time)),
        h($text)
    );
};

$record = $record ?? [];
$times = [];
$parts = [];
foreach ($dates as $role => $date) {
    if ($role === 'published' && array_key_exists('published', $record) && empty($record['published'])) {
        continue;
    }
    $time = 0;
    foreach ($date['keys'] as $key) {
        $time = $toTimestamp($record[$key] ?? null);
        if ($time > 0) {
            break;
        }
    }
    // A record never edited since its creation has nothing more to say.
    if ($time <= 0 || ($role === 'modified' && $time === ($times['created'] ?? null))) {
        continue;
    }
    $times[$role] = $time;
    $parts[] = $copyButton(
        $date['icon'],
        $date['label'],
        $time,
        $role === 'created' ? $calendarDate($time) : $age($time)
    );
}
if (empty($parts)) {
    return;
}
?>
<span class="d-inline-flex align-items-center flex-wrap column-gap-3 row-gap-1">
    <?= implode('', $parts) ?>
</span>
