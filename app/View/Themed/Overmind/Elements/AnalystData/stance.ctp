<?php
/**
 * An opinion's score as a gauge centred on neutral, its stance and the score
 * (analyst-rail.css). Shared by the analyst data threads, the opinions index
 * and the targets an opinion is about.
 *
 * Parameters:
 *   score  int  0-100
 */
$v = max(0, min(100, (int)($score ?? 50)));
if ($v <= 20) {
    list($label, $tone) = [__('Strongly disagree'), 'neg'];
} elseif ($v <= 40) {
    list($label, $tone) = [__('Disagree'), 'neg'];
} elseif ($v <= 60) {
    list($label, $tone) = [__('Neutral'), 'mid'];
} elseif ($v <= 80) {
    list($label, $tone) = [__('Agree'), 'pos'];
} else {
    list($label, $tone) = [__('Strongly agree'), 'pos'];
}
if ($v === 50) {
    $mark = '<span class="adr-gauge-dot"></span>';
} else {
    $mark = sprintf(
        '<span class="adr-gauge-fill adr-gauge-%s" style="width:%d%%"></span>',
        $v > 50 ? 'left' : 'right',
        abs($v - 50)
    );
}
printf(
    '<div class="adr-stance adr-tone-%s" title="%s">'
    . '<span class="adr-gauge" aria-hidden="true"><span class="adr-gauge-mid"></span>%s</span>'
    . '<span class="adr-stance-label">%s</span><span class="adr-stance-score">%d</span></div>',
    $tone,
    h(__('%s, %s out of 100', $label, $v)),
    $mark,
    h($label),
    $v
);
