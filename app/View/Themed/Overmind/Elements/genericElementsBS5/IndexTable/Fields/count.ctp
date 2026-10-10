<?php
/*
 * count.ctp
 *
 * Expected:
 * $data_path => item.count'
 *
 * Optional:
 * $tally => true to count what $data_path extracts (e.g. 'members.{n}.id')
 *           instead of printing the value stored there
 */

$count = Hash::extract($row, $field['data_path']);

if (!empty($field['tally'])) {
    $count = [count($count)];
} elseif (empty($count)) {
    return;
}

$badge = $this->element(
    'genericElementsBS5/Badges/count',
    [
        'count' => $count[0],
    ]
);

// Optional link: when $field['url'] is set, wrap the badge in an anchor.
// Placeholders: $field['url_params_data_paths']
if (!empty($field['url'])) {
    $url = $field['url'];
    if (!empty($field['url_params_data_paths'])) {
        foreach ($field['url_params_data_paths'] as $placeholder => $path) {
            $url = str_replace('%' . $placeholder . '%', Hash::get($row, $path), $url);
        }
    }
    $badge = sprintf(
        '<a href="%s" class="text-decoration-none">%s</a>',
        h($url),
        $badge
    );
}

echo $badge;
?>