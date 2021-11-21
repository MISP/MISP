<?php
$data = Hash::get($row, $field['data_path']);
$linkTitle = isset($field['link_title_path']) ? h(Hash::get($row, $field['link_title_path'])) : null;
$url = is_callable($field['url']) ? $field['url']($row) : $field['url'];
if ($url[0] === '/') {
    $url = $baseurl . $url;
}
echo "<a href=\"$url\"";
if ($linkTitle) {
    echo " title=\"$linkTitle\"";
}
echo '>' . h($data) . '</a>';
