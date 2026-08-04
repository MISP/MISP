<?php
if (!empty($element_id)) {
    $li = ' id="li' . $element_id . '"';
} else {
    if (!empty($url)) {
        $urlparts = explode('/', $url);
        $li = ' id="li' . h(end($urlparts)) . '"';
    } else {
        $li = '';
    }
}
if (!empty($class)) {
    $li .= ' class="' . h($class) . '"';
}
$post_link = $this->Form->postLink(
    $text,
    $url,
    null,
    empty($message) ? null : $message
);
echo "<li$li>$post_link</li>";
