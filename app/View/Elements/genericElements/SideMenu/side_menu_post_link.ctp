<?php
    $a = '';
    if (!empty($element_id)) {
        $element_id = 'id="li' . $element_id . '"';
    } else {
        if (!empty($url)) {
            $urlparts = explode('/', $url);
            $element_id = 'id="li' . h(end($urlparts)) . '"';
        } else {
            $element_id = '';
        }
    }
    if (empty($url)) {
        $a = '';
    } else if (strpos($url, '://') !== null) {
        $a = h($url);
    } else {
        $a = $baseurl . h($url);
    }
    if (!empty($class)) {
        $class = 'class="' . h($class) . '"';
    } else {
        $class = '';
    }
    $post_link = $this->Form->postLink(
        __('%s', $text),
        $url,
        null,
        empty($message) ? null : $message
    );
    echo sprintf('<li %s %s>%s</li>', $element_id, $class, $post_link);
?>
