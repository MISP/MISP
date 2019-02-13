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
        $a = 'href="#"';
    } else if (strpos($url, '://') !== null) {
        $a = 'href="' . h($url) . '"';
    } else {
        $a = 'href="' . $baseurl . h($url) . '"';
    }
    if (!empty($class)) {
        $class = 'class="' . h($class) . '"';
    } else {
        $class = '';
    }
    $post_link = $this->Form->postLink(
        __($text),
        $a,
        null,
        empty($message) ? $message : null
    );
    echo sprintf('<li %s %s>%s</li>', $element_id, $class, $post_link);
?>
