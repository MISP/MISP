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
    if (!empty($onClick)) {
        $params = '';
        foreach ($onClick['params'] as $param) {
            if (!empty($params)) {
                $params .= ', ';
            }
            if ($param === 'this') {
                $params .= $param;
            } else {
                $params .= "'" . h($param) . "'";
            }
        }
        $a .= sprintf(' onClick="%s(%s)"', $onClick['function'], $params);
    }
    if (!empty($download)) {
        $download = 'download="' . h($download) . '"';
    } else {
        $download = '';
    }

    echo sprintf('<li %s %s><a %s %s>%s</a></li>', $element_id, $class, $a, $download, h($text));
?>
