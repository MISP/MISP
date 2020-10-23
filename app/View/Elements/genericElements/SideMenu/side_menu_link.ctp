<?php
$active = $this->get('menuItem');
if (empty($element_id) && !empty($url)) {
    $urlparts = explode('/', $url);
    $element_id = end($urlparts);
}
if (isset($element_id) && $active === $element_id) {
    if (empty($class)) {
        $class = 'active';
    } else {
        $class .= ' active';
    }
}
if (!empty($element_id)) {
    $li = ' id="li' . h($element_id) . '"';
} else {
    $li = '';
}
if (!empty($class)) {
    $li .= ' class="' . h(trim($class)) . '"';
}
if (empty($url)) {
    $a = 'href="#"';
} else if (strpos($url, '://') !== false) {
    $a = 'href="' . h($url) . '"';
} else {
    $a = 'href="' . $this->get('baseurl') . h($url) . '"';
}
if (!empty($title)) {
    $a .= ' title="' . h($title) . '"';
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
    $a .= sprintf(' onclick="%s(%s)"', $onClick['function'], $params);
}
if (!empty($download)) {
    $a .= ' download="' . h($download) . '"';
}
echo "<li$li><a $a>" . h($text) . '</a></li>';
