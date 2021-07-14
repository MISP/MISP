<?php
    $url = Router::url(null, true);
    $matches = [];
    if (preg_match('/\/page:([0-9]+)/i', $url, $matches)) {
        $current_page = intval($matches[1]);
    } else {
        $current_page = 1;
        $url .= '/page:1';
    }
    $prev = false;
    if ($current_page > 1) {
        $prev = preg_replace('/\/page:[0-9]+/i', '/page:' . ($current_page - 1), $url);
    }
    $next = preg_replace('/\/page:[0-9]+/i', '/page:' . ($current_page + 1), $url);
    if ($prev) {
        $prev = sprintf(
            '<li class="prev"><a href="%s" rel="prev">« previous</a></li>',
            h($prev)
        );
    } else {
        $prev = '<li class="prev disabled"><span>« previous</span></li>';
    }
    $next = sprintf(
        '<li class="next"><a href="%s" rel="next">next »</a></li>',
        h($next)
    );
    echo sprintf(
        '<div class="pagination"><ul>%s%s</ul></div>',
        $prev,
        $next
    );
?>
