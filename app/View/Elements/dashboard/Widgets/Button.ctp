<?php
/**
 * Button renderer (dashboard v2).
 *
 * Renders a single link-styled button that fills the widget body — a
 * shortcut primitive used by ButtonWidget. Handler return shape:
 *
 *   $data = [
 *     'url'  => '/relative/path' or 'https://<same-host>/...' (required),
 *     'text' => 'button label'                                 (required),
 *   ];
 *
 * Both fields are user-controlled (widget config). The URL is gated by
 * the same _isSafeDashboardUrl contract SimpleList / Index use; unsafe
 * or missing URLs degrade to an inert "(Invalid URL)" tile so the
 * misconfiguration is visible in the dashboard rather than silently
 * navigating off-host. Text is h()-escaped.
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "Button renderer".
 */
$url  = isset($data['url'])  ? (string)$data['url']  : '';
$text = isset($data['text']) ? (string)$data['text'] : '';

$baseurl = (string)Configure::read('MISP.baseurl');

$isSafeUrl = function ($url) use ($baseurl) {
    if (!is_string($url) || $url === '') return false;
    if ($url[0] === '/' && (!isset($url[1]) || $url[1] !== '/')) return true;
    if ($baseurl === '') return false;
    $baseHost = parse_url($baseurl, PHP_URL_HOST);
    $host     = parse_url($url, PHP_URL_HOST);
    return $baseHost && $host && strcasecmp($baseHost, $host) === 0;
};

if (!$isSafeUrl($url)) {
    echo '<div class="misp-button-shell">';
    echo '<span class="misp-button misp-button--invalid" aria-disabled="true">'
        . h($text !== '' ? $text : __('(Invalid URL)'))
        . '</span>';
    echo '</div>';
    return;
}

// Empty text falls back to the URL itself so the button still reads
// as an actionable shortcut rather than a blank rectangle.
$label = $text !== '' ? $text : $url;

echo '<div class="misp-button-shell">';
printf(
    '<a class="misp-button" href="%s">%s</a>',
    h($url),
    h($label)
);
echo '</div>';
