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
 * Both fields are user-controlled (widget config) — `url` is the only
 * fully attacker-supplied URL anywhere in the dashboard, so it is gated
 * by DashboardURLValidator (DD-03), the same gate SimpleList / Index and
 * the other list renderers use. Unsafe or missing URLs degrade to an
 * inert "(Invalid URL)" tile so the misconfiguration is visible in the
 * dashboard rather than silently executing a script or navigating
 * off-host. Text is h()-escaped.
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "Button renderer".
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

$url  = isset($data['url'])  ? (string)$data['url']  : '';
$text = isset($data['text']) ? (string)$data['text'] : '';

$safeUrl = DashboardURLValidator::validate($url);

if ($safeUrl === null) {
    echo '<div class="misp-button-shell">';
    echo '<span class="misp-button misp-button--invalid" aria-disabled="true">'
        . h($text !== '' ? $text : __('(Invalid URL)'))
        . '</span>';
    echo '</div>';
    return;
}

// Empty text falls back to the URL itself so the button still reads
// as an actionable shortcut rather than a blank rectangle.
$label = $text !== '' ? $text : $safeUrl;

echo '<div class="misp-button-shell">';
printf(
    '<a class="misp-button" href="%s">%s</a>',
    h($safeUrl),
    h($label)
);
echo '</div>';
