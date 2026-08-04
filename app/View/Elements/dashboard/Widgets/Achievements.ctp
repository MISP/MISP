<?php
/**
 * Achievements renderer (dashboard v2).
 *
 * Two-section badges list emitted by widgets that declare
 * `$render = 'Achievements'` (AchievementsWidget). Expected shape:
 *
 *   $data = [
 *     'unlocked' => [ { icon, title, help_page? }, ... ],
 *     'locked'   => [ { icon, title, help_page? }, ... ],
 *   ];
 *
 * Each badge: `icon` (image URL, displayed at 48×48); `title` (text);
 * `help_page` (optional external doc link, shown for locked badges
 * so users can learn how to unlock).
 *
 * Badge content is widget-author-controlled (defined in
 * AchievementsWidget::__construct), not user config — XSS-risk is
 * theoretical. Renderer is still defensive: image src goes through a
 * same-host/http(s) allowlist; external help links open in a new tab
 * with `rel="noopener noreferrer"` (v1 set `target="_blank"` without
 * `rel`, a security oversight not reproduced).
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "Achievements renderer".
 */
$unlocked = isset($data['unlocked']) ? (array)$data['unlocked'] : array();
$locked   = isset($data['locked'])   ? (array)$data['locked']   : array();

/**
 * Image src allowlist: relative paths starting with `/` (single
 * slash — rejects protocol-relative `//host`), or absolute URLs with
 * http(s) scheme. Rejects javascript:, data:, file:, etc.
 */
$isSafeImageSrc = function ($src) {
    if (!is_string($src) || $src === '') return false;
    if ($src[0] === '/' && (!isset($src[1]) || $src[1] !== '/')) return true;
    $scheme = parse_url($src, PHP_URL_SCHEME);
    return $scheme === 'http' || $scheme === 'https';
};

/** External help-link allowlist: http(s) only. */
$isSafeHelpLink = function ($url) {
    if (!is_string($url) || $url === '') return false;
    $scheme = parse_url($url, PHP_URL_SCHEME);
    return $scheme === 'http' || $scheme === 'https';
};

$renderSection = function ($heading, $items, $emptyMsg, $showHelp) use ($isSafeImageSrc, $isSafeHelpLink) {
    echo '<section class="misp-achievements-section">';
    echo '<h3 class="misp-achievements-heading">' . h($heading) . '</h3>';
    if (empty($items)) {
        echo '<p class="misp-achievements-empty">' . h($emptyMsg) . '</p>';
        echo '</section>';
        return;
    }
    echo '<ul class="misp-achievements-list">';
    foreach ($items as $item) {
        $icon  = isset($item['icon'])      ? (string)$item['icon']      : '';
        $title = isset($item['title'])     ? (string)$item['title']     : '';
        $help  = isset($item['help_page']) ? (string)$item['help_page'] : '';
        echo '<li class="misp-achievements-row">';
        if ($isSafeImageSrc($icon)) {
            printf(
                '<img class="misp-achievements-icon" src="%s" alt="" width="48" height="48">',
                h($icon)
            );
        } else {
            echo '<span class="misp-achievements-icon misp-achievements-icon--missing" aria-hidden="true"></span>';
        }
        echo '<div class="misp-achievements-text">';
        echo '<div class="misp-achievements-title">' . h($title) . '</div>';
        if ($showHelp && $isSafeHelpLink($help)) {
            printf(
                '<a class="misp-achievements-help" href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
                h($help),
                __('Read more')
            );
        }
        echo '</div>';
        echo '</li>';
    }
    echo '</ul>';
    echo '</section>';
};

$renderSection(
    __('Achievements unlocked'),
    $unlocked,
    __("No achievements yet — check the list below to get started!"),
    false
);

$renderSection(
    __('Next on your list'),
    $locked,
    __('Well done! You got them all.'),
    true
);
