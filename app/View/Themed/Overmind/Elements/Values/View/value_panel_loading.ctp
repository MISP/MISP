<?php
/**
 * The chrome of the panels an endpoint is about to deliver, drawn
 * before it answers.
 *
 * **Why the page draws them at all.** Every panel here is lazily
 * loaded, and the container each one lands in used to hold nothing but
 * a centred spinner — ~84px whatever was coming. So a tab opened as a
 * column of anonymous boxes and grew to its real height panel by panel
 * as the fetches came back: a reader could not tell which section was
 * which, could not reach the one they came for, and watched the page
 * move under the cursor for as long as the slowest endpoint took.
 *
 * **The layout, the shimmer and the row split are not this file's.**
 * `genericElementsBS5/Layout/ajax_card_skeleton` owns them and any page
 * in the theme can use it. What is left here is the only part that is
 * this page's: the chrome. A panel skeleton wears `value_panel_header`
 * itself, so the glyph tile, the title baseline and the 36px they sit
 * on do not move when the fetch lands, and a rail skeleton wears the
 * `vp-aside-head` strip the rail cards wear.
 *
 * **A skeleton names only what the endpoint will certainly render.**
 * The Assessment rail is four cards or five depending on the lean,
 * and each one's title with it — a title guessed wrong is worse than no
 * title, so those entries pass `title => null` and get a shimmer where
 * the words will be. Only the rail's lighter chrome takes a null:
 * `value_panel_header` escapes and prints the title it is given, and
 * teaching it to hold markup for one caller would change the element
 * twenty-odd panels share.
 *
 * @var array $panels One descriptor per card:
 *                    `title`  string, or null on an `aside`
 *                    `icon`   Font Awesome class or misp-icon triplet
 *                    `color`  CSS colour for the glyph tile
 *                    `lines`  how many body lines to shimmer, default 3
 *                    `shape`  `panel` (default) or `aside`, the lighter
 *                             chrome the rail cards wear
 *                    `col`    Bootstrap lg width; when any entry
 *                             carries one the set is laid out as a row,
 *                             which is what the endpoints that own
 *                             their own split need
 */
$panels = isset($panels) ? $panels : array();

$cards = array();
foreach ($panels as $panel) {
    $title = isset($panel['title']) ? $panel['title'] : null;
    $icon = isset($panel['icon']) ? $panel['icon'] : null;
    $color = isset($panel['color'])
        ? $panel['color']
        : 'var(--bs-secondary-color)';
    $aside = isset($panel['shape']) && $panel['shape'] === 'aside';

    if ($aside) {
        ob_start();
        ?>
        <div class="vp-aside-head">
            <?php if ($icon === null): ?>
                <span class="skeleton-bar skeleton-square"></span>
            <?php elseif (strpos($icon, 'misp-icon') === 0): ?>
                <span class="<?= h($icon) ?>"
                      style="color: <?= h($color) ?>;"></span>
            <?php else: ?>
                <i class="<?= h($icon) ?>"
                   style="color: <?= h($color) ?>;"></i>
            <?php endif; ?>
            <?php if ($title === null): ?>
                <span class="vp-aside-title">
                    <span class="skeleton-bar" style="width: 7rem;"></span>
                </span>
            <?php else: ?>
                <span class="vp-aside-title"><?= h($title) ?></span>
            <?php endif; ?>
        </div>
        <?php
        $head = ob_get_clean();
    } else {
        /*
         * The subtitle carries the panel's headline number, which
         * nothing here knows — a shimmer holds the line instead of a
         * word repeated down the page.
         */
        $head = $this->element('Values/View/value_panel_header', array(
            'panelTitle' => (string)$title,
            'panelIcon' => $icon,
            'panelColor' => $color,
            'panelSub' => '<span class="skeleton-bar"'
                . ' style="width: 11rem;"></span>',
        ));
    }

    $cards[] = array(
        'head' => $head,
        'lines' => isset($panel['lines']) ? (int)$panel['lines'] : 3,
        'cardClass' => 'vp-panel' . ($aside ? ' vp-aside' : ''),
        'cardStyle' => '--vp-panel-color: ' . $color . ';',
    ) + (isset($panel['col']) ? array('col' => $panel['col']) : array());
}

echo $this->element('genericElementsBS5/Layout/ajax_card_skeleton',
    array('cards' => $cards));
