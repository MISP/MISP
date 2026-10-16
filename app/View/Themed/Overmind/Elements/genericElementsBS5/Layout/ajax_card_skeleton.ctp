<?php
/**
 * The shape of a lazily-loaded card, drawn before its endpoint answers.
 *
 * `view_layout` gives every ajax card a centred spinner by default,
 * which says *something is coming* and nothing else: the container is
 * ~84px tall whatever will land in it, so a tab of them opens as a
 * column of anonymous boxes and grows card by card as the fetches
 * return. A reader cannot tell which section is which, cannot reach the
 * one they came for, and watches the page move under the cursor until
 * the slowest endpoint answers.
 *
 * Pass this as a card's `placeholder` and the page draws the shape it
 * asked for instead — real card chrome, the section's own name, and a
 * shimmer where the contents will be:
 *
 * ```php
 * $card['placeholder'] = array(
 *     'element' => 'genericElementsBS5/Layout/ajax_card_skeleton',
 *     'params' => array('cards' => array(
 *         array('title' => __('Attributes'), 'icon' => 'fas fa-tag',
 *               'lines' => 8),
 *     )),
 * );
 * ```
 *
 * **One entry per card the endpoint will draw, not per endpoint.** An
 * action that renders three cards declares three, in the order it draws
 * them, and they stack; an action that owns an internal split gives its
 * entries a `col` and they lay out as a row.
 *
 * **Guess `lines` low.** The card that lands is then taller than its
 * skeleton, so the page grows rather than shrinking, and a section never
 * slides up out from under a reader who has already scrolled to it.
 *
 * **Name only what will certainly be there.** A card whose title depends
 * on the data passes `title => null` and gets a shimmer where the words
 * go, which is honest where a guessed name would not be.
 *
 * A page with card chrome of its own — its own header element, its own
 * card classes — keeps it by passing `head` and `cardClass` rather than
 * by forking this file. `Values/View/value_panel_loading` is the worked
 * example: it hands over `value_panel_header`'s own output so the glyph
 * tile and the title baseline do not move when the fetch lands.
 *
 * @var array $cards One descriptor per card:
 *                   `title`     string|null, shimmered when null
 *                   `icon`      Font Awesome class or misp-icon triplet
 *                   `color`     CSS colour for the icon
 *                   `lines`     body lines to shimmer, default 3
 *                   `col`       Bootstrap lg width; when any entry
 *                               carries one the set becomes a row
 *                   `cardClass` extra classes on the card
 *                   `cardStyle` extra inline style on the card
 *                   `head`      pre-rendered head markup, replacing the
 *                               default strip below
 */
$cards = isset($cards) ? $cards : array();

/*
 * Ragged on purpose, and deterministic. A stack of equal bars reads as a
 * table someone drew; uneven lengths read as text that has not arrived.
 * Cycled from a fixed list rather than randomised, so two renders of one
 * page are the same page.
 */
$skeletonWidths = array(88, 71, 94, 62, 83, 76);

$skeletonSplit = false;
foreach ($cards as $entry) {
    if (!empty($entry['col'])) {
        $skeletonSplit = true;
        break;
    }
}

/**
 * The default head: an icon, a name, and a shimmer where the card's
 * headline number will be. Bootstrap utilities only — a page that wants
 * its own chrome passes `head` instead.
 *
 * @param array $entry
 * @return string
 */
$skeletonHead = function (array $entry) {
    $title = isset($entry['title']) ? $entry['title'] : null;
    $icon = isset($entry['icon']) ? $entry['icon'] : null;
    $color = isset($entry['color']) ? $entry['color'] : null;
    ob_start();
    ?>
    <div class="p-3 border-bottom d-flex align-items-center gap-2">
        <?php if ($icon === null): ?>
            <span class="skeleton-bar skeleton-square"></span>
        <?php elseif (strpos($icon, 'misp-icon') === 0): ?>
            <span class="<?= h($icon) ?>"<?= $color === null ? ''
                : ' style="color: ' . h($color) . ';"' ?>></span>
        <?php else: ?>
            <i class="<?= h($icon) ?>"<?= $color === null ? ''
                : ' style="color: ' . h($color) . ';"' ?>></i>
        <?php endif; ?>
        <div class="me-auto">
            <div class="fw-bold lh-1">
                <?php if ($title === null): ?>
                    <span class="skeleton-bar" style="width: 8rem;"></span>
                <?php else: ?>
                    <?= h($title) ?>
                <?php endif; ?>
            </div>
            <div class="small mt-1">
                <span class="skeleton-bar" style="width: 11rem;"></span>
            </div>
        </div>
    </div>
    <?php
    return ob_get_clean();
};

/**
 * One card: the caller's chrome or the default, then the shimmer body.
 *
 * @param array $entry
 * @return void
 */
$skeletonCard = function (array $entry) use ($skeletonWidths, $skeletonHead) {
    $lines = isset($entry['lines']) ? (int)$entry['lines'] : 3;
    $extra = empty($entry['cardClass']) ? '' : ' ' . $entry['cardClass'];
    $style = empty($entry['cardStyle'])
        ? ''
        : ' style="' . h($entry['cardStyle']) . '"';
    ?>
    <div class="card shadow-sm mb-3 skeleton-card<?= h($extra) ?>"<?= $style ?>
         aria-busy="true">
        <?= isset($entry['head']) ? $entry['head'] : $skeletonHead($entry) ?>
        <div class="skeleton-body">
            <span class="visually-hidden"><?= __('Loading') ?></span>
            <?php for ($i = 0; $i < $lines; $i++): ?>
                <span class="skeleton-bar"
                      style="width: <?= (int)$skeletonWidths[
                          $i % count($skeletonWidths)] ?>%;"></span>
            <?php endfor; ?>
        </div>
    </div>
    <?php
};
?>
<?php if ($skeletonSplit): ?>
    <div class="row">
        <?php foreach ($cards as $entry): ?>
            <div class="col-lg-<?= (int)(isset($entry['col'])
                ? $entry['col'] : 12) ?>">
                <?php $skeletonCard($entry); ?>
            </div>
        <?php endforeach; ?>
    </div>
<?php else: ?>
    <?php foreach ($cards as $entry): ?>
        <?php $skeletonCard($entry); ?>
    <?php endforeach; ?>
<?php endif; ?>
