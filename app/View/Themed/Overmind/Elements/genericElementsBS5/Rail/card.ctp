<?php
/**
 * One rail card, built by a Lib/Tools/RailCards producer.
 *
 *   $card  array        see RailCard
 *   $tab   string|null  the tab it sits on; a link to that tab is not drawn.
 *                       A lazy card is fetched once for every tab it sits on,
 *                       so the page drops that link once it lands.
 *
 * The body is the element named after the card's shape.
 */
$tab = $tab ?? null;
$link = $this->RailCard->headerLink($card, $tab);
$state = null;
if ($card['shape'] === 'status') {
    $state = in_array($card['state'], RailCardHelper::TONES, true) ? $card['state'] : 'muted';
}
?>
<section class="card shadow-sm mb-3 rcard-card rcard-shape-<?= h($card['shape']) ?>"
    aria-label="<?= h($card['title']) ?>" data-rail-card="<?= h($card['id']) ?>">
    <div class="rcard-head p-3 border-bottom">
        <div class="rcard-tile rounded-2<?= $this->RailCard->toneClass($state, 'rcard-tile-') ?>">
            <?= $this->RailCard->icon($card['icon']) ?>
        </div>
        <div class="rcard-title fw-bold lh-1"><?= h($card['title']) ?></div>
        <?php if ($link): ?>
            <?= $this->RailCard->link(
                $link['href'],
                'rcard-head-link',
                h($link['label']) . ' <i class="fas fa-chevron-right" aria-hidden="true"></i>',
                null,
                null,
                ['data-hide-on-own-tab' => '']
            ) ?>
        <?php endif; ?>
    </div>
    <div class="rcard-body p-3">
        <?php if ($this->RailCard->isEmpty($card)): ?>
            <div class="rcard-empty">
                <?= $this->RailCard->icon($card['icon'], 'rcard-empty-icon') ?>
                <p class="rcard-empty-text"><?= h($card['empty'] ?? '') ?></p>
            </div>
        <?php else: ?>
            <?= $this->element('genericElementsBS5/Rail/' . $card['shape'], [
                'card' => $card,
                'tab' => $tab,
            ]) ?>
        <?php endif; ?>
        <?php if (!empty($card['note'])): ?>
            <div class="rcard-note">
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <span><?= h($card['note']) ?></span>
            </div>
        <?php endif; ?>
    </div>
</section>
