<?php
/**
 * The two things a reader can ask of the assessment, neither of which
 * is built yet.
 *
 * **They used to sit in the hero**, top right, at the same visual
 * weight as the lean badge and the signal-strength gauge — two disabled
 * buttons holding the most valuable corner of the card and doing
 * nothing with it. Four objects competed there and the eye had no
 * entry point. They are the small print of the card, so they are in
 * the small print: the provenance strip already runs a quarter empty
 * on every value, and *where the number came from* and *what you can
 * do with it* are the same kind of fact.
 *
 * They stay drawn rather than hidden, which is the opposite of D23's
 * call for the editor — and for the opposite reason. D23 removed an
 * inert *control*: a state an analyst could reach for and believe they
 * had set. These set nothing and claim nothing, and both say in a
 * tooltip which phase brings them. If that judgement goes the other
 * way, this element is the one file to delete.
 *
 * @var string|null $valueB64
 */
?>
<div class="vp-verdict-meta-actions">
    <button type="button" class="vp-vc-hero-action disabled"
            disabled title="<?= h(__(
                'Not available yet: this page does not write to the'
                . ' database.'
            )) ?>">
        <i class="fas fa-rotate"></i>
        <?= __('Recompute') ?>
    </button>
    <?php /*
     * Its own reason, because it is not a write.
     * `review-2026-09-13.md` §C4: both actions carried the no-writes
     * tooltip, which *Recompute* earns and this one does not — a
     * reader hovering it was told the wrong thing about why it is
     * unavailable.
     */ ?>
    <button type="button"
            class="vp-vc-hero-action vp-vc-hero-action-mono disabled"
            disabled title="<?= h(__(
                'Not available yet: the assessment has no API'
                . ' representation.'
            )) ?>">
        <?= __('view as JSON') ?>
    </button>
</div>
