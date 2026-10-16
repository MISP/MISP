<?php
/**
 * The warninglist band.
 *
 * A band inside the argument card rather than a card of its own,
 * because on the values that have one the hit is not a separate
 * finding — it is one of the sides talking, and often the loudest.
 *
 * It is the signal on this page most routinely read backwards, so the
 * band names the category and then says in prose what that category
 * does and does not claim. `known` means shared infrastructure, which
 * argues nothing about the reports; `false_positive` means reports
 * about the value are usually collateral. Neither means "the reporting
 * organisations were wrong", and the note is where that is said.
 *
 * How the value matched is the list's `type` in MISP's own vocabulary —
 * `cidr`, `string`, `substring`, `regex` — rendered as the phrase that
 * reads naturally in the sentence.
 *
 * @var array $warninglist name, version, category, matched, type, note
 */
$matchPhrases = array(
    'cidr' => __('matched by CIDR'),
    'string' => __('matched exactly'),
    'substring' => __('matched as a substring'),
    'regex' => __('matched by pattern'),
);
$matchPhrase = $matchPhrases[$warninglist['type'] ?? 'string']
    ?? __('matched');
?>
<div class="vp-vc-warninglist">
    <i class="fas fa-list-check"></i>
    <div class="vp-vc-warninglist-body">
        <div>
            <strong><?= h($warninglist['name']) ?></strong>
            <span class="font-monospace">
                v<?= h($warninglist['version']) ?>
            </span>
            ·
            <?= h(__('category')) ?>
            <strong><?= h($warninglist['category']) ?></strong>
            ·
            <?= h($matchPhrase) ?>
            <code><?= h($warninglist['matched']) ?></code>
        </div>
        <div class="vp-vc-warninglist-note">
            <?= h($warninglist['note']) ?>
        </div>
    </div>
    <a href="<?= $baseurl ?>/warninglists/index"
       class="vp-vc-warninglist-action">
        <?= __('View list') ?>
    </a>
</div>
