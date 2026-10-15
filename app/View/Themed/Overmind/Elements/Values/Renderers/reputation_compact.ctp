<?php
/**
 * What the reputation services said, in a word.
 *
 * **The colour is the reading and not the word.** `riot` is a benign
 * statement with no benign word in it and a confidence score is a
 * number; colouring on the vocabulary would leave both grey. The
 * reading came from `prepare()`, which is the same function the ledger
 * scores with, so the green here and the negative points there cannot
 * disagree.
 *
 * **A split is drawn rather than resolved.** Two services disagreeing
 * is a state a reader acts on differently from either word alone, and
 * a compact widget that showed only the newest would hide it.
 *
 * @var array $data
 */
$headline = $data['headline'];
$reading = $headline === null ? null : $headline['reading'];
$mark = $reading === 'threat'
    ? 'mal'
    : ($reading === 'benign' ? 'ben' : 'unknown');
?>
<div class="vp-rw-in vp-rw-rep">
    <?php if ($headline === null): ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('no verdict')) ?></div>
    <?php else: ?>
        <div class="vp-rw-verdict vp-rw-v-<?= h($mark) ?>"><?php
            if ($headline['classification'] !== null) {
                echo h($headline['classification']);
            } elseif ($headline['score'] !== null) {
                printf('%d%%', (int)$headline['score']);
            } elseif (!empty($headline['riot'])) {
                echo h(__('known service'));
            } else {
                echo h(__('listed'));
            }
        ?></div>
        <div class="vp-rw-sub font-monospace"><?=
            $this->element('Values/Renderers/source_cell',
                array('sources' => $headline['module'])
            ) ?></div>
        <?php if ($headline['score'] !== null
            && $headline['classification'] !== null): ?>
            <div class="vp-rw-note"><?= h(sprintf(
                __('%s%% confidence'),
                (int)$headline['score']
            )) ?></div>
        <?php endif; ?>
    <?php endif; ?>

    <?php if ($data['split']): ?>
        <div class="vp-rw-note vp-rw-split"><?= h(sprintf(
            __('%1$s against, %2$s for'),
            $data['threat'],
            $data['benign']
        )) ?></div>
    <?php elseif (count($data['verdicts']) > 1): ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('%s sources agree'),
            count($data['verdicts'])
        )) ?></div>
    <?php endif; ?>
</div>
