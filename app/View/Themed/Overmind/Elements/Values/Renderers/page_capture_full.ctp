<?php
/**
 * Each capture, its archived copy and whatever text was extracted.
 *
 * **The image is still a link rather than an inlined picture**, and
 * for the same reason the compact form gave: a screenshot URL points
 * at a third party, and a page that fetched it on open would tell that
 * third party somebody is looking at this value — which is exactly the
 * disclosure the enrichment gate exists to put behind a decision. A
 * link is that decision.
 *
 * The extracted text is the half a disinformation reader came for:
 * what a page said is often the finding, and it survives the page
 * being taken down.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-cap">
    <?php foreach ($data['captures'] as $capture): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($capture['url'] !== null): ?>
                    <a class="vp-rf-key font-monospace"
                       href="<?= h($capture['url']) ?>"
                       rel="noreferrer noopener"
                       target="_blank"><?= h($capture['url']) ?></a>
                <?php elseif ($capture['domain'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($capture['domain']) ?></span>
                <?php endif; ?>
                <?php if ($capture['captured'] !== null): ?>
                    <span class="vp-rf-dim"><?= h(date('Y-m-d',
                        $capture['captured'])) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $capture['module'])
                    ) ?></span>
            </div>
            <?php if ($capture['attachment'] !== null
                || !empty($capture['archive'])): ?>
                <div class="vp-rf-sub"><?= h(sprintf(
                    __('Archived as %s'),
                    $capture['attachment'] !== null
                        ? $capture['attachment']
                        : implode(', ', $capture['archive'])
                )) ?></div>
            <?php endif; ?>
            <?php if ($capture['text'] !== null): ?>
                <details class="vp-rf-raw">
                    <summary><?= h(__('Extracted text')) ?></summary>
                    <pre><?= h($capture['text']) ?></pre>
                </details>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
