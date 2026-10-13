<?php
/**
 * Every source's verdict, with what it based it on.
 *
 * The raw classification is shown beside the reading rather than
 * instead of it. A reader who disagrees with how `suspicious` was read
 * needs to see the word the service actually sent, and a page that
 * only showed the interpretation would be asking to be trusted about
 * the one thing on it that moves a number.
 *
 * @var array $data
 */
$readingLabel = function ($reading) {
    if ($reading === 'threat') {
        return __('points at threat');
    }
    if ($reading === 'benign') {
        return __('points away');
    }
    return __('no opinion');
};
?>
<div class="vp-rf vp-rf-rep">
    <?php if ($data['split']): ?>
        <p class="vp-rf-note vp-rf-warn"><?= h(sprintf(
            __('The sources disagree: %1$s point at a threat and'
                . ' %2$s point away.'),
            $data['threat'],
            $data['benign']
        )) ?></p>
    <?php endif; ?>

    <?php foreach ($data['verdicts'] as $verdict): ?>
        <?php
        $mark = $verdict['reading'] === 'threat'
            ? 'mal'
            : ($verdict['reading'] === 'benign' ? 'ben' : 'unknown');
        ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <span class="vp-rw-verdict vp-rw-v-<?= h($mark) ?>"><?php
                    echo h($verdict['classification'] !== null
                        ? $verdict['classification']
                        : ($verdict['score'] !== null
                            ? sprintf('%d%%', (int)$verdict['score'])
                            : __('listed')));
                ?></span>
                <span class="vp-rf-dim"><?=
                    h($readingLabel($verdict['reading'])) ?></span>
                <span class="vp-rf-name font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $verdict['module'])
                    ) ?></span>
                <span class="vp-rf-dim font-monospace"><?=
                    h((string)$verdict['template']) ?></span>
                <?php if ($verdict['link'] !== null): ?>
                    <a class="vp-rf-link"
                       href="<?= h($verdict['link']) ?>"
                       rel="noreferrer noopener"
                       target="_blank"><?= h(__('source')) ?></a>
                <?php endif; ?>
            </div>
            <?php if (!empty($verdict['whitelisted'])
                || !empty($verdict['riot'])): ?>
                <div class="vp-rf-sub"><?= h(!empty($verdict['riot'])
                    ? __('listed as a common service')
                    : __('whitelisted by the source')) ?></div>
            <?php endif; ?>
            <?php if (!empty($verdict['detail'])): ?>
                <dl class="vp-rf-pairs">
                    <?php foreach ($verdict['detail']
                        as $relation => $values): ?>
                        <dt><?= h($relation) ?></dt>
                        <dd><?= h(implode(', ', $values)) ?></dd>
                    <?php endforeach; ?>
                </dl>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
