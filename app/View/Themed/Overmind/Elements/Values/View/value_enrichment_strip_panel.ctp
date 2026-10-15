<?php
/**
 * One strip cell's panel, kept in a `<template>` until the cell opens
 * (js/tile-drawer.js): the full drawing of what the cell summarises, and
 * the modules it was drawn from, each a way to its own pane on the
 * Enrichment tab. The panel only reads; running a module stays there.
 *
 * @var array $widget One slot's `widget`, from `ValueRendererTool::drawFor`
 * @var string $name The shape as a heading
 * @var string $valueB64
 * @var string $baseurl
 */
$close = __('Close (Esc)');
?>
<template data-td-panel>
    <div class="td-head">
        <div class="td-titles">
            <div class="td-kicker"><b><?= h(__('Enrichment')) ?></b> — <?=
                h($widget['description']) ?></div>
            <h3 class="td-title" tabindex="-1"><?= h($name) ?></h3>
        </div>
        <div data-td-stepper></div>
        <button type="button" class="td-close" data-td-close
                aria-label="<?= h($close) ?>" title="<?= h($close) ?>">
            <i class="fas fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <div class="td-body">
        <div class="td-draw">
            <?= $this->element($widget['full'], array(
                'data' => $widget['data'],
            )) ?>
        </div>
        <aside class="td-aside" aria-label="<?=
            h(__('Where this comes from')) ?>">
            <section>
                <h4><?= h(__('Answered by')) ?></h4>
                <ul class="vp-eb-srcs">
                    <?php foreach ($widget['sources'] as $source): ?>
                        <?php
                        $module = $source['module'];
                        $made = array();
                        foreach ($source['templates'] as $template => $count) {
                            $made[] = h(number_format($count))
                                . ' <span class="font-monospace">'
                                . h($template) . '</span>';
                        }
                        if ($source['ran_at'] !== null) {
                            $age = $this->element(
                                'Values/View/value_enrichment_age',
                                array('askedAge' => time()
                                    - (int)$source['ran_at'])
                            );
                            $made[] = sprintf(h(__('asked %s')), $age);
                        }
                        $href = $baseurl . '/values/view/' . $valueB64
                            . '?module=' . rawurlencode($module)
                            . '#tab-enrichment';
                        $total = number_format($source['total']);
                        $drawn = number_format($source['shown']);
                        $kept = number_format($source['kept']);
                        ?>
                        <li>
                            <a class="vp-eb-src font-monospace"
                               href="<?= h($href) ?>"
                               data-vp-eb-open="<?= h($module) ?>"
                               title="<?= h(sprintf(
                                __('Open %s on the Enrichment tab'),
                                $module
                               )) ?>"><?= h($module) ?></a>
                            <span class="vp-eb-src-made"><?=
                                implode(' · ', $made) ?></span>
                            <?php if ($source['capped']): ?>
                                <span class="vp-eb-src-cut"
                                      title="<?= h(sprintf(__(
                                        'The module returned %1$s results'
                                        . ' and this draws the first %2$s.'
                                        . ' Its pane on the Enrichment tab'
                                        . ' can show %3$s of them.'
                                      ), $total, $drawn, $kept)) ?>"><?=
                                    h(sprintf(
                                        __('%1$s of %2$s drawn'),
                                        $drawn,
                                        $total
                                    )) ?></span>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </section>
            <p><?= h(__('A module\'s rows, and asking it again, are on its'
                . ' pane of the Enrichment tab.')) ?></p>
        </aside>
    </div>
</template>
