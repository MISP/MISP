<?php
/**
 * The two cases over time, as a rail card.
 *
 * The weights on one axis, because when they crossed is the fact a
 * snapshot cannot carry — and the note below says when, and what
 * changed that day.
 *
 * Drawn bare: three gridlines, two lines, no ticks. At this size an
 * axis would cost more room than it returns, and the reader is looking
 * for a crossing rather than a value. Tooltips still carry the numbers.
 *
 * @var array $valueIntelligence
 * @var string $chartId   Namespaced by the caller
 * @var string $cardTitle What the two lines are, for this value
 */
$verdict = $valueIntelligence['verdict'];
$curves = $verdict['curves'] ?? array();

if (!empty($curves)) {
    $buckets = count($curves[0]['data']);
    $labels = array();
    for ($i = 0; $i < $buckets; $i++) {
        $daysAgo = $buckets > 1
            ? (int)round((($buckets - 1 - $i) * 90) / ($buckets - 1))
            : 0;
        $labels[] = $daysAgo === 0 ? __('today') : '-' . $daysAgo . 'd';
    }

    $datasets = array();
    foreach ($curves as $curve) {
        $datasets[] = array(
            'label' => $curve['label'],
            'data' => array_values($curve['data']),
            'borderColor' => $curve['colour'],
            'backgroundColor' => $curve['colour'],
            'borderWidth' => 2,
            'pointRadius' => 0,
            'pointHoverRadius' => 3,
            'tension' => 0.3,
            'fill' => false,
        );
    }

    $chartConfig = array(
        'type' => 'line',
        'data' => array('labels' => $labels, 'datasets' => $datasets),
        'options' => array(
            'responsive' => true,
            'maintainAspectRatio' => false,
            'interaction' => array(
                'mode' => 'index',
                'intersect' => false,
            ),
            'layout' => array(
                'padding' => array('top' => 2, 'bottom' => 2),
            ),
            'scales' => array(
                'x' => array(
                    'display' => false,
                    'grid' => array('display' => false),
                ),
                'y' => array(
                    'beginAtZero' => true,
                    'border' => array('display' => false),
                    'grid' => array(
                        'color' => 'var(--bs-border-color)',
                        'drawTicks' => false,
                    ),
                    'ticks' => array('display' => false),
                    'grace' => '8%',
                ),
            ),
            'plugins' => array(
                'legend' => array('display' => false),
            ),
        ),
    );
}
?>
<?php if (!empty($curves)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside">

        <div class="vp-aside-head">
            <i class="fas fa-chart-line"
               style="color: var(--correlation);"></i>
            <span class="vp-aside-title">
                <?= h($cardTitle ?? __('The two cases over time')) ?>
            </span>
            <span class="vp-aside-meta">
                <?= h($verdict['curves_span'] ?? __('90 days')) ?>
            </span>
        </div>

        <div class="p-3">

            <?= $this->element('Values/View/value_chart', array(
                'chartId' => $chartId,
                'chartConfig' => $chartConfig,
                'chartHeight' => 96,
                'chartLabel' => sprintf(
                    __('%s over the last 90 days'),
                    implode(', ', array_column($curves, 'label'))
                ),
            )) ?>

            <div class="vp-curve-legend">
                <?php foreach ($curves as $curve): ?>
                    <span>
                        <span class="vp-curve-swatch"
                              style="--vp-curve-color: <?=
                                  h($curve['colour']) ?>;"></span>
                        <?= h($curve['label']) ?>
                    </span>
                <?php endforeach; ?>
            </div>

            <?php if (!empty($verdict['curves_note'])): ?>
                <p class="vp-aside-note">
                    <?= h($verdict['curves_note']) ?>
                </p>
            <?php endif; ?>

        </div>

    </div>
<?php endif; ?>
