<?php
/**
 * One Chart.js canvas, themed from CSS rather than from literals.
 *
 * Callers write colours as `var(--something)` in the config exactly as
 * they would in a stylesheet; `VP.chart` resolves them against the
 * canvas at init, so a chart picks up the same variables the rest of
 * the page does, and resolves them again when `data-misp-mode` flips —
 * the only way a canvas can follow a theme it cannot inherit.
 *
 * This element is the shape for a chart that is fully described by its
 * config. The Sightings overlay is not — it swaps datasets as the
 * reader changes range — so it drives `VP.chart` itself rather than
 * being handed a config here.
 *
 * Safe inside a lazily-injected fragment: `loadAjaxContainer` re-creates
 * every `<script>` after setting innerHTML, so the canvas exists by the
 * time this runs, and the Chart global is polled for rather than
 * assumed — `Chart.min` is loaded once at page level.
 *
 * @var string $chartId     Namespaced per panel, so two cards cannot
 *                          collide over one canvas
 * @var array $chartConfig  A Chart.js config
 * @var int $chartHeight    Fixed, because a canvas in a flex column
 *                          with no height resizes forever
 * @var string $chartLabel  Accessible name for the canvas
 * @var array $chartLegendSkip Dataset labels to keep off the legend,
 *                          for a series that is scaffolding rather than
 *                          a reading of its own — a threshold line. The
 *                          series is still drawn and still in tooltips.
 */
$chartHeight = $chartHeight ?? 240;
$chartLabel = $chartLabel ?? __('Chart');
$chartLegendSkip = $chartLegendSkip ?? array();
?>
<div class="vp-chart" style="height: <?= (int)$chartHeight ?>px;">
    <canvas id="<?= h($chartId) ?>"
            role="img"
            aria-label="<?= h($chartLabel) ?>"></canvas>
</div>
<script>
(function () {
    var id = <?= json_encode($chartId) ?>;
    var raw = <?= json_encode($chartConfig) ?>;
    var legendSkip = <?= json_encode(array_values($chartLegendSkip)) ?>;

    /*
     * `VP.chart` polls for the Chart global, resolves the config's
     * `var(--x)` colours against the canvas, and redraws when
     * `data-misp-mode` flips. All three are wanted by every chart on the
     * page, so they live in value-intelligence.js rather than once per
     * fragment that happens to draw one.
     */
    VP.chart.boot(id, function (el) {
        var config = VP.chart.resolve(JSON.parse(JSON.stringify(raw)), el);
        /*
         * A filter callback cannot survive JSON, so it is installed here
         * from the label list the caller passed instead.
         */
        if (legendSkip.length) {
            config.options = config.options || {};
            config.options.plugins = config.options.plugins || {};
            config.options.plugins.legend =
                config.options.plugins.legend || {};
            config.options.plugins.legend.labels =
                config.options.plugins.legend.labels || {};
            config.options.plugins.legend.labels.filter =
                function (item) {
                    return legendSkip.indexOf(item.text) === -1;
                };
        }
        return new Chart(el, config);
    });
}());
</script>