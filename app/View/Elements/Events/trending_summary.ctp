<?php
$clusteredTags = $trendAnalysis['clustered_tags'];
$clusteredEvents = $trendAnalysis['clustered_events'];
$allTags = $trendAnalysis['all_tags'];
$allTimestamps = $trendAnalysis['all_timestamps'];
$currentPeriod = $allTimestamps[0];
$previousPeriod = $allTimestamps[1];
$periods = $allTimestamps;
$reversedPeriods = array_reverse($periods);
$periodCount = count($periods);

$allUniqueTagsPerPeriod = array_map(function ($tags) {
    return array_keys($tags);
}, $clusteredTags);
$allUniqueTags = array_values(array_unique(Hash::extract($allUniqueTagsPerPeriod, '{n}.{n}')));
App::uses('ColourPaletteTool', 'Tools');
$paletteTool = new ColourPaletteTool();
$COLOR_PALETTE = $paletteTool->createColourPalette(max(count($allUniqueTags), 1));

$trendIconMapping = [
    1 => '▲',
    -1 => '▼',
    0 => '⮞',
    '?' => '',
];
$trendColorMapping = [
    1 => '#b94a48',
    -1 => '#468847',
    0 => '#3a87ad',
    '?' => '#999999',
];
$now = new DateTime();

$colorForTags = [];
$chartData = [];
$maxValue = 0;
foreach ($allUniqueTags as $i => $tag) {
    $sumForTags = array_reduce($clusteredTags, function ($carry, $clusteredTagsPerPeriod) use ($tag) {
        return $carry + ($clusteredTagsPerPeriod[$tag]['occurrence'] ?? 0);
    }, 0);
    if ($sumForTags > 0) {
        $colorForTags[$tag] = $COLOR_PALETTE[$i];
        $chartData[$tag] = array_values(array_map(function ($clusteredTagsPerPeriod) use ($tag) {
            return $clusteredTagsPerPeriod[$tag]['occurrence'] ?? 0;
        }, $clusteredTags));
        $chartData[$tag] = array_reverse($chartData[$tag]);
        $maxValue = max($maxValue, max($chartData[$tag]));
    }
    $colorForTags[$tag] = $COLOR_PALETTE[$i];
}
$canvasWidth = 600;
$canvasHeight = 150;
foreach (array_keys($chartData) as $tag) {
    $lastIndex = count($chartData[$tag]) - 1;
    $canvasSubWidth = $lastIndex;
    $chartData[$tag][0] = [0, $canvasHeight - ($chartData[$tag][0] / $maxValue) * $canvasHeight];
    for ($i = 1; $i < $lastIndex; $i++) {
        $chartData[$tag][$i] = [$canvasWidth * ($i / $canvasSubWidth), $canvasHeight - ($chartData[$tag][$i] / $maxValue) * $canvasHeight];
    }
    $chartData[$tag][$lastIndex] = [$canvasWidth, $canvasHeight - ($chartData[$tag][$lastIndex] / $maxValue) * $canvasHeight];
}

if (!function_exists('reduceTag')) {
    function reduceTag(string $tagname, int $reductionLength = 1): string
    {
        $re = '/^(?<namespace>[a-z0-9_-]+)(:(?<predicate>[a-z0-9_-]+)="(?<value>[^"]+)"$)?(:(?<predicate2>[a-z0-9_-]+))?/';
        $matches = [];
        preg_match($re, $tagname, $matches);
        if (!empty($matches['predicate2'])) {
            return $reductionLength == 0 ? $tagname : $matches['predicate2'];
        } else if (!empty($matches['value'])) {
            return $reductionLength == 0 ? $tagname : ($reductionLength == 1 ? sprintf('%s="%s"', $matches['predicate'], $matches['value']) : $matches['value']
            );
        } else if (!empty($matches['namespace'])) {
            return $matches['namespace'];
        } else {
            return $tagname;
        }
    }
}

if (!function_exists('computeLinePositions')) {
    function computeLinePositions(float $x1, float $y1, float $x2, float $y2): array
    {
        $x_offset = 3.5;
        $y_offset = 1;
        $conf = [
            'left' => $x1 + $x_offset,
            'top' => $y1 + $y_offset,
            'width' => sqrt(pow($y2 - $y1, 2) + pow($x2 - $x1, 2)),
            'angle' => atan(($y2 - $y1) / ($x2 - $x1)),
        ];
        return $conf;
    }
}

if (!function_exists('getColorFromYlOrBr')) {
    function getColorFromYlOrBr(float $min, float $max, float $value): string
    {
        $YlOrBrPalette = ["#fff7bc", "#fee391", "#fec44f", "#fe9929", "#ec7014", "#cc4c02", "#993404", "#662506"];
        $valuePercent = $value / ($max - $min);
        $paletteRatio = $valuePercent * count($YlOrBrPalette);
        $paletteIndex = max(round($paletteRatio - 1), 0);
        return $YlOrBrPalette[$paletteIndex];
    }
}

?>

<div style="display: flex; column-gap: 20px; justify-content: space-around; margin-bottom: 40px;">
    <div style="display: flex; align-items: center;">
        <table class="table table-condensed" style="min-width: 300px; max-width: 400px; margin: 0;">
            <tbody>
                <tr>
                    <td><?= __('Period duration') ?></td>
                    <td><?= __('%s days', DateTime::createFromFormat('U', $currentPeriod)->diff($now)->format('%a')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Period number') ?></td>
                    <td><?= count($periods) - 1 ?></td>
                </tr>
                <tr>
                    <td><?= __('Starting period') ?></td>
                    <td><?= sprintf('%s', DateTime::createFromFormat('U', $currentPeriod)->format('M d, o. (\W\e\e\k W)')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Last period') ?></td>
                    <td><?= sprintf('%s', DateTime::createFromFormat('U', $periods[$periodCount - 1])->format('M d, o. (\W\e\e\k W)')); ?></td>
                </tr>
            </tbody>
        </table>
    </div>
    <?php if (!empty($allUniqueTags)) : ?>
        <div style="padding: 0 40px;">
            <div class="chart-container">
                <div class="y-axis-container">
                    <div>
                        <span class="y-axis-label" style="<?= sprintf('left: %spx; top: %spx; transform: translate(-100%%, %s%%)', 0, 0, -25) ?>"><?= h($maxValue) ?></span>
                        <span class="y-axis-label" style="<?= sprintf('left: %spx; top: %spx; transform: translate(-100%%, %s%%)', 0, ($canvasHeight - 20) / 2, 0) ?>"><?= h(round($maxValue / 2, 2)) ?></span>
                        <span class="y-axis-label" style="<?= sprintf('left: %spx; top: %spx; transform: translate(-100%%, %s%%)', 0, ($canvasHeight - 20), 25) ?>">0</span>
                    </div>
                </div>
                <div class="canvas">
                    <?php foreach ($chartData as $tag => $coords) : ?>
                        <?php for ($i = 0; $i < count($periods); $i++) : ?>
                            <?php
                            $coord = $coords[$i];
                            $previousCoord = isset($coords[$i - 1]) ? $coords[$i - 1] : false;
                            ?>
                            <span class="dot" style="<?= sprintf('left: %spx; top: %spx; background-color: %s;', $coord[0], $coord[1], $colorForTags[$tag]) ?>" title="<?= h($tag) ?>"></span>
                            <?php
                            if (!empty($previousCoord)) {
                                $linePosition = computeLinePositions($previousCoord[0], $previousCoord[1], $coord[0], $coord[1]);
                                echo sprintf(
                                    '<span class="line" style="left: %spx; top: %spx; width: %spx; transform: rotate(%srad); background-color: %s;" title="%s"></span>',
                                    $linePosition['left'],
                                    $linePosition['top'],
                                    $linePosition['width'],
                                    $linePosition['angle'],
                                    $colorForTags[$tag],
                                    h($tag)
                                );
                            }
                            ?>
                        <?php endfor ?>
                    <?php endforeach ?>
                </div>
                <div class="x-axis-container">
                    <?php foreach ($reversedPeriods as $i => $period) : ?>
                        <span class="x-axis-label" style="<?= sprintf('left: %spx; top: %spx;', $i * $canvasWidth / $canvasSubWidth, 0) ?>"><?= DateTime::createFromFormat('U', $period)->format('M. d, o') ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    <?php else : ?>
        <p><?= __('- No tag for the selected tag namespace -') ?></p>
    <?php endif; ?>
</div>

<?php if (!empty($allTags)) : ?>
    <table class="table table-condensed no-border trending-table">
        <thead>
            <tr>
                <th></th>
                <?php foreach ($reversedPeriods as $i => $period) : ?>
                    <th>
                        <span>
                            <div><?= DateTime::createFromFormat('U', $period)->format('M. d, o') ?></div>
                            <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$period])) ?></div>
                        </span>
                        <table class="trending-table-data">
                            <thead style="font-size: small;">
                                <tr>
                                    <td title="<?= __('Occurrence per events') ?>">#</td>
                                    <td title="<?= __('Raw change') ?>">⥮</td>
                                    <td title="<?= __('Percent change') ?>">%</td>
                                    <td></td>
                                </tr>
                            </thead>
                        </table>
                    </th>
                <?php endforeach; ?>
            </tr>
        </thead>
        <?php foreach ($tagFilterPrefixes as $tagPrefix) : ?>
            <?php
            if (empty($allTags[$tagPrefix])) {
                continue;
            }
            ?>
            <tbody>
                <tr>
                    <td colspan="4">
                        <h4><?= __('Tag namespace: %s', sprintf('<code>%s</code>', h($tagPrefix))) ?></h4>
                    </td>
                </tr>
                <?php foreach ($allTags[$tagPrefix] as $tagName) : ?>
                    <tr>
                        <td style="padding-left: 15px;">
                            <span class="tag-legend" style="background-color: <?= $colorForTags[$tagName] ?>;"></span>
                            <code><?= h(reduceTag($tagName, count(explode(':', $tagPrefix)))) ?></code>
                        </td>
                        <?php foreach ($reversedPeriods as $i => $period) : ?>
                            <td>
                                <table class="table-condensed no-border trending-table-data">
                                    <tbody>
                                        <tr>
                                            <td title="<?= __('Occurrence per events') ?>"><?= h($clusteredTags[$period][$tagName]['occurrence'] ?? '-') ?></td>
                                            <td title="<?= __('Raw change') ?>"><?= h($clusteredTags[$period][$tagName]['raw_change'] ?? '-') ?></td>
                                            <td title="<?= __('Percent change') ?>"><?= h($clusteredTags[$period][$tagName]['percent_change'] ?? '-') ?>%</td>
                                            <?php if ($i > 0) : ?>
                                                <td title="<?= __('Evolution') ?>" style="font-size: large; color: <?= $trendColorMapping[$clusteredTags[$period][$tagName]['change_sign'] ?? '?'] ?>"><?= $trendIconMapping[$clusteredTags[$period][$tagName]['change_sign'] ?? '?'] ?></td>
                                            <?php endif; ?>
                                        </tr>
                                    </tbody>
                                </table>
                            </td>
                        <?php endforeach; ?>
                    </tr>
                    <td style="padding: 0;"></td>
                    <td colspan="<?= count($periods) ?>" style="padding: 0;">
                        <?php
                        $colorGradient = [];
                        foreach ($reversedPeriods as $i => $period) {
                            $color = getColorFromYlOrBr(0, $maxValue, $clusteredTags[$period][$tagName]['occurrence'] ?? 0);
                            $length = 100 * $i / (count($periods) - 1);
                            $length = $i > 0 ? $length - 5 : $length; // Small offset to better align colors on the table period header
                            $colorGradient[] = sprintf('%s %s%%', $color, $length);
                        }
                        ?>
                        <div class="heatbar" style="background: <?= sprintf('linear-gradient(90deg, %s);', implode(', ', $colorGradient)) ?>;"></div>
                    </td>
                <?php endforeach; ?>
            </tbody>
        <?php endforeach; ?>
    </table>
<?php endif; ?>

<style>
    table.trending-table table.trending-table-data {
        width: 150px;
    }

    table.trending-table th:not(:first-child) {
        width: 150px;
    }

    table.trending-table table.trending-table-data thead td:first-child,
    table.trending-table table.trending-table-data tbody td:first-child {
        box-sizing: border-box;
        width: 35px;
    }

    table.trending-table table.trending-table-data thead td:nth-child(2),
    table.trending-table table.trending-table-data tbody td:nth-child(2) {
        box-sizing: border-box;
        width: 35px;
    }

    .dot {
        position: absolute;
        height: 7px;
        width: 7px;
        border-radius: 50%;
    }

    .line {
        position: absolute;
        background: blue;
        height: 3px;
        transform-origin: left center;
        box-shadow: 1px 1px 3px 0px #00000033;
    }

    .chart-container {
        position: relative;
        background-color: #dddddd33;
        padding: 5px 35px 5px 45px;
        border-radius: 5px;
        border: 1px solid #ddd;
    }

    .canvas {
        width: 610px;
        height: 160px;
        position: relative;
    }

    .x-axis-container {
        position: relative;
        height: 20px;
    }

    .x-axis-label {
        font-size: 12px;
        position: absolute;
        white-space: nowrap;
        translate: -50%;
    }

    .y-axis-container {
        height: 150px;
        border-right: 1px solid #000;
        position: absolute;
        left: -5px;
        top: 10px;
        padding-left: inherit;
    }

    .y-axis-container>div {
        position: relative;
        height: 100%;
    }

    .y-axis-label {
        position: absolute;
        white-space: nowrap;
        font-size: 12px;
        padding: 0 5px;
    }

    .tag-legend {
        display: inline-block;
        width: 10px;
        height: 10px;
        border: 1px solid #000;
    }

    .heatbar {
        height: 3px;
        width: calc(100% - 10px);
    }
</style>