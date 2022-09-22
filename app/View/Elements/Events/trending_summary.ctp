<?php
$clusteredTags = $trendAnalysis['clustered_tags'];
$clusteredEvents = $trendAnalysis['clustered_events'];
$allTags = $trendAnalysis['all_tags'];
$allTimestamps = $trendAnalysis['all_timestamps'];
$currentPeriod = $allTimestamps[0];
$previousPeriod = $allTimestamps[1];
$previousPeriod2 = $allTimestamps[2];
$periods = [$previousPeriod2, $previousPeriod, $currentPeriod];

$allUniqueTagsPerPeriod = array_map(function ($tags) {
    return array_keys($tags);
}, $clusteredTags);
$allUniqueTags = array_unique(array_merge($allUniqueTagsPerPeriod[$currentPeriod], $allUniqueTagsPerPeriod[$previousPeriod], $allUniqueTagsPerPeriod[$previousPeriod2]));
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
$currentPeriodDate = DateTime::createFromFormat('U', $currentPeriod);
$previousPeriodDate = DateTime::createFromFormat('U', $previousPeriod);
$previousPeriod2Date = DateTime::createFromFormat('U', $previousPeriod2);

$colorForTags = [];
$chartData = [];
$maxValue = 0;
foreach ($allUniqueTags as $i => $tag) {
    if (
        !empty($clusteredTags[$previousPeriod2][$tag]['occurence']) ||
        !empty($clusteredTags[$previousPeriod][$tag]['occurence']) ||
        !empty($clusteredTags[$currentPeriod][$tag]['occurence'])
    ) {
        $colorForTags[$tag] = $COLOR_PALETTE[$i];
        $chartData[$tag] = [
            $clusteredTags[$previousPeriod2][$tag]['occurence'] ?? 0,
            $clusteredTags[$previousPeriod][$tag]['occurence'] ?? 0,
            $clusteredTags[$currentPeriod][$tag]['occurence'] ?? 0,
        ];
        $maxValue = max($maxValue, max($chartData[$tag]));
    }
}
$canvasWidth = 600;
$canvasHeight = 150;
foreach (array_keys($chartData) as $tag) {
    $chartData[$tag][0] = [0, $canvasHeight - ($chartData[$tag][0] / $maxValue) * $canvasHeight];
    $chartData[$tag][1] = [$canvasWidth / 2, $canvasHeight - ($chartData[$tag][1] / $maxValue) * $canvasHeight];
    $chartData[$tag][2] = [$canvasWidth, $canvasHeight - ($chartData[$tag][2] / $maxValue) * $canvasHeight];
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

?>

<div style="display: flex; column-gap: 20px; justify-content: space-around; margin-bottom: 40px;">
    <div style="display: flex; align-items: center;">
        <table class="table table-condensed" style="min-width: 300px; max-width: 400px; margin: 0;">
            <tbody>
                <tr>
                    <td><?= __('Period duration') ?></td>
                    <td><?= __('%s days', $currentPeriodDate->diff($now)->format('%a')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Starting period') ?></td>
                    <td><?= sprintf('%s', $currentPeriodDate->format('M d, o. (\W\e\e\k W)')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Previous period') ?></td>
                    <td><?= sprintf('%s', $previousPeriodDate->format('M d, o. (\W\e\e\k W)')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Period-2') ?></td>
                    <td><?= sprintf('%s', $previousPeriod2Date->format('M d, o. (\W\e\e\k W)')); ?></td>
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
                        <span class="y-axis-label" style="<?= sprintf('left: %spx; top: %spx; transform: translate(-100%%, %s%%)', 0, ($canvasHeight - 20), 25) ?>"><?= 0 ?></span>
                    </div>
                </div>
                <div class="canvas">
                    <?php foreach ($chartData as $tag => $coords) : ?>
                        <?php for ($i = 0; $i < 3; $i++) : ?>
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
                    <span class="x-axis-label" style="<?= sprintf('left: %spx; top: %spx;', 0, 0) ?>"><?= __('Period-2') ?></span>
                    <span class="x-axis-label" style="<?= sprintf('left: %spx; top: %spx;', $canvasWidth / 2, 0) ?>"><?= __('Previous period') ?></span>
                    <span class="x-axis-label" style="<?= sprintf('left: %spx; top: %spx;', $canvasWidth, 0) ?>"><?= __('Starting period') ?></span>
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
                <th>
                    <span>
                        <div><?= __('Period-2') ?></div>
                        <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$previousPeriod2])) ?></div>
                    </span>
                    <table class="trending-table-data">
                        <thead style="font-size: small;">
                            <tr>
                                <td>#</td>
                                <td>⥮</td>
                                <td>%</td>
                                <td></td>
                            </tr>
                        </thead>
                    </table>
                </th>
                <th>
                    <span>
                        <div><?= __('Previous period') ?></div>
                        <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$previousPeriod])) ?></div>
                    </span>
                    <table class="trending-table-data">
                        <thead style="font-size: small;">
                            <tr>
                                <td>#</td>
                                <td>⥮</td>
                                <td>%</td>
                                <td></td>
                            </tr>
                        </thead>
                    </table>
                </th>
                <th>
                    <span>
                        <div><?= __('Starting period') ?></div>
                        <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$currentPeriod])) ?></div>
                    </span>
                    <table class="trending-table-data">
                        <thead style="font-size: small;">
                            <tr>
                                <td>#</td>
                                <td>⥮</td>
                                <td>%</td>
                                <td></td>
                            </tr>
                        </thead>
                    </table>
                </th>
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
                        <td>
                            <table class="table-condensed no-border trending-table-data">
                                <tbody>
                                    <tr>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['occurence'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['raw_change'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['percent_change'] ?? '-') ?>%</td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                        <td>
                            <table class="table-condensed no-border trending-table-data">
                                <tbody>
                                    <tr>
                                        <td><?= h($clusteredTags[$previousPeriod][$tagName]['occurence'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod][$tagName]['raw_change'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod][$tagName]['percent_change'] ?? '-') ?>%</td>
                                        <td style="font-size: large; color: <?= $trendColorMapping[$clusteredTags[$previousPeriod][$tagName]['change_sign'] ?? '?'] ?>"><?= $trendIconMapping[$clusteredTags[$previousPeriod][$tagName]['change_sign'] ?? '?'] ?></td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                        <td>
                            <table class="table-condensed no-border trending-table-data">
                                <tbody>
                                    <tr>
                                        <td><?= h($clusteredTags[$currentPeriod][$tagName]['occurence'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$currentPeriod][$tagName]['raw_change'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$currentPeriod][$tagName]['percent_change'] ?? '-') ?>%</td>
                                        <td style="font-size: large; color: <?= $trendColorMapping[$clusteredTags[$currentPeriod][$tagName]['change_sign'] ?? '?'] ?>"><?= $trendIconMapping[$clusteredTags[$currentPeriod][$tagName]['change_sign'] ?? '?'] ?></td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                    </tr>
                    <td style="padding: 0;"></td>
                    <td colspan="3" style="padding: 0;">
                        <?php
                            $low = '#fee8c8';
                            $medium = '#f09c8f';
                            $high = '#bc2f1a';
                            $colorGradient = [];
                            foreach ($periods as $i => $period) {
                                $ratio = ($clusteredTags[$period][$tagName]['occurence'] ?? 0) / $maxValue;
                                $color = $ratio <= 0.33 ? $low : ($ratio >= 0.66 ? $high : $medium);
                                $length = 100 * $i / (count($periods) - 1);
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

    .y-axis-container > div {
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