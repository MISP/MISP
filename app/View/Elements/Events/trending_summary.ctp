<?php
$clusteredTags = $trendAnalysis['clustered_tags'];
$clusteredEvents = $trendAnalysis['clustered_events'];
$allTags = $trendAnalysis['all_tags'];
$allTimestamps = $trendAnalysis['all_timestamps'];
$currentPeriod = $allTimestamps[0];
$previousPeriod = $allTimestamps[1];
$previousPeriod2 = $allTimestamps[2];

$clusteredTags[$previousPeriod]['admiralty-scale:source-reliability="d"'] = [
    'occurence' => (float) 0.33,
    'raw_change' => (int) 1,
    'percent_change' => (int) 100,
    'change_sign' => (int) 1
];
$allUniqueTagsPerPeriod = array_map(function ($tags) {
    return array_keys($tags);
}, $clusteredTags);
$allUniqueTags = array_unique(array_merge($allUniqueTagsPerPeriod[$currentPeriod], $allUniqueTagsPerPeriod[$previousPeriod], $allUniqueTagsPerPeriod[$previousPeriod2]));
App::uses('ColourPaletteTool', 'Tools');
$paletteTool = new ColourPaletteTool();
$COLOR_PALETTE = $paletteTool->createColourPalette(count($allUniqueTags));

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
    $colorForTags[$tag] = $COLOR_PALETTE[$i];
    $chartData[$tag] = [
        $clusteredTags[$previousPeriod2][$tag]['occurence'] ?? 0,
        $clusteredTags[$previousPeriod][$tag]['occurence'] ?? 0,
        $clusteredTags[$currentPeriod][$tag]['occurence'] ?? 0,
    ];
    $maxValue = max($maxValue, max($chartData[$tag]));
}
$canvasWidth = 600;
$canvasHeight = 150;
foreach (array_keys($chartData) as $tag) {
    $chartData[$tag][0] = [0, $canvasHeight - ($chartData[$tag][0] / $maxValue) * $canvasHeight];
    $chartData[$tag][1] = [$canvasWidth/2, $canvasHeight - ($chartData[$tag][1] / $maxValue) * $canvasHeight];
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

<h2><?= __('Tag trendings') ?></h2>

<div style="display: flex; column-gap: 20px; justify-content: space-around; margin-bottom: 40px;">
    <div>
        <table class="table table-condensed" style="min-width: 300px; min-width: 400px;">
            <tbody>
                <tr>
                    <td><?= __('Period duration') ?></td>
                    <td><?= __('%s days', $currentPeriodDate->diff($now)->format('%a')); ?></td>
                </tr>
                <tr>
                    <td><?= __('Current period') ?></td>
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
    <div style="padding: 0 40px; margin: -40px 20px 0 0;">
        <div class="chart-container">
            <div class="canvas">
                <?php foreach ($chartData as $tag => $coords) : ?>
                    <?php for ($i=0; $i < 3; $i++) : ?>
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
                                    h($tag),
                                );
                            }
                        ?>
                    <?php endfor ?>
                <?php endforeach ?>
            </div>
            <div style="position: relative;">
                <span style="<?= sprintf('position: absolute; white-space: nowrap; translate: -50%%; left: %spx; top: %spx;', 0, 0) ?>"><?= __('Period 2') ?></span>
                <span style="<?= sprintf('position: absolute; white-space: nowrap; translate: -50%%; left: %spx; top: %spx;', $canvasWidth/2, 0) ?>"><?= __('Previous period') ?></span>
                <span style="<?= sprintf('position: absolute; white-space: nowrap; translate: -50%%; left: %spx; top: %spx;', $canvasWidth, 0) ?>"><?= __('Current period') ?></span>
            </div>
        </div>
    </div>
</div>

<?php if (!empty($allTags)) : ?>
    <table class="table table-condensed no-border">
        <thead>
            <tr>
                <th></th>
                <th>
                    <span>
                        <div><?= __('Period-2') ?></div>
                        <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$previousPeriod2])) ?></div>
                    </span>
                    <table>
                        <thead style="font-size: small;">
                            <tr>
                                <td style="min-width: 20px;">#</td>
                                <td style="min-width: 15px;">⥮</td>
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
                    <table>
                        <thead style="font-size: small;">
                            <tr>
                                <td style="min-width: 20px;">#</td>
                                <td style="min-width: 15px;">⥮</td>
                                <td>%</td>
                                <td></td>
                            </tr>
                        </thead>
                    </table>
                </th>
                <th>
                    <span>
                        <div><?= __('Current period') ?></div>
                        <div style="font-weight: normal;"><?= __('%s events', h($clusteredEvents[$currentPeriod])) ?></div>
                    </span>
                    <table>
                        <thead style="font-size: small;">
                            <tr>
                                <td style="min-width: 20px;">#</td>
                                <td style="min-width: 15px;">⥮</td>
                                <td>%</td>
                                <td></td>
                            </tr>
                        </thead>
                    </table>
                </th>
            </tr>
        </thead>
        <?php foreach ($tagFilterPrefixes as $tagPrefix) : ?>
            <tbody>
                <tr>
                    <td colspan="4">
                        <h4><?= __('Taxonomy: %s', sprintf('<code>%s</code>', h($tagPrefix))) ?></h4>
                    </td>
                </tr>
                <?php foreach ($allTags[$tagPrefix] as $tagName) : ?>
                    <tr>
                        <td style="padding-left: 15px;">
                            <span class="tag-legend" style="background-color: <?= $colorForTags[$tagName] ?>;"></span>
                            <code><?= h(reduceTag($tagName, count(explode(':', $tagPrefix)))) ?></code>
                        </td>
                        <td>
                            <table class="table-condensed no-border">
                                <tbody>
                                    <tr>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['occurence'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['raw_change'] ?? '-') ?></td>
                                        <td><?= h($clusteredTags[$previousPeriod2][$tagName]['percent_change'] ?? '-') ?>%</td>
                                        <td style="font-size: large; color: <?= $trendColorMapping[$clusteredTags[$previousPeriod2][$tagName]['change_sign'] ?? '?'] ?>"><?= $trendIconMapping[$clusteredTags[$previousPeriod2][$tagName]['change_sign'] ?? '?'] ?></td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                        <td>
                            <table class="table-condensed no-border">
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
                            <table class="table-condensed no-border">
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
                <?php endforeach; ?>
            </tbody>
        <?php endforeach; ?>
    </table>
<?php endif; ?>

<style>
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
        box-shadow: 1px 1px 2px 0px #00000066;
    }

    .canvas {
        width: 610px;
        height: 160px;
        position: relative;
    }

    .tag-legend {
        display: inline-block;
        width: 10px;
        height: 10px;
        border: 1px solid #000;
    }
</style>
