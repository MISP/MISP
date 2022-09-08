<?php
$clusteredTags = $trendAnalysis['clustered_tags'];
$clusteredEvents = $trendAnalysis['clustered_events'];
$allTags = $trendAnalysis['all_tags'];
$allTimestamps = $trendAnalysis['all_timestamps'];
$currentPeriod = $allTimestamps[0];
$previousPeriod = $allTimestamps[1];
$previousPeriod2 = $allTimestamps[2];

$COLOR_PALETTE = ['#eecc66', '#ee99aa', '#6699cc', '#997700', '#994455', '#dddddd'];

// $pieChartData = array_map(function(array $tagMetrics) {
//     return $tagMetrics['occurence'];
// }, $clusteredTags[$currentPeriod]);
// arsort($pieChartData);
// $topPieChartData = array_slice($pieChartData, 0, 5);

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

if (!function_exists('reduceTag')) {
    function reduceTag(string $tagname, int $reductionLength=1): string
    {
        $re = '/^(?<namespace>[a-z0-9_-]+)(:(?<predicate>[a-z0-9_-]+)="(?<value>[^"]+)"$)?(:(?<predicate2>[a-z0-9_-]+))?/';
        $matches = [];
        preg_match($re, $tagname, $matches);
        if (!empty($matches['predicate2'])) {
            return $reductionLength == 0 ? $tagname : $matches['predicate2'];
        } else if (!empty($matches['value'])) {
            return $reductionLength == 0 ? $tagname : (
                $reductionLength == 1 ? sprintf('%s="%s"', $matches['predicate'], $matches['value']) : $matches['value']
            );
        } else if (!empty($matches['namespace'])) {
            return $matches['namespace'];
        } else {
            return $tagname;
        }
    }
}
?>

<h2><?= __('Tag trendings') ?></h2>

<div style="display: flex;">
    <div>
        <table class="table table-condensed" style="max-width: 400px;">
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
    <div>
    </div>
</div>

<?php if (!empty($allTags)): ?>
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
                        <h5><?= __('Taxonomy: %s', sprintf('<code>%s</code>', h($tagPrefix))) ?></h5>
                    </td>
                </tr>
                <?php foreach ($allTags[$tagPrefix] as $tagName) : ?>
                    <tr>
                        <td style="padding-left: 15px;"><code style="color: black;"><?= h(reduceTag($tagName, count(explode(':', $tagPrefix)))) ?></code></td>
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
</style>