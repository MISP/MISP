<?php
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

// Group galaxies by name, collecting cluster values and local status
$groupedGalaxies = [];
foreach ($data as $item) {
    if (!empty($item['Galaxy'])) {
        $galaxyName  = $item['Galaxy']['name'];
        $clusterValue = $item['value'] ?? '';
        $isLocal     = !empty($item['local']);
    } elseif (!empty($item['GalaxyCluster'])) {
        $galaxyName  = $item['name'] ?? 'Unknown';
        $clusterValue = $item['GalaxyCluster'][0]['value'] ?? '';
        $isLocal     = !empty($item['GalaxyCluster'][0]['local']);
    } else {
        continue;
    }

    if (!isset($groupedGalaxies[$galaxyName])) {
        $groupedGalaxies[$galaxyName] = ['clusters' => [], 'local' => false];
    }
    $groupedGalaxies[$galaxyName]['clusters'][] = $clusterValue;
    if ($isLocal) {
        $groupedGalaxies[$galaxyName]['local'] = true;
    }
}

//Determine galaxy badge colors based on galaxy name hash
$galaxyHue = function (string $name): int {
    $hash = 0;
    for ($i = 0, $len = strlen($name); $i < $len; $i++) {
        $hash = (($hash << 5) - $hash + ord($name[$i])) & 0x7FFFFFFF;
    }
    return $hash % 360;
};

// Show all galaxy badges until cumulative galaxy >= 2 or cumulative clusters >= 5
$maxGalaxies     = 2;
$runningGalaxies = 0;
$maxClusters     = 5;
$runningClusters = 0;
$hiddenCount     = 0;
?>

<div class="galaxy-container">

<?php foreach ($groupedGalaxies as $galaxyName => $galaxyData):
    $isHidden = (($runningClusters >= $maxClusters) || ($runningGalaxies >= $maxGalaxies));
    if (!$isHidden) {
        $runningGalaxies++;
    }
    $runningClusters += count($galaxyData['clusters']);

    if ($isHidden) {
        $hiddenCount++;
    }

    $hue         = $galaxyHue($galaxyName);
    $bgColor     = "hsla({$hue},65%,55%,0.12)";
    $textColor   = "hsl({$hue},65%,30%)";
    $borderColor = "hsl({$hue},65%,30%)";
    $borderStyle = $galaxyData['local'] ? 'dashed' : 'solid';

    $style = "background-color:{$bgColor}; color:{$textColor};"
           . " border:1px {$borderStyle} {$borderColor};"
           . " background-image:linear-gradient(145deg,rgba(255,255,255,0.15) 0%,rgba(255,255,255,0.04) 40%,rgba(0,0,0,0.04) 100%);"
           . " text-align:left; white-space:normal; word-wrap:break-word; cursor:pointer;";

    $clusterList = implode(' &middot; ', array_map('h', $galaxyData['clusters']));
    $hiddenClass = $isHidden ? 'd-none extra-galaxies' : '';
?>
    <span class="badge me-1 mb-1 <?= $hiddenClass ?>" style="<?= $style ?>">
        <div class="d-flex flex-column">
            <div
                class="fw-bold mb-1 d-flex align-items-center"
                style="font-size:0.95rem; color:hsl(<?= $hue ?>,75%,22%);"
            >
                <?php if ($galaxyData['local']): ?>
                    <i class="fas fa-user me-1"></i>
                <?php endif; ?>
                <span><?= h($galaxyName) ?></span>
            </div>
            <div
                style="
                    font-size:0.78rem;
                    color:hsl(<?= $hue ?>,45%,35%);
                    line-height:1.25;
                "
            >
                <?= implode('<br>', array_map('h', $galaxyData['clusters'])) ?>
            </div>
        </div>
    </span>
<?php endforeach; ?>

<?php if ($hiddenCount > 0): ?>
    <span
        class="badge bg-secondary text-white me-1 mb-1 galaxy-expand"
        style="cursor:pointer;"
        onclick="toggleGalaxies(this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

</div>

<script>
window.toggleGalaxies = window.toggleGalaxies || function(badge) {
    const container = badge.closest('.galaxy-container');
    const hidden = container.querySelectorAll('.extra-galaxies');
    if (!hidden.length) return;
    const isHidden = hidden[0].classList.contains('d-none');
    hidden.forEach(el => el.classList.toggle('d-none'));
    badge.textContent = isHidden ? '−' : '+' + hidden.length;
};
</script>