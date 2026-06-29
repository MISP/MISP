<?php
$data = Hash::extract($row, $field['data_path']);

/*
 * Optional inline "+" button to attach a galaxy cluster to this object.
 * Enabled by the caller via $field['add_galaxy'] (already ACL-gated upstream).
 * $field['add_galaxy_url'] holds a URL template with a %id% placeholder,
 * resolved from $field['add_galaxy_id_path'] (falls back to $row['id']).
 */
$allowAddGalaxy = !empty($field['add_galaxy']);
$addUrl         = null;
if ($allowAddGalaxy) {
    $addId = Hash::get($row, $field['add_galaxy_id_path'] ?? 'id');
    if (empty($addId) && !empty($row['id'])) {
        $addId = $row['id'];
    }
    $isDeleted = !empty($row['deleted']) || !empty($row['Attribute']['deleted']);
    if (!empty($addId) && !$isDeleted && !empty($field['add_galaxy_url'])) {
        $addUrl = str_replace('%id%', rawurlencode($addId), $field['add_galaxy_url']);
    }
}

if (empty($data)) {
    if (!empty($row['Galaxy'])) {
        $data = $row['Galaxy'];
    } elseif (!empty($row['AttributeTag'])) {
        $data = $row['AttributeTag'];
    } elseif (empty($addUrl)) {
        return;
    } else {
        $data = [];
    }
}

// Group galaxies by name, collecting cluster values and local status
$groupedGalaxies = [];

foreach ($data as $item) {
    // AttributeTag format: Tag.is_galaxy = true 
    if (!empty($item['Tag']) && !empty($item['Tag']['is_galaxy'])) {
        $tagName = $item['Tag']['name'];
        preg_match('/^[^:]+:([^=]+)="(.+)"$/', $tagName, $m);
        $galaxyType   = isset($m[1]) ? $m[1] : 'unknown';
        $clusterValue = isset($m[2]) ? $m[2] : $tagName;
        $isLocal      = !empty($item['local']);
        $galaxyName   = ucwords(str_replace('-', ' ', $galaxyType));

        if (!isset($groupedGalaxies[$galaxyName])) {
            $groupedGalaxies[$galaxyName] = [
                'clusters' => [],
                'icon'     => 'circle-dot',
            ];
        }
        $groupedGalaxies[$galaxyName]['clusters'][] = [
            'value' => $clusterValue,
            'local' => $isLocal,
        ];
        continue;
    }

    //Galaxy / GalaxyCluster format
    if (!empty($item['Galaxy'])) {
        $galaxyName  = $item['Galaxy']['name'];
        $clusterValue = $item['value'] ?? '';
        $isLocal     = !empty($item['local']);
        $icon        = $item['Galaxy']['icon'] ?? 'globe';

    } elseif (!empty($item['GalaxyCluster'])) {
        $galaxyName  = $item['name'] ?? 'Unknown';
        $clusterValue = $item['GalaxyCluster'][0]['value'] ?? '';
        $isLocal     = !empty($item['GalaxyCluster'][0]['local']);
        $icon        = $item['icon'] ?? 'globe';

    } else {
        continue;
    }

    if (!isset($groupedGalaxies[$galaxyName])) {
        $groupedGalaxies[$galaxyName] = [
            'clusters' => [],
            'icon' => $icon
        ];
    }

    $groupedGalaxies[$galaxyName]['clusters'][] = [
        'value' => $clusterValue,
        'local' => $isLocal
    ];
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
    $bgColor     = "hsla({$hue},65%,55%,var(--galaxy-alpha,0.12))";
    $textColor   = "hsl({$hue},65%,30%)";
    $borderColor = "hsl({$hue},65%,30%)";
    $borderStyle = 'solid';//$galaxyData['local'] ? 'dashed' : 'solid';

    $style = "background-color:{$bgColor}; color:{$textColor};"
           . " border:1px {$borderStyle} {$borderColor};"
           . " background-image:linear-gradient(145deg,rgba(255,255,255,0.15) 0%,rgba(255,255,255,0.04) 40%,rgba(0,0,0,0.04) 100%);"
           . " text-align:left; white-space:normal; word-wrap:break-word; cursor:pointer;";

    $clusterList = implode(' &middot; ', array_map(function($c) { return h($c['value']); }, $galaxyData['clusters']));
    $hiddenClass = $isHidden ? 'd-none extra-galaxies' : '';
?>
<?php
$brandIcons = [
    'github',
    'gitlab',
    'docker',
    'linux',
    'android',
    'apple',
    'google',
    'microsoft',
    'facebook',
    'twitter',
    'linkedin',
    'btc',
    'ethereum',
    'optin-monster',
    'internet-explorer'
];

$iconPrefix = in_array($groupedGalaxies[$galaxyName]['icon'], $brandIcons, true) ? 'fab' : 'fas';
?>


    <span class="badge me-1 mb-1 <?= $hiddenClass ?>" style="<?= $style ?>">
        <div class="d-flex flex-column">
            <div
                class="fw-bold mb-1 d-flex align-items-center"
                style="font-size:0.95rem; color:hsl(<?= $hue ?>,75%,22%);"
            >
                <i class="<?= $iconPrefix ?> fa-<?= h($groupedGalaxies[$galaxyName]['icon']) ?> me-1"></i>
                <span><?= h($galaxyName) ?></span>
            </div>
            <div
                style="font-size:0.78rem; color:hsl(<?= $hue ?>,45%,35%); line-height:1.25;"
            >
                <?php foreach ($galaxyData['clusters'] as $cluster): ?>
                    <div class="d-flex align-items-center gap-1">
                        <?php if ($cluster['local']): ?>
                            <i class="fas fa-user"></i>
                        <?php endif; ?>
                        <span><?= h($cluster['value']) ?></span>
                    </div>
                <?php endforeach; ?>
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

<?php if (!empty($addUrl)): ?>
    <button
        type="button"
        class="badge border-0 me-1 mb-1 align-self-start attr-add-galaxy-btn"
        style="cursor:pointer; background:hsla(258,90%,66%,.12); color:hsl(258,55%,40%);"
        title="<?= __('Add a galaxy cluster') ?>"
        aria-label="<?= __('Add a galaxy cluster') ?>"
        onclick="event.stopPropagation(); openModal('<?= h($addUrl) ?>', 'xl');"
    >
        <i class="fas fa-plus"></i>
    </button>
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