<?php

$brandIcons = [
    'github', 'gitlab', 'docker', 'linux', 'android', 'apple',
    'google', 'microsoft', 'facebook', 'twitter', 'linkedin',
    'btc', 'ethereum',
];

$galaxyHue = function (string $name): int {
    $hash = 0;
    for ($i = 0, $len = strlen($name); $i < $len; $i++) {
        $hash = (($hash << 5) - $hash + ord($name[$i])) & 0x7FFFFFFF;
    }
    return $hash % 360;
};

$totalClusters = 0;
foreach ($galaxies as $g) {
    $totalClusters += count($g['GalaxyCluster'] ?? []);
}
?>

<div data-galaxy-count="<?= $totalClusters ?>"
     data-galaxy-count-label="<?= h($totalClusters === 1 ? __('cluster') : __('clusters')) ?>">

<?php if (empty($galaxies)): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4" data-galaxy-empty>
        <span class="misp-icon misp-icon-galaxy misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
        <p class="mb-0 small fw-semibold">
            <?= __('No galaxy clusters associated with this event.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="p-3 d-flex flex-column gap-3" data-galaxy-list>

    <?php foreach ($galaxies as $galaxy):
        $galaxyName = h($galaxy['name']);
        $galaxyDesc = h($galaxy['description'] ?? '');
        $galaxyId   = (int)($galaxy['id'] ?? 0);
        $icon       = $galaxy['icon'] ?? 'meteor';
        $iconPrefix = in_array($icon, $brandIcons, true) ? 'fab' : 'fas';
        $hue        = $galaxyHue($galaxy['name']);
        $bgSection  = "hsla({$hue},55%,55%,0.07)";
        $borderCol  = "hsl({$hue},55%,70%)";
        $headCol    = "hsl({$hue},60%,28%)";

        $clusterNames = implode(' ', array_map(
            function ($c) { return strtolower($c['value'] ?? ''); },
            $galaxy['GalaxyCluster']
        ));
    ?>

        <div class="rounded-2 border overflow-hidden"
             style="border-color:<?= $borderCol ?> !important;
                    background:<?= $bgSection ?>;"
             data-galaxy-section
             data-galaxy-name="<?= h(strtolower($galaxy['name'])) ?>"
             data-cluster-names="<?= h($clusterNames) ?>">

            <!-- Galaxy header -->
            <div class="d-flex align-items-center gap-2 px-3 py-2"
                 style="background:hsla(<?= $hue ?>,55%,55%,var(--galaxy-alpha,0.12));
                        border-bottom:1px solid <?= $borderCol ?>;">
                <i class="<?= $iconPrefix ?> fa-<?= h($icon) ?>"
                   style="color:<?= $headCol ?>; font-size:0.95rem;"></i>
                <span class="fw-bold" style="color:<?= $headCol ?>; font-size:0.9rem;">
                    <?= $galaxyName ?>
                </span>
                <?php if ($galaxyId): ?>
                <a href="<?= h($baseurl) ?>/galaxies/view/<?= $galaxyId ?>"
                   class="ms-auto text-dark small"
                   style="opacity:.6;"
                   title="<?= __('View galaxy') ?>"
                   target="_blank">
                    <i class="fas fa-external-link-alt"></i>
                </a>
                <?php endif; ?>
            </div>

            <!-- Clusters -->
            <div class="d-flex flex-wrap gap-2 p-3">
            <?php foreach ($galaxy['GalaxyCluster'] as $cluster):
                $cValue    = h($cluster['value'] ?? '');
                $cDesc     = h($cluster['description'] ?? '');
                $cId       = (int)($cluster['id'] ?? 0);
                $isLocal   = !empty($cluster['local']);
                $relType   = $cluster['relationship_type'] ?? false;
                $tagId     = (int)($cluster['tag_id'] ?? 0);

                $bgColor   = "hsla({$hue},65%,55%,var(--galaxy-alpha,0.12))";
                $textColor = "hsl({$hue},65%,25%)";
                $border    = "hsl({$hue},55%,65%)";
                $metallic  = 'background-image:linear-gradient(145deg,'
                           . 'rgba(255,255,255,.18) 0%,rgba(255,255,255,.04) 40%,'
                           . 'rgba(0,0,0,.04) 100%)';
                $badgeStyle = "background-color:{$bgColor};color:{$textColor};"
                            . "border:1px solid {$border};{$metallic};"
                            . "white-space:normal;word-wrap:break-word;"
                            . "text-align:left;max-width:260px;";
            ?>
                <div data-cluster-item
                     data-cluster-name="<?= h(strtolower($cluster['value'] ?? '')) ?>">
                     <a style="cursor:pointer;"
                     href="<?= h($baseurl) ?>/galaxy_clusters/view/<?= $cId ?>">

                        <span class="badge p-2"
                            style="<?= $badgeStyle ?>"
                            <?= $cDesc ? 'title="' . $cDesc . '"' : '' ?>>

                            <div class="d-flex flex-column">

                                <?php if ($relType): ?>
                                <div class="mb-1">
                                    <span class="badge text-white me-1 bg-dark"
                                        style="font-size:.65rem;">
                                        <?= h($relType) ?>
                                    </span>
                                </div>
                                <?php endif; ?>

                                <div class="d-flex align-items-center gap-1">
                                    <?php if ($isLocal): ?>
                                        <i class="fas fa-user" title="<?= __('Local cluster') ?>"></i>
                                    <?php endif; ?>
                                    <span>
                                        <?= $cValue ?>
                                    </span>
                                </div>

                            </div>
                        </span>
                    </a>
                </div>
            <?php endforeach; ?>
            </div>

        </div>

    <?php endforeach; ?>

    </div>

    <!-- No-results message -->
    <div class="d-none text-center text-muted py-3 small"
         data-galaxy-noresult>
        <i class="fas fa-search me-1 opacity-50"></i>
        <?= __('No galaxy clusters match your search.') ?>
    </div>

<?php endif; ?>

</div>