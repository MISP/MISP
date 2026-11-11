<?php
/**
 * Server-rendered decay curve preview (Polynomial formula).
 * score(x) = 100 * (1 - (x/lifetime)^(1/decay_speed)); clamped to 0 below the
 * cutoff threshold. Rendered as inline SVG — no client JS needed.
 */
$dm = $data['DecayingModel'];
$p = $dm['parameters'] ?? [];
$lifetime = isset($p['lifetime']) ? (float)$p['lifetime'] : 0;
$decay = isset($p['decay_speed']) ? (float)$p['decay_speed'] : 0;
$threshold = isset($p['threshold']) ? (float)$p['threshold'] : 0;
$canPlot = $lifetime > 0 && $decay > 0;

// Full parameters JSON, copied to clipboard from the card header.
$paramsForCopy = $p;
if (isset($paramsForCopy['base_score_config']) && empty($paramsForCopy['base_score_config'])) {
    $paramsForCopy['base_score_config'] = new stdClass();
}
if (isset($paramsForCopy['settings']) && empty($paramsForCopy['settings'])) {
    $paramsForCopy['settings'] = new stdClass();
}
$paramsJson = json_encode($paramsForCopy, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

$daysToText = function ($days) {
    if (!is_finite($days) || $days < 0) {
        return '—';
    }
    $whole = (int)floor($days);
    $hours = (int)round(($days - $whole) * 24);
    $t = $whole . ' ' . ($whole === 1 ? __('day') : __('days'));
    if ($hours > 0) {
        $t .= ' ' . $hours . ' ' . ($hours === 1 ? __('hour') : __('hours'));
    }
    return $t;
};
$reverseScore = function ($y) use ($lifetime, $decay) {
    return $lifetime * pow(1 - ($y / 100), $decay);
};
?>

<div class="card shadow-sm mb-3" id="collections-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#7f24a340;">
                <i class="fas fa-wave-square" style="color: #7f24a3; font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Decay curve') ?></div>
            </div>
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-json="<?= h($paramsJson) ?>"
                    onclick="copyValueToClipboard(this.dataset.json, '<?= h(__('Parameters JSON copied to clipboard')) ?>');"
                    title="<?= h($paramsJson) ?>">
                <i class="fas fa-copy me-1"></i><?= __('Copy parameters') ?>
            </button>
        </div>
    </div>
    <div class="card-body">
        <?php if (!$canPlot): ?>
            <div class="alert alert-light border mb-0">
                <i class="fas fa-circle-info me-1"></i>
                <?= __('No polynomial curve to preview for this formula/parameters.') ?>
            </div>
        <?php else:
            $W = 720; $H = 320; $ml = 46; $mr = 16; $mt = 16; $mb = 40;
            $pw = $W - $ml - $mr; $ph = $H - $mt - $mb;
            $mapX = function ($day) use ($ml, $pw, $lifetime) { return $ml + ($lifetime > 0 ? $day / $lifetime : 0) * $pw; };
            $mapY = function ($score) use ($mt, $ph) { return $mt + (1 - $score / 100) * $ph; };
            $N = 120;
            $pts = [];
            for ($i = 0; $i <= $N; $i++) {
                $day = ($lifetime / $N) * $i;
                $s = 100 * (1 - pow($day / $lifetime, 1 / $decay));
                if (!is_finite($s) || $s < 0) { $s = 0; }
                if ($s < $threshold) { $s = 0; }
                $pts[] = [$mapX($day), $mapY($s)];
            }
            $line = '';
            foreach ($pts as $i => $pt) {
                $line .= ($i ? 'L' : 'M') . round($pt[0], 1) . ' ' . round($pt[1], 1) . ' ';
            }
            $area = $line . 'L' . round($mapX($lifetime), 1) . ' ' . round($mapY(0), 1)
                . ' L' . round($mapX(0), 1) . ' ' . round($mapY(0), 1) . ' Z';
            $expiry = $reverseScore($threshold);
            $half = $reverseScore((100 + $threshold) / 2);
            $thy = $mapY($threshold);
        ?>
            <div class="border rounded p-2 bg-body mb-3" style="overflow-x:auto;">
                <svg viewBox="0 0 <?= $W ?> <?= $H ?>" style="width:100%; height:auto; display:block;" role="img"
                     aria-label="<?= h(__('Decay curve')) ?>">
                    <?php
                        foreach ([0, 25, 50, 75, 100] as $sc) {
                            $y = round($mapY($sc), 1);
                            echo '<line x1="' . $ml . '" y1="' . $y . '" x2="' . ($ml + $pw) . '" y2="' . $y . '" stroke="var(--bs-border-color)" stroke-width="1"/>';
                            echo '<text x="' . ($ml - 8) . '" y="' . ($y + 3) . '" text-anchor="end" fill="var(--bs-secondary-color)" font-size="11">' . $sc . '</text>';
                        }
                        for ($f = 0; $f <= 4; $f++) {
                            $x = round($ml + ($pw / 4) * $f, 1);
                            $dayLabel = (int)round(($lifetime / 4) * $f);
                            echo '<line x1="' . $x . '" y1="' . $mt . '" x2="' . $x . '" y2="' . ($mt + $ph) . '" stroke="var(--bs-border-color)" stroke-width="1"/>';
                            echo '<text x="' . $x . '" y="' . ($mt + $ph + 16) . '" text-anchor="middle" fill="var(--bs-secondary-color)" font-size="11">' . $dayLabel . '</text>';
                        }
                        // markers
                        foreach ([[$half, __('half-life')], [$expiry, __('expiry')]] as $m) {
                            if ($m[0] > 0 && $m[0] <= $lifetime) {
                                $mx = round($mapX($m[0]), 1);
                                echo '<line x1="' . $mx . '" y1="' . $mt . '" x2="' . $mx . '" y2="' . ($mt + $ph) . '" stroke="var(--bs-secondary-color)" stroke-width="1" stroke-dasharray="3 3"/>';
                                echo '<text x="' . $mx . '" y="' . ($mt + 12) . '" text-anchor="middle" fill="var(--bs-body-color)" font-size="10" font-weight="600">' . h($m[1]) . '</text>';
                            }
                        }
                    ?>
                    <path d="<?= h($area) ?>" fill="var(--bs-primary)" opacity="0.12"/>
                    <path d="<?= h($line) ?>" fill="none" stroke="var(--bs-primary)" stroke-width="2.5" stroke-linejoin="round"/>
                    <line x1="<?= $ml ?>" y1="<?= round($thy, 1) ?>" x2="<?= $ml + $pw ?>" y2="<?= round($thy, 1) ?>"
                          stroke="var(--bs-danger)" stroke-width="1.5" stroke-dasharray="5 4"/>
                    <text x="<?= $ml + $pw ?>" y="<?= round($thy - 4, 1) ?>" text-anchor="end" fill="var(--bs-danger)" font-size="10" font-weight="600">
                        <?= __('cutoff') ?> <?= (int)$threshold ?>
                    </text>
                    <text x="<?= $ml + $pw / 2 ?>" y="<?= $H - 4 ?>" text-anchor="middle" fill="var(--bs-secondary-color)" font-size="11"><?= __('Days') ?></text>
                    <text transform="translate(12 <?= $mt + $ph / 2 ?>) rotate(-90)" text-anchor="middle" fill="var(--bs-secondary-color)" font-size="11"><?= __('Score') ?></text>
                </svg>
            </div>

            <div class="row g-2">
                <div class="col-sm-4">
                    <div class="border rounded p-2 h-100">
                        <div class="text-uppercase text-secondary fw-semibold" style="font-size:.62rem; letter-spacing:.06em;"><?= __('Decay speed') ?></div>
                        <div class="fw-bold"><?= h($decay) ?></div>
                    </div>
                </div>
                <div class="col-sm-4">
                    <div class="border rounded p-2 h-100">
                        <div class="text-uppercase text-secondary fw-semibold" style="font-size:.62rem; letter-spacing:.06em;"><?= __('Score halved after') ?></div>
                        <div class="fw-bold"><?= h($daysToText($half)) ?></div>
                    </div>
                </div>
                <div class="col-sm-4">
                    <div class="border rounded p-2 h-100">
                        <div class="text-uppercase text-secondary fw-semibold" style="font-size:.62rem; letter-spacing:.06em;"><?= __('Expires after') ?></div>
                        <div class="fw-bold"><?= h($daysToText($expiry)) ?></div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>
