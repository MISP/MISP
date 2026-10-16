<?php
$analysisDots = [
    'var(--misp-tone-blue-solid, #0d6efd)',
    'var(--misp-tone-orange-solid, #fd7e14)',
    'var(--misp-tone-green-solid, #198754)',
];
$noDot = 'var(--misp-tone-gray-solid, #adb5bd)';
$threatColors = [
    'High'      => 'var(--misp-tone-red-solid, #dc3545)',
    'Medium'    => 'var(--misp-tone-orange-solid, #fd7e14)',
    'Low'       => 'var(--misp-tone-yellow-solid, #ffc107)',
    'Undefined' => $noDot,
];

if (empty($event)):
    $msg = __('No matching event found.');
    if ($validUuid) {
        $msg .= ' ' . __('The UUID is valid and will extend the event once it becomes visible.');
    }
?>
<div class="d-flex align-items-start gap-2 p-2 rounded border mt-1"
     style="border-color:var(--misp-field-line, #d8dde3); font-size:.8rem;">
    <i class="fas fa-circle-exclamation text-warning mt-1"
       style="font-size:.75rem; flex-shrink:0;"></i>
    <span class="text-muted"><?= h($msg) ?></span>
</div>

<?php else:
    $eId        = $event['Event']['id'] ?? '';
    $eUuid      = $event['Event']['uuid'] ?? '';
    $eInfo      = $event['Event']['info'] ?? '';
    $eAnalysis  = (int)($event['Event']['analysis'] ?? 0);
    $eThreat    = $event['ThreatLevel']['name'] ?? '';
    $eTags      = $event['EventTag'] ?? [];
    $analysisDot   = $analysisDots[$eAnalysis] ?? $noDot;
    $analysisLabel = $analysisLevels[$eAnalysis] ?? '';
    $threatDot     = $threatColors[$eThreat] ?? $noDot;
?>
<div class="rounded border mt-2 overflow-hidden js-extends-event-card"
     data-extends-uuid="<?= h($eUuid) ?>"
     title="<?= h(__('Click to use this event\'s UUID')) ?>"
     style="border-color:var(--primary); font-size:.8rem; cursor:pointer;">

    <!-- Header -->
    <div class="d-flex align-items-center justify-content-between px-3 py-2"
         style="background:rgba(24,146,177,.07); border-bottom:1px solid rgba(24,146,177,.2);">
        <div class="d-flex align-items-center gap-2">
            <i class="fas fa-circle-check" style="color:var(--primary); font-size:.75rem;"></i>
            <span class="fw-semibold text-uppercase"
                  style="font-size:.6rem; letter-spacing:.08em; color:var(--primary);">
                <?= __('Matched Event') ?>
            </span>
        </div>
        <a href="<?= h($baseurl) ?>/events/view/<?= h($eId) ?>"
           class="d-flex align-items-center gap-1 text-decoration-none"
           style="font-size:.7rem; color:var(--primary);"
           target="_blank"
           onclick="event.stopPropagation();">
            <span class="fw-semibold">#<?= h($eId) ?></span>
            <i class="fas fa-arrow-up-right-from-square" style="font-size:.6rem;"></i>
        </a>
    </div>

    <!-- Body -->
    <div class="px-3 py-2 d-flex flex-column gap-2">

        <!-- Info -->
        <div class="fw-semibold" style="font-size:.825rem; line-height:1.35;
                                        color:var(--bs-body-color);">
            <?= h($eInfo) ?>
        </div>

        <!-- Analysis + Threat -->
        <div class="d-flex align-items-center gap-3" style="font-size:.75rem;">

            <div class="d-flex align-items-center gap-1">
                <span class="rounded-circle d-inline-block"
                      style="width:.45rem; height:.45rem;
                             background:<?= h($analysisDot) ?>;
                             flex-shrink:0;"></span>
                <span class="text-muted"><?= __('Analysis') ?>:</span>
                <span class="fw-semibold"><?= h($analysisLabel) ?></span>
            </div>

            <div class="d-flex align-items-center gap-1">
                <span class="rounded-circle d-inline-block"
                      style="width:.45rem; height:.45rem;
                             background:<?= h($threatDot) ?>;
                             flex-shrink:0;"></span>
                <span class="text-muted"><?= __('Threat') ?>:</span>
                <span class="fw-semibold"><?= h($eThreat) ?></span>
            </div>

        </div>

        <!-- Tags -->
        <?php if (!empty($eTags)):
            $maxVisible = 6;
            $shown      = array_slice($eTags, 0, $maxVisible);
            $overflow   = count($eTags) - $maxVisible;
        ?>
        <div class="d-flex flex-wrap gap-1 align-items-center">
            <?= $this->TagChip->collection($shown, ['searchUrl' => '']) ?>
            <?php if ($overflow > 0): ?>
            <span class="text-muted" style="font-size:.7rem;">
                +<?= $overflow ?> <?= __('more') ?>
            </span>
            <?php endif; ?>
        </div>
        <?php endif; ?>

    </div><!-- body -->
</div>
<?php endif; ?>
