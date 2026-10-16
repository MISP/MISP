<?php
/**
 * Resolve it — the first card in the rail.
 *
 * At the top because it is the only card on the page that asks the
 * reader to do something. Conflicted is a state to act on, not a score
 * to accept, and the argument beside it exists to inform this choice.
 *
 * Each option names the write it would perform rather than the verdict
 * it would assert. The write is the part somebody has to own, and a
 * card that hid it would be asking for a signature on a blank form.
 *
 * @var array $valueIntelligence
 * @var string $noWrites Why every control here is disabled
 */
$verdict = $valueIntelligence['verdict'];
$resolutions = $verdict['resolutions'] ?? array();
?>
<?php if (!empty($resolutions)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside vp-aside-conflict">

        <div class="vp-aside-head">
            <i class="fas fa-scale-unbalanced"></i>
            <span class="vp-aside-title"><?= __('Resolve it') ?></span>
        </div>

        <div class="p-3 d-flex flex-column gap-2">

            <p class="vp-resolve-intro">
                <?= __(
                    'Conflicted is a state to act on, not a score to'
                    . ' accept. Each option writes something different,'
                    . ' and each confirms first.'
                ) ?>
            </p>

            <?php foreach ($resolutions as $resolution): ?>
                <button type="button"
                        class="vp-resolution disabled"
                        disabled
                        title="<?= h($noWrites) ?>">
                    <span class="vp-resolution-head">
                        <i class="<?= h($resolution['icon']) ?>"
                           style="color: <?= h($resolution['colour']) ?>;">
                        </i>
                        <span class="vp-resolution-title">
                            <?= h($resolution['title']) ?>
                        </span>
                    </span>
                    <span class="vp-resolution-note">
                        <?= h($resolution['note']) ?>
                    </span>
                    <span class="vp-resolution-writes">
                        <?= h($resolution['writes']) ?>
                    </span>
                </button>
            <?php endforeach; ?>

        </div>

    </div>
<?php endif; ?>
