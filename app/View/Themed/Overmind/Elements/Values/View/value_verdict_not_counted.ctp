<?php
/**
 * What the profile deliberately set aside.
 *
 * A signal silently dropped looks the same as a signal nobody found, so
 * the exclusions are listed with the reason for each. Distinct from the
 * unresolved band in the argument card: those are splits that could
 * still fall either way, these were never going to count.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$verdict = $valueIntelligence['verdict'];
$notCounted = $verdict['not_counted'] ?? array();

/*
 * A `policy` entry is the analyst's own decision, so it is the one
 * kind that can say where the decision lives — turning *"why doesn't
 * this count?"* into a click. The link needs the profile that made the
 * call, so it appears only when the assessment names one.
 */
$profileId = $verdict['profile_id'] ?? null;
$valueB64 = $valueB64 ?? null;
?>
<?php if (!empty($notCounted)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside">

        <div class="vp-aside-head">
            <i class="fas fa-eye-slash"
               style="color: var(--bs-secondary-color);"></i>
            <span class="vp-aside-title"><?= __('Not counted') ?></span>
        </div>

        <div class="p-3 d-flex flex-column vp-notcounted">
            <?php foreach ($notCounted as $item): ?>
                <div class="vp-notcounted-item">
                    <strong><?= h($item['title']) ?></strong>
                    — <?= h($item['note']) ?>
                    <?php if ($profileId !== null
                        && ($item['reason'] ?? null) === 'policy'): ?>
                        <a href="<?= h($this->Html->url(array(
                            'controller' => 'analystProfiles',
                            'action' => 'view',
                            $profileId,
                            '?' => $valueB64 === null
                                ? array('section' => 'exclusions')
                                : array(
                                    'section' => 'exclusions',
                                    'value' => $valueB64,
                                ),
                        ))) ?>"><?= h(__('the rule that set it aside')) ?></a>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>

    </div>
<?php endif; ?>
