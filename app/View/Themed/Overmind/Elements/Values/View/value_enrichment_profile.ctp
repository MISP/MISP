<?php
/**
 * The Analyst Profile's part in the Enrichment tab, in two pieces:
 *
 *   part 'pill'    the header pill: the profile's name and how many modules
 *                  it preselects (and runs on its own); a toggle for the
 *                  detail when there is one
 *   part 'detail'  a collapse under the header: what the profile did here,
 *                  and every condition on it; the modules an administrator
 *                  turned off only with $withDisabled, as the module list
 *                  names them otherwise
 *
 * Nothing at all when no profile is in force.
 *
 * @var array $enrichment
 * @var string $part pill or detail
 * @var string $detailId the collapse's id
 */
$declaration = isset($enrichment['profile']) ? $enrichment['profile'] : array();
if (empty($declaration['in_force'])) {
    return;
}
$selected = count($declaration['selected']);
$applicable = (int)$declaration['applicable'];
$declared = (int)$declaration['declared'];

$firing = 0;
$reusing = 0;
foreach (isset($declaration['auto']) && is_array($declaration['auto']) ? $declaration['auto'] : array() as $one) {
    if ($one['disposition'] === 'fire' || $one['disposition'] === 'in_flight') {
        $firing++;
    } elseif ($one['disposition'] === 'fresh') {
        $reusing++;
    }
}

$withDisabled = !empty($withDisabled);
$conditions = array_values(array_filter(
    isset($declaration['conditions']) ? $declaration['conditions'] : array(),
    function ($condition) use ($withDisabled) {
        return $withDisabled || $condition['id'] !== 'module.disabled';
    }
));

if ($applicable === 0) {
    $headline = sprintf(__n(
        'Your profile names %d module, and none of them for what this value is.',
        'Your profile names %d modules, and none of them for what this value is.',
        $declared
    ), $declared);
} elseif ($selected === $applicable) {
    $headline = sprintf(__n(
        'It preselects the %d module it names for this value\'s types.',
        'It preselects all %d modules it names for this value\'s types.',
        $applicable
    ), $applicable);
} else {
    $headline = sprintf(
        __('It preselects %1$d of the %2$d modules it names for this value\'s types.'),
        $selected,
        $applicable
    );
}
if ($firing > 0) {
    $note = sprintf(__n(
        '%d of them runs on its own: it is being asked now, because your profile says so and this instance allows it.',
        '%d of them run on their own: they are being asked now, because your profile says so and this instance allows it.',
        $firing
    ), $firing);
} elseif ($reusing > 0) {
    $note = sprintf(__n(
        '%d of them runs on its own and was asked recently: its kept answer is shown, nothing was sent this visit.',
        '%d of them run on their own and were asked recently: their kept answers are shown, nothing was sent this visit.',
        $reusing
    ), $reusing);
} else {
    $note = __('Nothing runs until you press Run: a preselection only ticks the boxes.');
}

$name = empty($declaration['name']) ? __('your Analyst Profile') : $declaration['name'];

if ($part === 'pill'):
    $facts = array(sprintf(__n('preselects %d', 'preselects %d', $selected), $selected));
    if ($firing > 0) {
        $facts[] = sprintf(__n('runs %d on its own', 'runs %d on their own', $firing), $firing);
    }
    ?>
    <button type="button" class="vp-e-ppill" data-bs-toggle="collapse" data-bs-target="#<?= h($detailId) ?>"
            aria-expanded="false" aria-controls="<?= h($detailId) ?>" title="<?= h($headline . ' ' . $note) ?>">
        <i class="fas fa-user-gear" aria-hidden="true"></i>
        <span><?= h(sprintf(__('Profile: %s'), $name)) ?></span>
        <span class="vp-e-ppill-facts"><?= h(implode(' · ', $facts)) ?></span>
        <i class="fas fa-chevron-down vp-e-ppill-caret" aria-hidden="true"></i>
    </button>
<?php else: ?>
    <?php
    $icons = array(
        'service.unreachable' => 'fa-plug-circle-xmark',
        'module.disabled' => 'fa-toggle-off',
        'module.not_offered' => 'fa-circle-question',
        'module.restricted' => 'fa-building-lock',
        'module.type_mismatch' => 'fa-shuffle',
        'module.unresolved' => 'fa-circle-question',
        'type.unused' => 'fa-filter-circle-xmark',
        'state.never' => 'fa-ban',
        'state.auto_disabled' => 'fa-hand-pointer',
        'state.auto_site_admin' => 'fa-user-shield',
    );
    ?>
    <div class="collapse" id="<?= h($detailId) ?>">
        <div class="vp-e-pdetail">
            <p class="vp-e-pdetail-lead"><?= h($headline) ?> <?= h($note) ?></p>
            <?php if (!empty($conditions)): ?>
                <ul class="vp-e-pdetail-conds">
                    <?php foreach ($conditions as $condition): ?>
                        <li>
                            <i class="fas <?= h(isset($icons[$condition['id']]) ? $icons[$condition['id']] : 'fa-circle-info') ?>" aria-hidden="true"></i>
                            <span>
                                <?php if (!empty($condition['module'])): ?>
                                    <span class="font-monospace fw-semibold"><?= h($condition['module']) ?></span> &mdash;
                                <?php endif; ?>
                                <?= h($condition['note']) ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>
