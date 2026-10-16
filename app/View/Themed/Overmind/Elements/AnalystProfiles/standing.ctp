<?php
/**
 * Why a profile is, or is not, the one weighting this reader's pages.
 *
 * A badge on one row cannot say *why* the fork you are editing is not
 * the one scoring you. A per-row standing can, and the model computes
 * it rather than the page inferring it.
 *
 * It is kept to one short line each. MISP ships six profiles and five
 * of them stand *not chosen*, so any sentence here is printed five
 * times down the page: a paragraph explaining what choosing means
 * becomes a wall the reader learns to skip, and the explanation itself
 * belongs where it is said once — the rail — or where it is acted on —
 * the confirm on *Use this*.
 *
 * @var array $profile A row from the index board
 */
$standing = $profile['standing'];
$state = $standing['state'];
$tone = array(
    'in_force' => 't-force',
    'disabled' => 't-off',
    'overridden' => 't-over',
    'not_selected' => 't-plain',
    'other_owner' => 't-plain',
    'unresolved' => 't-missing',
);
$label = array(
    'in_force' => __('in force'),
    'disabled' => __('switched off'),
    'overridden' => __('overridden'),
    'not_selected' => __('not chosen'),
    'other_owner' => __('another owner'),
    'unresolved' => __('unresolved'),
);
/*
 * Which scopes point at this row (D45). A shipped profile that nobody
 * has chosen is switched on and doing nothing, and *not chosen* is a
 * different sentence from *overridden* — one of them names something a
 * reader can do about it.
 */
$selectedBy = isset($profile['selected_by'])
    ? $profile['selected_by']
    : array();
?>
<span class="pill <?= h(isset($tone[$state]) ? $tone[$state] : 't-plain') ?>">
    <?= h(isset($label[$state]) ? $label[$state] : $state) ?>
</span>
<?php
/*
 * `not_selected` gets the pill and nothing else. It is the standing of
 * five of the six rows MISP ships, so any sentence here is printed five
 * times — and every word it could carry is already on the row: the
 * owner column says *Shipped by MISP*, the pill says *not chosen*, and
 * the button beside it says *Use this*.
 */
?>
<?php if ($state !== 'not_selected'): ?>
<div class="wb-sub mt-1">
    <?php if ($state === 'in_force'): ?>
        <?php if (in_array('user', $selectedBy, true)): ?>
            <?= h(__('You chose it.')) ?>
        <?php elseif (in_array('org', $selectedBy, true)): ?>
            <?= h(__('Your organisation chose it.')) ?>
        <?php elseif (in_array('instance', $selectedBy, true)): ?>
            <?= h(__('This instance runs it.')) ?>
        <?php else: ?>
            <?= h(__('Yours, and switched on.')) ?>
        <?php endif; ?>
    <?php elseif ($state === 'disabled' && !empty($profile['default'])): ?>
        <?php
        /*
         * Tested before `editable`, which a site admin has on every
         * shipped profile: *yours* would be wrong on the row a site
         * admin is most likely to be reading, and wrong in the one
         * direction that matters — it is MISP's, and switching it off
         * stops scoring for everybody who has chosen nothing.
         */
        ?>
        <?php
        /*
         * The consequence holds only where this row is the one the
         * instance names. A shipped profile nobody named can be off
         * and cost nothing, and *nothing is scored while it is off* is
         * simply false beside an organisation that chose another.
         */
        ?>
        <?php if (in_array('instance', $selectedBy, true)): ?>
            <?= h(__('The one this instance names, switched off. A reader'
                . ' with no other answer is scored by nothing.')) ?>
        <?php else: ?>
            <?= h(__('MISP\'s own, and switched off.')) ?>
        <?php endif; ?>
    <?php elseif ($state === 'disabled' && $profile['editable']): ?>
        <?= h(__('Yours, weighting nothing.')) ?>
    <?php elseif ($state === 'disabled'): ?>
        <?= h(__('Your organisation\'s, weighting nothing.')) ?>
    <?php elseif ($state === 'overridden'): ?>
        <?= h(__('Beaten for you by')) ?>
        <?php if (!empty($standing['winner'])): ?>
            <a class="fw-semibold"
               href="<?= h($this->Html->url(array(
                   'action' => 'view', $standing['winner']['id']))) ?>">
                <?= h($standing['winner']['name']) ?></a>.
        <?php else: ?>
            <?= h(__('a nearer profile.')) ?>
        <?php endif; ?>
        <?php if (in_array('instance', $selectedBy, true)
            || in_array('org', $selectedBy, true)): ?>
            <?= h(__('It still scores colleagues who have chosen nothing.')) ?>
        <?php endif; ?>
    <?php elseif ($state === 'other_owner'): ?>
        <?= h(__('Somebody else\'s; you see it because you administer this'
            . ' instance.')) ?>
    <?php else: ?>
        <?= h(__('Switched on and applies to you, yet nothing is in force —'
            . ' which resolution cannot produce. Reported rather than'
            . ' explained away.')) ?>
    <?php endif; ?>
</div>
<?php endif; ?>
