<?php
/**
 * Why a profile is, or is not, the one weighting this reader's pages.
 *
 * Kept to one short line each: MISP ships six profiles and most of them
 * stand *not chosen*, so any sentence here is printed once per row.
 *
 * A profile somebody owns is *in use* or *not in use*, the words the row
 * menu acts with. *Switched off* is kept for a shipped or shared profile
 * a site admin turned off, which nobody can then choose.
 *
 * @var array $profile A row from the index board
 */
$standing = $profile['standing'];
$state = $standing['state'];
$global = !empty($profile['default']) || !empty($profile['shared']);
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
    'disabled' => $global ? __('switched off') : __('not in use'),
    'overridden' => __('overridden'),
    'not_selected' => __('not chosen'),
    'other_owner' => __('another owner'),
    'unresolved' => __('unresolved'),
);
$selectedBy = isset($profile['selected_by'])
    ? $profile['selected_by']
    : array();
?>
<span class="pill <?= h(isset($tone[$state]) ? $tone[$state] : 't-plain') ?>">
    <?= h(isset($label[$state]) ? $label[$state] : $state) ?>
</span>
<?php // `not_selected` needs no line: the owner column and the pill already say it all. ?>
<?php if ($state !== 'not_selected'): ?>
<div class="wb-sub mt-1">
    <?php if ($state === 'in_force'): ?>
        <?php if (in_array('user', $selectedBy, true)): ?>
            <?= h(__('You chose it.')) ?>
        <?php elseif (in_array('org', $selectedBy, true)): ?>
            <?= h(__('Your organisation chose it.')) ?>
        <?php elseif (in_array('instance', $selectedBy, true)): ?>
            <?= h(__('This instance runs it.')) ?>
        <?php elseif ($profile['scope_rank'] === 2): ?>
            <?= h(__('Your organisation\'s own, in use.')) ?>
        <?php else: ?>
            <?= h(__('Your own, in use.')) ?>
        <?php endif; ?>
    <?php elseif ($state === 'disabled' && !empty($profile['default'])): ?>
        <?php // Only the row the instance names leaves readers with no answer unscored. ?>
        <?php if (in_array('instance', $selectedBy, true)): ?>
            <?= h(__('The one this instance names, switched off. A reader'
                . ' with no other answer is scored by nothing.')) ?>
        <?php else: ?>
            <?= h(__('MISP\'s own, switched off: nobody can choose it.')) ?>
        <?php endif; ?>
    <?php elseif ($state === 'disabled' && !empty($profile['shared'])): ?>
        <?= h(__('Shared, switched off: nobody can choose it.')) ?>
    <?php elseif ($state === 'disabled' && $profile['scope_rank'] === 3): ?>
        <?= h(__('Yours, kept but not in use.')) ?>
    <?php elseif ($state === 'disabled' && $profile['scope_rank'] === 2): ?>
        <?= h(__('Your organisation\'s, kept but not in use.')) ?>
    <?php elseif ($state === 'disabled'): ?>
        <?= h(__('Kept but not in use.')) ?>
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
        <?= h(__('In use and applies to you, yet nothing is in force —'
            . ' which resolution cannot produce. Reported rather than'
            . ' explained away.')) ?>
    <?php endif; ?>
</div>
<?php endif; ?>
