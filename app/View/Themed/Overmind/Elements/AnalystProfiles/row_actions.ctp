<?php
/**
 * One row's actions, all behind its menu: whom the profile scores first,
 * then what else can be done with it.
 *
 * A profile you own is used by switching it on and dropped by switching
 * it off; anybody else's is chosen and unchosen. The menu says *use* and
 * *stop using* either way, so a reader never has to know which of the two
 * mechanisms a row goes through.
 *
 * Every write opens its confirmation in #mainModal: the action answers an
 * ajax GET with the question (ask.ctp) and the modal's form posts it.
 *
 * @var array $profile A row from the index board
 * @var bool $may_select_for_org
 * @var bool $may_select_for_instance
 * @var bool $can_fork_for_org
 */
$chosenByMe = in_array('user', $profile['selected_by'], true);
$chosenByOrg = in_array('org', $profile['selected_by'], true);
$chosenByInstance = in_array('instance', $profile['selected_by'], true);
$ownedByMe = $profile['scope_rank'] === 3;
$ownedByOrg = $profile['scope_rank'] === 2 && $profile['editable'];

$item = 'dropdown-item justify-content-start';

$ask = function ($icon, $label, $url, $extra = '') use ($item) {
    $href = $this->Html->url($url);
    return '<a class="' . h(trim($item . ' ' . $extra)) . '" href="' . h($href)
        . '" onclick="' . h('event.preventDefault(); openModal('
            . json_encode($href) . ", 'md');") . '">'
        . '<i class="fas fa-' . h($icon) . ' me-2"></i>' . h($label) . '</a>';
};

$uses = array();
if ($ownedByMe) {
    $uses[] = $profile['enabled']
        ? $ask('user-xmark', __('Stop using for me'),
            array('action' => 'disable', $profile['id']))
        : $ask('user-check', __('Use for me'),
            array('action' => 'enable', $profile['id']));
} elseif ($chosenByMe) {
    $uses[] = $ask('user-xmark', __('Stop using for me'),
        array('action' => 'deselect', '?' => array('scope' => 'user')));
} elseif (!empty($profile['selectable'])) {
    $uses[] = $ask('user-check', __('Use for me'),
        array('action' => 'select', $profile['id'],
            '?' => array('scope' => 'user')));
}
if ($ownedByOrg) {
    $uses[] = $profile['enabled']
        ? $ask('building-circle-xmark', __('Stop using for my organisation'),
            array('action' => 'disable', $profile['id']))
        : $ask('building-circle-check', __('Use for my organisation'),
            array('action' => 'enable', $profile['id']));
} elseif ($chosenByOrg && $may_select_for_org) {
    $uses[] = $ask('building-circle-xmark', __('Stop using for my organisation'),
        array('action' => 'deselect', '?' => array('scope' => 'org')));
} elseif (!empty($profile['selectable_for_org'])) {
    $uses[] = $ask('building-circle-check', __('Use for my organisation'),
        array('action' => 'select', $profile['id'],
            '?' => array('scope' => 'org')));
}
// The instance always names a profile, so it is pointed elsewhere rather than stopped.
if ($may_select_for_instance && $chosenByInstance) {
    $uses[] = '<span class="' . $item . ' disabled"><i class="fas fa-server me-2">'
        . '</i>' . h(__('Runs on this instance')) . '</span>';
} elseif ($may_select_for_instance && !empty($profile['enabled'])
    && (!empty($profile['default']) || !empty($profile['shared']))
) {
    $uses[] = $ask('server', __('Run on this instance'),
        array('action' => 'select', $profile['id'],
            '?' => array('scope' => 'instance')));
}
?>
<div class="ap-acts" data-tour="ap-row-actions">
    <div class="dropdown">
        <button class="btn btn-sm p-1 row-menu-toggle ap-act-more" type="button"
                data-bs-toggle="dropdown" aria-expanded="false"
                title="<?= h(sprintf(__('More for %s'), $profile['name'])) ?>"
                aria-label="<?= h(sprintf(__('More for %s'), $profile['name'])) ?>">
            <i class="fa-solid fa-ellipsis-vertical"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end">
            <?php foreach ($uses as $use): ?>
                <li><?= $use ?></li>
            <?php endforeach; ?>
            <?php if (!empty($uses)): ?>
                <li><hr class="dropdown-divider"></li>
            <?php endif; ?>

            <li>
                <a class="<?= $item ?>" href="<?= h($this->Html->url(array(
                    'action' => 'view', $profile['id']))) ?>">
                    <i class="fas fa-eye me-2"></i><?= h(__('View')) ?></a>
            </li>
            <?php if ($profile['editable']): ?>
                <li>
                    <a class="<?= $item ?>" href="<?= h($this->Html->url(array(
                        'action' => 'edit', $profile['id']))) ?>">
                        <i class="fas fa-pen-to-square me-2"></i><?= h(
                            __('Edit')) ?></a>
                </li>
            <?php endif; ?>
            <li>
                <a class="<?= $item ?>" href="<?= h($this->Html->url(array(
                    'action' => 'simulate', $profile['id']))) ?>">
                    <i class="fas fa-flask me-2"></i><?= h(
                        __('Try it on a value')) ?></a>
            </li>
            <li>
                <a class="<?= $item ?>" href="<?= h($this->Html->url(array(
                    'action' => 'export', $profile['id']))) ?>">
                    <i class="fas fa-file-export me-2"></i><?= h(
                        __('Export JSON')) ?></a>
            </li>

            <?php if (!$profile['in_force'] || !empty($profile['default'])): ?>
                <li><hr class="dropdown-divider"></li>
                <li><?= $ask('code-branch', __('Fork to me'),
                    array('action' => 'fork', $profile['id'])) ?></li>
                <?php if ($can_fork_for_org): ?>
                    <li><?= $ask('code-branch', __('Fork to my organisation'),
                        array('action' => 'fork', $profile['id'],
                            '?' => array('for_org' => 1))) ?></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if (!empty($profile['can_share'])): ?>
                <li><hr class="dropdown-divider"></li>
                <li><?= empty($profile['shared'])
                    ? $ask('share-nodes', __('Share with everyone'),
                        array('action' => 'share', $profile['id']))
                    : $ask('share-nodes', __('Stop sharing'),
                        array('action' => 'unshare', $profile['id'])) ?></li>
            <?php endif; ?>

            <?php if ($profile['editable'] && empty($profile['default'])): ?>
                <li><hr class="dropdown-divider"></li>
                <li><?= $ask('trash', __('Delete'),
                    array('action' => 'delete', $profile['id']),
                    'text-danger') ?></li>
            <?php endif; ?>
        </ul>
    </div>
</div>
