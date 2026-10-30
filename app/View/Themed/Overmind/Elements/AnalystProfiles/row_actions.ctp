<?php
/**
 * One row's actions, all behind its menu: whom the profile scores first,
 * then what else can be done with it. The writes come from
 * ProfileActionsTool, which the profile view's action card shares.
 *
 * Every write opens its confirmation in #mainModal: the action answers an
 * ajax GET with the question (ask.ctp) and the modal's form posts it.
 *
 * @var array $profile A row from the index board
 * @var bool $may_select_for_org
 * @var bool $may_select_for_instance
 * @var bool $can_fork_for_org
 */
App::uses('ProfileActionsTool', 'Tools/AnalystProfile');

$writes = ProfileActionsTool::writes($profile, array(
    'org' => $may_select_for_org,
    'instance' => $may_select_for_instance,
    'fork_org' => $can_fork_for_org,
));
$item = 'dropdown-item justify-content-start';

$entry = function (array $write, $extra = '') use ($item) {
    $glyph = '<i class="fas fa-' . h($write['icon']) . ' me-2"></i>'
        . h($write['label']);
    if ($write['disabled']) {
        return '<span class="' . $item . ' disabled">' . $glyph . '</span>';
    }
    $href = $this->Html->url($write['url']);
    return '<a class="' . h(trim($item . ' ' . $extra)) . '" href="' . h($href)
        . '" onclick="' . h('event.preventDefault(); openModal('
            . json_encode($href) . ", 'md');") . '">' . $glyph . '</a>';
};
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
            <?php foreach ($writes['use'] as $write): ?>
                <li><?= $entry($write) ?></li>
            <?php endforeach; ?>
            <?php if (!empty($writes['use'])): ?>
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

            <?php foreach (array('fork', 'share', 'delete') as $group): ?>
                <?php if (!empty($writes[$group])): ?>
                    <li><hr class="dropdown-divider"></li>
                    <?php foreach ($writes[$group] as $write): ?>
                        <li><?= $entry($write,
                            $group === 'delete' ? 'text-danger' : '') ?></li>
                    <?php endforeach; ?>
                <?php endif; ?>
            <?php endforeach; ?>
        </ul>
    </div>
</div>
