<?php
/**
 * One row's actions: the decision, and everything else behind a menu.
 *
 * The index used to lay nine buttons side by side in a 15% column, so
 * every one of them wrapped onto its own line and a row stood 260px
 * tall. Nine equal buttons are not nine choices — they are a reader
 * reading nine labels to find the one verb their row actually offers.
 *
 * So the cell answers one question in the open — *what do I press on
 * this row?* — and keeps the rest where rest belongs. The open button
 * is whichever of those verbs applies here, and never more than one:
 *
 *   selectable          Use this        (choose it; no fork, D45)
 *   chosen by me        Stop using
 *   mine and switched off   Enable
 *   otherwise           nothing
 *
 * Reading is not a decision, so View left the cell entirely — the
 * profile name is the link. Forking, exporting and simulating are
 * real, but they are things you go and do, not things this row is
 * asking about, and they sit in the menu.
 *
 * @var array $profile A row from the index board
 * @var array|null $in_force
 * @var bool $may_select_for_org
 * @var bool $may_select_for_instance
 * @var bool $can_fork_for_org
 */
$chosenByMe = in_array('user', $profile['selected_by'], true);
$chosenByOrg = in_array('org', $profile['selected_by'], true);
$chosenByInstance = in_array('instance', $profile['selected_by'], true);

$btn = 'btn btn-sm py-0 px-2 ap-act-primary';
$item = 'dropdown-item justify-content-start';

/*
 * The confirm on *Use this* carries the one thing a reader cannot see
 * from the row: choosing replaces what is scoring them now, and if
 * that was their own profile it is switched off rather than deleted.
 */
/*
 * A menu entry that posts. The icon has to reach `postLink()` inside
 * the title, which means turning escaping off, so the label is escaped
 * here instead — every caller passes a translated string and nothing
 * else.
 */
$post = function ($icon, $label, $url, $confirm = false, $extra = '')
    use ($item) {
    return $this->Form->postLink(
        '<i class="fas fa-' . $icon . ' me-2"></i>' . h($label),
        $url,
        array('class' => trim($item . ' ' . $extra), 'escape' => false),
        $confirm
    );
};

$useConfirm = ($in_force !== null && $in_force['name'] !== $profile['name'])
    ? sprintf(
        __('Score your pages with %1$s instead of %2$s? If %2$s is one'
            . ' you own it is switched off, not deleted.'),
        $profile['name'],
        $in_force['name']
    )
    : false;
?>
<div class="ap-acts" data-tour="ap-row-actions">
    <?php if (!empty($profile['selectable'])): ?>
        <?= $this->Form->postLink(
            __('Use this'),
            array('action' => 'select', $profile['id'],
                '?' => array('scope' => 'user')),
            array('class' => $btn . ' btn-primary'),
            $useConfirm
        ) ?>
    <?php elseif ($chosenByMe): ?>
        <?= $this->Form->postLink(
            __('Stop using'),
            array('action' => 'deselect', '?' => array('scope' => 'user')),
            array('class' => $btn . ' btn-outline-secondary')
        ) ?>
    <?php elseif ($profile['editable'] && !$profile['enabled']): ?>
        <?= $this->Form->postLink(
            __('Enable'),
            array('action' => 'enable', $profile['id']),
            array('class' => $btn . ' btn-outline-primary'),
            $in_force === null || !empty($profile['shared']) ? false : sprintf(
                __('You may hold one enabled profile, so enabling this'
                    . ' one switches %s off. Nothing is deleted.'),
                $in_force['name']
            )
        ) ?>
    <?php endif; ?>

    <div class="dropdown">
        <button class="btn btn-sm p-1 row-menu-toggle ap-act-more" type="button"
                data-bs-toggle="dropdown" aria-expanded="false"
                title="<?= h(sprintf(__('More for %s'), $profile['name'])) ?>">
            <i class="fa-solid fa-ellipsis-vertical"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end">
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

            <?php
            /*
             * Choosing for somebody other than yourself. Same verb as
             * the open button, a wider blast radius, and therefore a
             * confirm naming who it lands on.
             */
            $wider = ($chosenByOrg && $may_select_for_org)
                || !empty($profile['selectable_for_org'])
                || ($may_select_for_instance
                    && (!empty($profile['default']) || !empty($profile['shared']))
                    && !$chosenByInstance && !empty($profile['enabled']));
            ?>
            <?php if ($wider): ?>
                <li><hr class="dropdown-divider"></li>
                <?php if ($chosenByOrg && $may_select_for_org): ?>
                    <li><?= $post(
                        'building',
                        __('Stop using for my organisation'),
                        array('action' => 'deselect',
                            '?' => array('scope' => 'org'))
                    ) ?></li>
                <?php elseif (!empty($profile['selectable_for_org'])): ?>
                    <li><?= $post(
                        'building',
                        __('Use for my organisation'),
                        array('action' => 'select', $profile['id'],
                            '?' => array('scope' => 'org')),
                        sprintf(
                            __('Score your organisation with %s? It applies'
                                . ' to every colleague who has not chosen or'
                                . ' forked one of their own.'),
                            $profile['name']
                        )
                    ) ?></li>
                <?php endif; ?>
                <?php if ($may_select_for_instance
                    && (!empty($profile['default']) || !empty($profile['shared']))
                    && !$chosenByInstance
                    && !empty($profile['enabled'])): ?>
                    <li><?= $post(
                        'server',
                        __('Run on this instance'),
                        array('action' => 'select', $profile['id'],
                            '?' => array('scope' => 'instance')),
                        sprintf(
                            __('Score this instance with %s? It applies to'
                                . ' every reader whose organisation and'
                                . ' account have chosen none.'),
                            $profile['name']
                        )
                    ) ?></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if (!$profile['in_force'] || !empty($profile['default'])): ?>
                <li><hr class="dropdown-divider"></li>
                <li><?= $post(
                    'code-branch',
                    __('Fork to me'),
                    array('action' => 'fork', $profile['id'])
                ) ?></li>
                <?php if ($can_fork_for_org): ?>
                    <li><?= $post(
                        'code-branch',
                        __('Fork to my organisation'),
                        array('action' => 'fork', $profile['id'],
                            '?' => array('for_org' => 1))
                    ) ?></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if (!empty($profile['can_share'])): ?>
                <li><hr class="dropdown-divider"></li>
                <?php if (empty($profile['shared'])): ?>
                    <li><?= $post(
                        'share-nodes',
                        __('Share with everyone'),
                        array('action' => 'share', $profile['id']),
                        sprintf(
                            __('Share %s? Every user can read, fork and'
                                . ' select it, and your edits reach everyone'
                                . ' who selected it. It stops being your own'
                                . ' profile.'),
                            $profile['name']
                        )
                    ) ?></li>
                <?php else: ?>
                    <li><?= $post(
                        'share-nodes',
                        __('Stop sharing'),
                        array('action' => 'unshare', $profile['id']),
                        sprintf(
                            __('Stop sharing %s? Readers who selected it fall'
                                . ' back to their next profile, and it comes'
                                . ' back to you disabled.'),
                            $profile['name']
                        )
                    ) ?></li>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($profile['editable'] && empty($profile['default'])): ?>
                <li><hr class="dropdown-divider"></li>
                <?php if ($profile['enabled']): ?>
                    <li><?= $post(
                        'power-off',
                        __('Switch off'),
                        array('action' => 'disable', $profile['id'])
                    ) ?></li>
                <?php endif; ?>
                <li><?= $post(
                    'trash',
                    __('Delete'),
                    array('action' => 'delete', $profile['id']),
                    sprintf(
                        __('Delete %s? A profile is a tuned judgement and'
                            . ' this cannot be undone. Switching it off'
                            . ' keeps it.'),
                        $profile['name']
                    ),
                    'text-danger'
                ) ?></li>
            <?php endif; ?>
        </ul>
    </div>
</div>
