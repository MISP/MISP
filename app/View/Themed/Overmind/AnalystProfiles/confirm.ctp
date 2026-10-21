<?php
/**
 * A write that stopped to ask, with the consequence named.
 *
 * Two of them exist and both are refusals to act silently rather than
 * failures: a fork into an occupied slot, and the one-enabled swap.
 * **Replace disables; it never deletes** — a profile is somebody's
 * tuned judgement and a one-click flow must not be able to destroy it.
 *
 * Posted from the page, it is a page; posted from a header action with
 * `modal`, it is the content of #mainModal.
 *
 * @var string $confirm
 * @var array $existing
 * @var array|null $affects
 * @var string $message
 * @var array $form `title`, `url`, `fields`, `confirm_label`, `cancel`
 * @var bool $ajax
 */
$affectsText = empty($affects) ? null : sprintf(
    __n(
        'It would change how values are scored for %1$s of'
            . ' the %2$s people in your organisation — the'
            . ' ones who have not enabled a profile of'
            . ' their own.',
        'It would change how values are scored for %1$s of'
            . ' the %2$s people in your organisation — the'
            . ' ones who have not enabled a profile of'
            . ' their own.',
        $affects['affected']
    ),
    $affects['affected'],
    $affects['users']
);
$note = sprintf(
    __('Replace disables, never deletes — %s and its history'
        . ' stay, and re-enabling it is one press. The fork'
        . ' itself gets a new uuid, its counters reset, and no'
        . ' lineage: its description is rewritten to say where'
        . ' it came from, which is the only provenance a fork'
        . ' has.'),
    $existing['name']
);

// Through FormHelper, so the fields are part of the `_Token` hash.
$formOpen = $this->Form->create('AnalystProfile', array(
    'url' => $this->Html->url($form['url']),
    'class' => empty($ajax) ? 'wb-inline' : 'm-0',
));
foreach ($form['fields'] as $field => $value) {
    $formOpen .= $this->Form->hidden($field, array('value' => $value));
}
?>
<?php if (!empty($ajax)): ?>
    <?= $formOpen ?>
    <?= $this->element('genericElementsBS5/Forms/modal_header', array(
        'eyebrow' => __('Analyst Profiles'),
        'title' => $form['title'],
        'description' => __('Nothing has been written yet.'),
        'titleIcon' => 'fas fa-code-branch',
        'icon' => 'fas fa-code-branch',
        'accent' => 'warning',
    )) ?>
    <div class="px-4 py-4">
        <p class="mb-2"><?= h($message) ?></p>
        <?php if ($affectsText !== null): ?>
            <p class="mb-2"><?= h($affectsText) ?></p>
        <?php endif; ?>
        <p class="small text-body-secondary mb-0"><?= h($note) ?></p>
    </div>
    <?= $this->element('genericElementsBS5/Forms/modal_footer', array(
        'align' => 'end',
        'bleed' => true,
        'accent' => 'warning',
        'cancel' => array('label' => __('Cancel')),
        'submit' => array(
            'label' => $form['confirm_label'],
            'icon' => 'fas fa-code-branch',
        ),
    )) ?>
    <?= $this->Form->end() ?>
<?php else: ?>
<?php
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
));

$this->set('headerTitle', $form['title']);
$this->set('headerBreadcrumb', array(
    array('label' => __('Analyst Profiles'),
        'url' => array('action' => 'index')),
    $form['title'],
));
$this->set('headerDescription', __('Nothing has been written yet.'));
?>
<div class="ap-page">
    <div class="container-fluid">
        <div class="wb-confirm" style="max-width:44rem">
            <div class="wb-confirm-head">
                <i class="fas fa-code-branch"></i>
                <span><?= h($form['title']) ?></span>
            </div>
            <p class="mb-2"><?= h($message) ?></p>
            <?php if ($affectsText !== null): ?>
                <p class="mb-2"><?= h($affectsText) ?></p>
            <?php endif; ?>

            <?= $formOpen ?>
                <button type="submit" class="btn btn-sm btn-primary py-0 px-2">
                    <?= h($form['confirm_label']) ?>
                </button>
                <a class="btn btn-sm btn-outline-secondary py-0 px-2"
                   href="<?= h($this->Html->url($form['cancel'])) ?>">
                    <?= h(__('Cancel')) ?>
                </a>
            <?= $this->Form->end() ?>

            <p class="wb-sub mt-2 mb-0"><?= h($note) ?></p>
        </div>
    </div>
</div>
<?php endif; ?>
