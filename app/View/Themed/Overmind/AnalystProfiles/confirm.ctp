<?php
/**
 * A write that stopped to ask, with the consequence named.
 *
 * Two of them exist and both are refusals to act silently rather than
 * failures: a fork into an occupied slot, and the one-enabled swap.
 * **Replace disables; it never deletes** — a profile is somebody's
 * tuned judgement and a one-click flow must not be able to destroy it.
 *
 * @var string $confirm
 * @var array $existing
 * @var array|null $affects
 * @var string $message
 * @var array $form `title`, `url`, `fields`, `confirm_label`, `cancel`
 */
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
            <?php if (!empty($affects)): ?>
                <p class="mb-2">
                    <?= h(sprintf(
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
                    )) ?>
                </p>
            <?php endif; ?>

            <?= $this->Form->create('AnalystProfile', array(
                'url' => $this->Html->url($form['url']),
                'class' => 'wb-inline',
            )) ?>
                <?php foreach ($form['fields'] as $field => $value): ?>
                    <input type="hidden" name="data[AnalystProfile][<?= h($field) ?>]"
                           value="<?= h($value) ?>">
                <?php endforeach; ?>
                <button type="submit" class="btn btn-sm btn-primary py-0 px-2">
                    <?= h($form['confirm_label']) ?>
                </button>
                <a class="btn btn-sm btn-outline-secondary py-0 px-2"
                   href="<?= h($this->Html->url($form['cancel'])) ?>">
                    <?= h(__('Cancel')) ?>
                </a>
            <?= $this->Form->end() ?>

            <p class="wb-sub mt-2 mb-0">
                <?= h(sprintf(
                    __('Replace disables, never deletes — %s and its history'
                        . ' stay, and re-enabling it is one press. The fork'
                        . ' itself gets a new uuid, its counters reset, and no'
                        . ' lineage: its description is rewritten to say where'
                        . ' it came from, which is the only provenance a fork'
                        . ' has.'),
                    $existing['name']
                )) ?>
            </p>
        </div>
    </div>
</div>
