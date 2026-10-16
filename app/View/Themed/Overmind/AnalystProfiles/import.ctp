<?php
/**
 * Somebody else's profile, as a copy of their judgement.
 *
 * Import is the sharing path and the second of the two ways in — the
 * other is a fork. A uuid that already exists locally is re-minted
 * rather than overwritten, and an import lands **disabled** when the
 * owner already holds an enabled profile: reviewing a profile before
 * adopting it should not change your own pages underneath you first.
 *
 * @var bool $can_import_for_org
 * @var bool $holds_enabled
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
));

$this->set('headerTitle', __('Import a profile'));
$this->set('headerBreadcrumb', array(
    array('label' => __('Analyst Profiles'),
        'url' => array('action' => 'index')),
    __('Import'),
));
$this->set('headerDescription', __('One JSON document, exported from an'
    . ' instance that already scores something.'));
?>
<div class="ap-page">
    <div class="container-fluid" style="max-width:52rem">
        <?= $this->Form->create('AnalystProfile', array(
            'url' => $this->Html->url(array('action' => 'import')),
            'type' => 'file',
        )) ?>
            <div class="wb-field">
                <label for="ap-import-json"><?= h(__('The document')) ?></label>
                <textarea class="form-control font-monospace" id="ap-import-json"
                          name="data[AnalystProfile][json]" rows="18"
                          spellcheck="false"
                          placeholder='{"name": "...", "parameters": {...}}'></textarea>
                <p class="help">
                    <?= h(__('An export carries name, description, uuid,'
                        . ' version and parameters. Only parameters is'
                        . ' required — without it there would be nothing to'
                        . ' score with.')) ?>
                </p>
            </div>

            <?php if ($can_import_for_org): ?>
                <div class="wb-field mt-2">
                    <label class="wb-inline">
                        <input class="form-check-input" type="checkbox"
                               name="data[AnalystProfile][for_org]" value="1">
                        <span><?= h(__('Import for my organisation')) ?></span>
                    </label>
                    <p class="help">
                        <?= h(__('An organisation profile applies to every'
                            . ' colleague who has not enabled one of their'
                            . ' own.')) ?>
                    </p>
                </div>
            <?php endif; ?>

            <div class="wb-note mt-2">
                <?= $holds_enabled
                    ? h(__('You already hold an enabled profile, so this one'
                        . ' arrives disabled. Simulate it, and enable it when'
                        . ' you have decided.'))
                    : h(__('You hold no enabled profile, so this one arrives'
                        . ' enabled and becomes the one in force.')) ?>
                <div class="wb-sub mt-1">
                    <?= h(__('A uuid that already exists here is re-minted,'
                        . ' never overwritten: an imported profile is a copy'
                        . ' of somebody else\'s judgement, and overwriting a'
                        . ' local row of the same uuid would silently rewrite'
                        . ' the profile your assessments have been naming.')) ?>
                </div>
            </div>

            <div class="wb-inline mt-3">
                <button type="submit" class="btn btn-primary">
                    <?= h(__('Import')) ?>
                </button>
                <a class="btn btn-outline-secondary"
                   href="<?= h($this->Html->url(array('action' => 'index'))) ?>">
                    <?= h(__('Cancel')) ?>
                </a>
            </div>
        <?= $this->Form->end() ?>
    </div>
</div>
