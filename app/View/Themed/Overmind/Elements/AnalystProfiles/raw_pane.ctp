<?php
/**
 * The whole document, as the last entry of the section list, in the JSON
 * box the modals use (genericElementsBS5/Forms/json_field).
 *
 * It reads as text until the owner double-clicks it; it is then a box
 * whose Save posts the document to `edit`, which replaces rather than
 * merges (analyst-profile-settings.js). A paste refused by a plain form
 * post comes back here open, with what was posted and the error.
 *
 * @var array $profile
 * @var string $raw
 * @var bool $may_edit
 * @var bool $open Whether this pane is the one on screen
 * @var array|null $parse A refused paste, with its line
 */
$refused = !empty($parse);
?>
<div class="ap-pane" data-ap-pane="raw"<?= $open ? '' : ' hidden' ?>>
    <section class="wb-sec is-open" data-sec="raw">
        <div class="wb-sec-head">
            <div>
                <p class="wb-h wb-sec-title"><?= h(__('Raw JSON')) ?></p>
                <p class="wb-blurb">
                    <?= h(__('The whole document.')) ?>
                    <?php if ($may_edit): ?>
                        <span class="ap-raw-hint" data-ap-raw-hint<?= $refused ? ' hidden' : '' ?>>
                            <i class="fas fa-hand-pointer" aria-hidden="true"></i>
                            <?= h(__('Double-click the document to edit it.')) ?>
                        </span>
                    <?php endif; ?>
                </p>
            </div>
            <?php if ($may_edit): ?>
                <div class="ap-raw-acts" data-ap-raw-acts<?= $refused ? '' : ' hidden' ?>>
                    <button type="button" class="btn btn-sm btn-outline-secondary" data-ap-raw-cancel>
                        <?= h(__('Cancel')) ?>
                    </button>
                    <button type="button" class="btn btn-sm btn-success" data-ap-raw-save>
                        <i class="fas fa-check me-1" aria-hidden="true"></i><?= h(__('Save')) ?>
                    </button>
                </div>
            <?php endif; ?>
        </div>
        <div class="card ap-blk ap-raw-doc<?= $may_edit ? ' is-editable' : '' ?><?= $refused ? ' is-editing' : '' ?>"
             data-ap-raw>
            <?php if ($may_edit): ?>
                <p class="ap-raw-editing">
                    <i class="fas fa-pen-to-square" aria-hidden="true"></i>
                    <?= h(__('Editing the whole document. Saving replaces it, nothing'
                        . ' is merged; Esc cancels.')) ?>
                </p>
                <div class="wb-note bad mb-2" data-ap-raw-msg role="alert"<?= $refused ? '' : ' hidden' ?>>
                    <?php if ($refused): ?>
                        <b><?= h(__('Not saved.')) ?></b>
                        <?= h($parse['error']) ?>
                        <?php if ($parse['line'] !== null): ?>
                            <?= h(sprintf(__('Line %s.'), $parse['line'])) ?>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <?= $this->element('genericElementsBS5/Forms/json_field', array(
                'field' => false,
                'id' => 'ap-raw',
                'label' => __('Document'),
                'value' => $raw,
                'shape' => 'object',
                'rows' => 28,
                'minHeight' => '28rem',
                'inputAttrs' => array_filter(array(
                    'name' => $may_edit ? 'data[AnalystProfile][parameters_json]' : null,
                    'readonly' => $refused ? null : 'readonly',
                    'aria-label' => __('Raw JSON'),
                )),
            )) ?>
        </div>
    </section>
</div>
