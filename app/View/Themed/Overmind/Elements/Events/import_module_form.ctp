<?php
/*
 * The form of one import module. Field names match what
 * EventsController::importModule() reads (Event.config.*, Event.source,
 * Event.paste, Event.fileupload); the form posts into a chained modal, where
 * the import results are reviewed.
 *
 * Vars: $module, $configTypes, $eventId, $idPrefix, $inline (an accordion
 * section rather than a modal of its own), $moduleError.
 */

$eventId = (int)$eventId;
$p = isset($idPrefix) ? $idPrefix : 'ImportModule';
$inline = !empty($inline);
$inputSource = isset($module['mispattributes']['inputSource'])
    ? $module['mispattributes']['inputSource']
    : ['paste'];
$hasPaste = in_array('paste', $inputSource, true);
$hasFile  = in_array('file', $inputSource, true);
if ($hasPaste && $hasFile) {
    $source = 'both';
} elseif ($hasFile) {
    $source = 'file';
} elseif ($hasPaste) {
    $source = 'paste';
} else {
    $source = null;
}

echo $this->Form->create('Event', [
    'url' => $baseurl . '/events/importModule/' . $module['name'] . '/' . $eventId,
    'type' => 'file',
    'id' => $p . 'Form',
    'class' => 'om-import-module-form',
]);
?>

<?php if (!empty($moduleError)): ?>
    <div class="alert alert-danger py-2 mb-3"><?= h($moduleError) ?></div>
<?php endif; ?>

<?php if (isset($module['meta']['description'])): ?>
    <p class="text-muted <?= $inline ? 'small mb-2' : 'mb-3' ?>"><?= h($module['meta']['description']) ?></p>
<?php endif; ?>

<?php
if (!empty($module['mispattributes']['userConfig'])):
    foreach ($module['mispattributes']['userConfig'] as $configName => $config):
        $field = 'Event.config.' . $configName;
        $fieldId = $p . 'Config' . Inflector::camelize($configName);
        $type = $configTypes[$config['type']]['field'] ?? 'text';
        $label = ucfirst(h($configName));
        ?>
        <div class="mb-3">
            <?php if ($type === 'checkbox'): ?>
                <div class="form-check">
                    <?= $this->Form->checkbox($field, [
                        'class' => 'form-check-input',
                        'id' => $fieldId,
                        'checked' => !empty($config['checked']),
                    ]) ?>
                    <label class="form-check-label fw-semibold" for="<?= h($fieldId) ?>"><?= $label ?></label>
                    <?php if (!empty($config['message'])): ?>
                        <div class="form-text"><?= h($config['message']) ?></div>
                    <?php endif; ?>
                </div>
            <?php elseif ($type === 'select'): ?>
                <label class="form-label fw-semibold" for="<?= h($fieldId) ?>"><?= $label ?></label>
                <?php if (!empty($config['message'])): ?>
                    <div class="form-text mb-1"><?= h($config['message']) ?></div>
                <?php endif; ?>
                <?= $this->Form->select($field, $config['options'] ?? [], [
                    'class' => 'form-select',
                    'id' => $fieldId,
                    'empty' => true,
                ]) ?>
            <?php else: ?>
                <label class="form-label fw-semibold" for="<?= h($fieldId) ?>"><?= $label ?></label>
                <?php if (!empty($config['message'])): ?>
                    <div class="form-text mb-1"><?= h($config['message']) ?></div>
                <?php endif; ?>
                <?= $this->Form->text($field, ['class' => 'form-control', 'id' => $fieldId]) ?>
            <?php endif; ?>
        </div>
        <?php
    endforeach;
endif;
?>

<?php if ($source === 'both'): ?>
    <div class="form-check form-switch mb-3">
        <?= $this->Form->checkbox('Event.source', [
            'class' => 'form-check-input',
            'id' => $p . 'Source',
            'checked' => false,
        ]) ?>
        <label class="form-check-label fw-semibold" for="<?= h($p) ?>Source">
            <?= __('Upload a file instead of pasting') ?>
        </label>
    </div>
<?php elseif ($source !== null): ?>
    <?= $this->Form->hidden('Event.source', [
        'id' => $p . 'Source',
        'value' => $source === 'file' ? '1' : '0',
    ]) ?>
<?php endif; ?>

<?php if ($hasPaste): ?>
    <div class="mb-3" id="<?= h($p) ?>PasteDiv">
        <label class="form-label fw-semibold" for="<?= h($p) ?>Paste"><?= __('Paste input') ?></label>
        <?= $this->Form->textarea('Event.paste', [
            'class' => 'form-control',
            'id' => $p . 'Paste',
            'rows' => $inline ? 8 : 12,
        ]) ?>
    </div>
<?php endif; ?>

<?php if ($hasFile): ?>
    <div class="mb-3" id="<?= h($p) ?>FileDiv">
        <label class="form-label fw-semibold" for="<?= h($p) ?>File"><?= __('Input file') ?></label>
        <?= $this->Form->file('Event.fileupload', [
            'class' => 'form-control',
            'id' => $p . 'File',
        ]) ?>
    </div>
<?php endif; ?>

<?php if ($inline): ?>
    <div class="d-flex justify-content-end mt-3">
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-file-import me-1"></i><?= __('Run %s', h(Inflector::humanize($module['name']))) ?>
        </button>
    </div>
<?php else: ?>
    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'align' => 'end',
        'cancel' => false,
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-file-import'],
    ]) ?>
<?php endif; ?>

<?= $this->Form->end(); ?>

<script>
(function () {
    var form = document.getElementById(<?= json_encode($p . 'Form') ?>);
    if (!form) {
        return;
    }
    var src = document.getElementById(<?= json_encode($p . 'Source') ?>);
    var paste = document.getElementById(<?= json_encode($p . 'Paste') ?>);
    var file = document.getElementById(<?= json_encode($p . 'File') ?>);
    var pasteDiv = document.getElementById(<?= json_encode($p . 'PasteDiv') ?>);
    var fileDiv = document.getElementById(<?= json_encode($p . 'FileDiv') ?>);
    var btn = form.querySelector('[type="submit"]');

    function usesFile() {
        if (src && src.type === 'checkbox') {
            return src.checked;
        }
        return !paste && !!file;
    }

    // Keep the button disabled until the input the module reads is there.
    function check() {
        if (src && src.type === 'checkbox' && pasteDiv && fileDiv) {
            fileDiv.style.display = src.checked ? '' : 'none';
            pasteDiv.style.display = src.checked ? 'none' : '';
        }
        if (!btn || (!paste && !file)) {
            return;
        }
        btn.disabled = usesFile()
            ? !(file && file.files && file.files.length)
            : !(paste && paste.value.trim() !== '');
    }

    [src, paste, file].forEach(function (el) {
        if (el) {
            el.addEventListener(el === paste ? 'input' : 'change', check);
        }
    });
    check();

    form.addEventListener('submit', function (e) {
        if (!document.getElementById('mainModal')) {
            return;
        }
        e.preventDefault();
        openModalPostChained(form.getAttribute('action'), new FormData(form));
    });
})();
</script>
