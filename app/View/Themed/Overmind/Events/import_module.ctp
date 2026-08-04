<?php
/**
 *
 * jQuery-free BS5 rewrite of app/View/Events/import_module.ctp: same field
 * names (Event.config.*, Event.source, Event.paste, Event.fileupload) so the
 * importModule POST handler is unchanged. No SideMenu. The Import button is a
 * native submit → full-page POST → result screen renders with the legacy stack.
 *
 * Vars: $module, $configTypes, $eventId, $event, $mayModify.
 */

$eventId = (int)$eventId;
$inputSource = !empty($module['mispattributes']['inputSource'])
    ? $module['mispattributes']['inputSource']
    : ['paste'];
$hasPaste = in_array('paste', $inputSource, true);
$hasFile  = in_array('file', $inputSource, true);
if ($hasPaste && $hasFile) {
    $source = 'both';
} elseif ($hasFile) {
    $source = 'file';
} else {
    $source = 'paste';
}
?>

<!-- ── HEADER ───────────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="border-bottom:2px solid var(--bs-primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Import module') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-puzzle-piece text-primary" style="font-size:1.2rem;"></i>
            <?= h(Inflector::humanize($module['name'])) ?>
        </h4>
        <div class="text-muted small mt-1">
            <?= __('Event') ?>: <strong class="text-body">#<?= h($eventId) ?></strong>
        </div>
    </div>
    <div class="d-flex gap-2">
        <button type="button" class="btn btn-outline-secondary btn-sm"
                onclick="openModalChained('<?= $baseurl ?>/events/populateFrom/<?= $eventId ?>');">
            <i class="fas fa-arrow-left me-1"></i><?= __('Back') ?>
        </button>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
    </div>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">
    <?php echo $this->Form->create('', ['type' => 'file', 'id' => 'importModuleForm']); ?>

    <?php if (isset($module['meta']['description'])): ?>
        <p class="text-muted mb-3"><?= h($module['meta']['description']) ?></p>
    <?php endif; ?>

    <?php
    // ── Module user config ──────────────────────────────────────
    if (!empty($module['mispattributes']['userConfig'])):
        foreach ($module['mispattributes']['userConfig'] as $configName => $config):
            $field = 'Event.config.' . $configName;
            $type = $configTypes[$config['type']]['field'] ?? 'text';
            $label = ucfirst(h($configName));
            ?>
            <div class="mb-3">
                <?php if ($type === 'checkbox'): ?>
                    <div class="form-check">
                        <?= $this->Form->checkbox($field, [
                            'class' => 'form-check-input',
                            'checked' => !empty($config['checked']),
                        ]) ?>
                        <label class="form-check-label fw-semibold"><?= $label ?></label>
                        <?php if (!empty($config['message'])): ?>
                            <div class="form-text"><?= h($config['message']) ?></div>
                        <?php endif; ?>
                    </div>
                <?php elseif ($type === 'select'): ?>
                    <label class="form-label fw-semibold"><?= $label ?></label>
                    <?php if (!empty($config['message'])): ?>
                        <div class="form-text mb-1"><?= h($config['message']) ?></div>
                    <?php endif; ?>
                    <?= $this->Form->select($field, $config['options'] ?? [], [
                        'class' => 'form-select',
                        'empty' => true,
                    ]) ?>
                <?php else: ?>
                    <label class="form-label fw-semibold"><?= $label ?></label>
                    <?php if (!empty($config['message'])): ?>
                        <div class="form-text mb-1"><?= h($config['message']) ?></div>
                    <?php endif; ?>
                    <?= $this->Form->text($field, ['class' => 'form-control']) ?>
                <?php endif; ?>
            </div>
            <?php
        endforeach;
    endif;
    ?>

    <?php if (!empty($inputSource)): ?>
        <?php if ($source === 'both'): ?>
            <div class="form-check form-switch mb-3">
                <?= $this->Form->checkbox('Event.source', [
                    'class' => 'form-check-input',
                    'id' => 'EventSource',
                    'checked' => false,
                ]) ?>
                <label class="form-check-label fw-semibold" for="EventSource">
                    <?= __('Upload a file instead of pasting') ?>
                </label>
            </div>
        <?php else: ?>
            <?= $this->Form->hidden('Event.source', [
                'id' => 'EventSource',
                'value' => $source === 'file' ? '1' : '0',
            ]) ?>
        <?php endif; ?>

        <?php if ($hasPaste): ?>
            <div class="mb-3" id="pasteDiv">
                <label class="form-label fw-semibold" for="EventPaste"><?= __('Paste input') ?></label>
                <?= $this->Form->textarea('Event.paste', [
                    'class' => 'form-control',
                    'id' => 'EventPaste',
                    'rows' => 12,
                ]) ?>
            </div>
        <?php endif; ?>

        <?php if ($hasFile): ?>
            <div class="mb-3" id="fileDiv">
                <label class="form-label fw-semibold" for="EventFileupload"><?= __('Input file') ?></label>
                <?= $this->Form->file('Event.fileupload', [
                    'class' => 'form-control',
                    'id' => 'EventFileupload',
                ]) ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <div class="d-flex justify-content-end mt-3">
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-file-import me-1"></i><?= __('Import') ?>
        </button>
    </div>

    <?php echo $this->Form->end(); ?>
</div>

<script>
(function () {
    var src = document.getElementById('EventSource');
    var pasteDiv = document.getElementById('pasteDiv');
    var fileDiv = document.getElementById('fileDiv');

    function toggle() {
        // Only a real checkbox (source === 'both') drives the toggle; a hidden
        // input keeps both divs as rendered (single-source modules).
        if (!src || src.type !== 'checkbox' || !pasteDiv || !fileDiv) {
            return;
        }
        if (src.checked) {
            fileDiv.style.display = '';
            pasteDiv.style.display = 'none';
        } else {
            fileDiv.style.display = 'none';
            pasteDiv.style.display = '';
        }
    }

    if (src && src.type === 'checkbox') {
        src.addEventListener('change', toggle);
        toggle();
    }
})();
</script>
