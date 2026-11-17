<?php
/**
 * The foot of an open object, under its attributes: its uuid and its template
 * version, then what the surface adds.
 *
 * Parameters:
 *   object    array   the Object, with its uuid, name and template_version
 *   taxonomy  bool    add its tags and galaxies (Objects/object_taxonomy)
 *   origin    bool    add the event it comes from, in an extended view
 *   content   string  optional raw HTML appended last. Escape it yourself.
 */
$uuid = (string)($object['uuid'] ?? '');
$version = (string)($object['template_version'] ?? '');
?>
<div class="oi-card-foot">
    <span class="oi-card-uuid">
        <i class="fas fa-fingerprint"></i>
        <code class="user-select-all"><?= h($uuid) ?></code>
        <button type="button" class="btn btn-sm btn-link p-0 lh-1"
                title="<?= h(__('Copy UUID')) ?>"
                onclick="copyValueToClipboard('<?= h($uuid) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
            <i class="fas fa-copy"></i>
        </button>
    </span>
    <?php if ($version !== ''): ?>
        <span class="oi-card-version"
              title="<?= h(__('Template %s, version %s', $object['name'] ?? '', $version)) ?>">
            <span class="oi-card-version-label">
                <i class="fas fa-code-branch" aria-hidden="true"></i><?= __('Template') ?>
            </span>
            <span class="oi-card-version-num"><?= h(__('v%s', $version)) ?></span>
        </span>
    <?php endif; ?>
    <?php if (!empty($taxonomy)): ?>
        <?= $this->element('Objects/object_taxonomy', ['object' => $object]) ?>
    <?php endif; ?>
    <?php if (!empty($origin)): ?>
        <?= $this->element('Events/View/extension_origin', [
            'event_id' => $object['event_id'] ?? 0,
            'compact' => true,
            'only_foreign' => true,
        ]) ?>
    <?php endif; ?>
    <?= $content ?? '' ?>
</div>
