<?php
/**
 * The row an object opens in the event's Objects tab: its attributes as an
 * index table, over the foot the objects index gives its open rows
 * (Objects/ajax/index_card). The foot carries the object's uuid, its tags and
 * galaxies and, in an extended view, the event it comes from.
 *
 * Parameters:
 *   object             array  one entry of $objects
 *   ctx                array  see $objContext in Elements/Objects/index.ctp
 *   columns            int    how many columns of the objects table it spans
 *   mayGraph           bool   may add to a workspace
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *
 * Read from the view: $baseurl, $me, $extensionEvents.
 */
$uuid = (string)($object['uuid'] ?? '');
?>
<tr class="oi-detail"<?= $ctx['expand'] ? '' : ' hidden' ?>>
    <td colspan="<?= (int)$columns ?>">
        <div class="oi-card">
            <?= $this->element('Objects/object_attribute_table', [
                'attrs' => $ctx['attrs'],
                'canEdit' => $ctx['canEdit'],
                'canTag' => $ctx['canTag'],
                'mayGraph' => $mayGraph ?? false,
                'enrichmentEnabled' => $enrichmentEnabled ?? false,
                'cortexEnabled' => $cortexEnabled ?? false,
            ]) ?>
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
                <?= $this->element('Objects/object_taxonomy', ['object' => $object]) ?>
                <?= $this->element('Events/View/extension_origin', [
                    'event_id' => $object['event_id'] ?? 0,
                    'compact' => true,
                    'only_foreign' => true,
                ]) ?>
            </div>
        </div>
    </td>
</tr>
