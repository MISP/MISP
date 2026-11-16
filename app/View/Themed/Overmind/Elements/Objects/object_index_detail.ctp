<?php
/**
 * The row an object opens in the event's Objects tab: its attributes as an
 * index table, over the foot the objects index gives its open rows
 * (Objects/ajax/index_card). The foot (Objects/object_foot) carries the
 * object's uuid, its template version, its tags and galaxies and, in an
 * extended view, the event it comes from.
 *
 * Parameters:
 *   object             array  one entry of $objects
 *   ctx                array  see $objContext in Elements/Objects/index.ctp
 *   columns            int    how many columns of the objects table it spans
 *   mayGraph           bool   may add to a workspace
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *   readonly           bool   for an event held elsewhere: no selection box or
 *                             action menu, the IDS and correlation states
 *                             without their toggles, no sightings
 *
 * Read from the view: $baseurl, $me, $extensionEvents.
 */
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
                'readonly' => !empty($readonly),
                'remote' => !empty($readonly),
                // A deleted object is restored or deleted whole.
                'locked' => $ctx['deleted'],
            ]) ?>
            <?= $this->element('Objects/object_foot', [
                'object' => $object,
                'taxonomy' => true,
                'origin' => true,
            ]) ?>
        </div>
    </td>
</tr>
