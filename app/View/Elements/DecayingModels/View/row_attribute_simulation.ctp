<?php
    $tr_class = array('useCursorPointer');
    if (!empty($object['object_relation'])) {
        $tr_class[] = '';
    }
    $tr_class = implode(' ', $tr_class);
?>
<tr id = "Attribute_<?php echo h($object['id']); ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0" onclick="doSimulation(this, <?php echo h($object['id']); ?>)">
    <td class="short">
        <?php echo h($object['id']); ?>
    </td>
    <td class="short">
        <a href="<?php echo $baseurl . '/events/view/' . h($object['event_id']) ?>" target="_blank"><?php echo h($object['event_id']); ?></a>
    </td>
    <td class="short">
        <?php echo date('Y-m-d', $object['timestamp']); ?>
    </td>
    <td class="short">
        <?php echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 24)); ?>
        &nbsp;
    </td>
    <td class="short">
        <div id = "Attribute_<?php echo $object['id']; ?>_category_solid" class="inline-field-solid">
            <?php echo h($object['category']); ?>
        </div>
    </td>
    <td class="short">
        <?php if (!empty($object['object_relation'])): ?>
            <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
        <?php endif; ?>
        <div id = "Attribute_<?php echo $object['id']; ?>_type_solid" class="inline-field-solid">
            <?php echo h($object['type']); ?>
        </div>
    </td>
    <td id="Attribute_<?php echo h($object['id']); ?>_container" class="showspaces limitedWidth shortish">
        <div id = "Attribute_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
            <span style="white-space: nowrap;" title="<?php echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => 'blue')) ?>"><?php echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => 'blue')) ?></span>
        </div>
    </td>
    <td class="shortish">
        <div class="attributeTagContainer" id="#Attribute_<?php echo h($object['id']);?>_tr .attributeTagContainer">
            <?php echo $this->element('ajaxAttributeTags', array('attributeId' => $object['id'], 'attributeTags' => $object['AttributeTag'], 'tagAccess' => false)); ?>
        </div>
    </td>
    <?php
        $element = '';
        if (!empty($object['EventTag'])) {
            $element = $this->element('ajaxAttributeTags', array('attributeId' => $object['id'], 'attributeTags' => $object['EventTag'], 'tagAccess' => false));
        }
        echo sprintf(
            '<td class="shortish"><div %s>%s</div></td>',
            'class="attributeRelatedTagContainer" id="#Attribute_' . h($object['id']) . 'Related_tr .attributeTagContainer"',
            $element
        );
    ?>
    <td class="short" id="attribute_<?php echo h($object['id']); ?>_galaxy">
      <?php
        echo $this->element('galaxyQuickViewMini', array(
            'mayModify' => false,
            'isSiteAdmin' => false, // prevent add button
            'isAclTagger' => false,
            'data' => (!empty($object['Galaxy']) ? $object['Galaxy'] : array()),
            'target_id' => $object['id'],
            'target_type' => 'attribute'
        ));
      ?>
    </td>
    <td class="showspaces bitwider">
        <div id = "Attribute_<?php echo $object['id']; ?>_comment_solid" class="inline-field-solid">
            <?php echo nl2br(h($object['comment'])); ?>&nbsp;
        </div>
    </td>
    <td class="short">
        <div id = "Attribute_<?php echo $object['id']; ?>_to_ids_solid" class="inline-field-solid">
            <span class="fa fa-<?php echo $object['to_ids'] ? 'check' : 'times' ; ?>"></span>
        </div>
    </td>
    <td class="short">
      <?php
        if (!empty($sightingsData['csv'][$object['id']])) {
          echo $this->element('sparkline', array('scope' => 'object', 'id' => $object['id'], 'csv' => $sightingsData['csv'][$object['id']]));
        }
      ?>
    </td>
    <td class="short">
        <div id = "Attribute_<?php echo $object['id']; ?>_score_solid" class="inline-field-solid">
            <?php echo $this->element('DecayingModels/View/attribute_decay_score', array('scope' => 'object', 'object' => $object, 'uselink' => false)); ?>
        </div>
    </td>
</tr>
