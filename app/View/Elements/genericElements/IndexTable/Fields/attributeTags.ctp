<?php
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;
$objectId = intval($attribute['id']);
$event = isset($row['Event']) ? $row : (isset($parent['Event']) ? $parent : null);
?>
<div class="attributeTagContainer">
    <?= $this->element(
        'ajaxTags',
        array(
            'attributeId' => $attribute['id'],
            'tags' => isset($attribute['AttributeTag']) ? $attribute['AttributeTag'] : $attribute['Tag'],
            'tagAccess' => $this->Acl->canModifyTag($event),
            'localTagAccess' => $this->Acl->canModifyTag($event, true),
            'context' => 'event',
            'scope' => 'attribute',
            'tagConflicts' => $attribute['tagConflicts'] ?? [],
        )
    ); ?>
</div>
<?php
if (!empty($includeRelatedTags)) {
    $element = '';
    if (!empty($attribute['RelatedTags'])) {
        $element = $this->element('ajaxAttributeTags', array('attributeId' => $attribute['id'], 'attributeTags' => $attribute['RelatedTags'], 'tagAccess' => false));
    }
    echo sprintf(
        '<td class="shortish"><div %s>%s</div></td>',
        'class="attributeRelatedTagContainer" id="#Attribute_' . $objectId . 'Related_tr .attributeTagContainer"',
        $element
    );
}
