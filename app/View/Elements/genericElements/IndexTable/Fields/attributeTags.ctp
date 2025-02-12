<?php
$attribute = $row['Attribute'];
$objectId = intval($attribute['id']);
?>
<div class="attributeTagContainer">
    <?= $this->element(
        'ajaxTags',
        array(
            'attributeId' => $attribute['id'],
            'tags' => $attribute['AttributeTag'],
            'tagAccess' => $this->Acl->canModifyTag($row),
            'localTagAccess' => $this->Acl->canModifyTag($row, true),
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
