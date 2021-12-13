<?php

$attribute = Hash::extract($row, 'Attribute');
$event = Hash::extract($row, 'Event');
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));
$objectId = intval($attribute['id']);

?>
<div class="attributeTagContainer">
    <?php echo $this->element(
        'ajaxTags',
        array(
            'attributeId' => $attribute['id'],
            'tags' => $attribute['AttributeTag'],
            'tagAccess' => ($isSiteAdmin || $mayModify),
            'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
            'context' => 'event',
            'scope' => 'attribute',
            'tagConflicts' => isset($attribute['tagConflicts']) ? $attribute['tagConflicts'] : array()
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
