<?php

$attribute = $row['Attribute'];
$event = $row['Event'];
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));
$objectId = intval($attribute['id']);

?>
<div class="attributeTagContainer">
    <?= $this->element(
        'ajaxTags',
        array(
            'attributeId' => $attribute['id'],
            'tags' => $attribute['AttributeTag'],
            'tagAccess' => $isSiteAdmin || $mayModify,
            'localTagAccess' => $isSiteAdmin || $mayModify || $me['org_id'] == $event['org_id'] || $hostOrgUser,
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
