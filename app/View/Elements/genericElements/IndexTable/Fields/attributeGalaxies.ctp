<?php
$attribute = $row['Attribute'];
$event = $row['Event'];
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['org_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));

echo '<div id="attribute_' . intval($attribute['id']) . '_galaxy">';
echo $this->element('galaxyQuickViewNew', array(
    'mayModify' => $mayModify,
    'isAclTagger' => $isAclTagger,
    'data' => (!empty($attribute['Galaxy']) ? $attribute['Galaxy'] : array()),
    'event' => ['Event' => $event],
    'target_id' => $attribute['id'],
    'target_type' => 'attribute',
));
echo '</div>';
