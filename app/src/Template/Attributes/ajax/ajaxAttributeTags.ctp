<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
	echo $this->element('ajaxAttributeTags', array('attributeId' => $attributeId, 'attributeTags' => $attributeTags, 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'])));
?>
