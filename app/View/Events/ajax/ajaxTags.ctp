<?php
    $mayModify = (
        ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) ||
        ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id'])
    );
    echo $this->element('ajaxTags', array(
        'event' => $event,
        'tags' => $tags,
        'tagAccess' => ($isSiteAdmin || $mayModify),
        'tagConflicts' => $tagConflicts
    ));
?>
