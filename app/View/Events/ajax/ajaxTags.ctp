<?= $this->element('ajaxTags', array(
    'event' => $event,
    'tags' => $tags,
    'tagAccess' => $isSiteAdmin || $mayModify,
    'localTagAccess' => $isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || $hostOrgUser,
    'tagConflicts' => $tagConflicts
));
