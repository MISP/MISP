<?= $this->element('ajaxTags', array(
    'event' => $event,
    'tags' => $tags,
    'tagAccess' => $isSiteAdmin || $mayModify,
    'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
    'tagConflicts' => $tagConflicts
));
