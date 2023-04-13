<?= $this->element('ajaxTags', array(
    'event' => $event,
    'tags' => $tags,
    'tagAccess' => $isSiteAdmin || $mayModify,
    'localTagAccess' => $this->Acl->canModifyTag($event, true),
    'tagConflicts' => $tagConflicts
));
