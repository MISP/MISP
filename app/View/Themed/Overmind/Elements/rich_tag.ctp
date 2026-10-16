<?php
if (!isset($canModifyAllTags)) {
    $canModifyAllTags = $isAclTagger && $tagAccess && empty($static_tags_only);
}
if (!isset($canModifyLocalTags)) {
    $canModifyLocalTags = $isAclTagger && $localTagAccess && empty($static_tags_only);
}
echo $this->TagChip->chip($tag, [
    'scope' => $scope ?? 'event',
    'id' => $id ?? null,
    'searchUrl' => $searchUrl ?? '/events/index/searchtag:',
    'canModifyAll' => $canModifyAllTags,
    'canModifyLocal' => $canModifyLocalTags,
    'display' => $this->TagChip->displayFromStyle($tag_display_style ?? 1),
]) . ' ';
