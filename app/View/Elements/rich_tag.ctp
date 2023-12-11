<?php
if (!isset($canModifyAllTags)) {
    $canModifyAllTags = $isAclTagger && $tagAccess && empty($static_tags_only);
}
if (!isset($canModifyLocalTags)) {
    $canModifyLocalTags = $isAclTagger && $localTagAccess && empty($static_tags_only);
}
if (empty($tag['Tag'])) {
    $tag['Tag'] = $tag;
}
if (empty($tag['Tag']['colour'])) {
    $tag['Tag']['colour'] = '#0088cc';
}
$aStyle = 'background-color:' . h($tag['Tag']['colour']) . ';color:' . $this->TextColour->getTextColour($tag['Tag']['colour']);
$aClass = 'tag nowrap';
$aText = trim($tag['Tag']['name']);
$aTextModified = null;
if (isset($tag_display_style)) {
    if ($tag_display_style == 1) {
        // default behaviour, do nothing for now
    } else if ($tag_display_style == 2) {
        $separator_pos = strpos($aText, ':');
        if ($separator_pos !== false) {
            $aTextModified = substr($aText, $separator_pos + 1);
            $value_pos = strpos($aTextModified, '=');
            if ($value_pos !== false) {
                $aTextModified = substr($aTextModified, $value_pos + 1);
                $aTextModified = trim($aTextModified, '"');
            }
            $aTextModified = h($aTextModified);
        }
    } else if ($tag_display_style === 0 || $tag_display_style === '0') {
        $aTextModified = '&nbsp;';
    }
}
$aText = h($aText);
$span_scope = !empty($hide_global_scope) ? '' : sprintf(
    '<span class="%s" title="%s" role="img" aria-label="%s"><i class="fas fa-%s"></i></span>',
    'black-white tag',
    !empty($tag['local']) ? __('Local tag') : __('Global tag'),
    !empty($tag['local']) ? __('Local tag') : __('Global tag'),
    !empty($tag['local']) ? 'user' : 'globe-americas'
);
$span_relationship_type = empty($tag['relationship_type']) ? '' : sprintf(
    '<span class="tag nowrap white" style="background-color:black" title="%s" aria-label="%s">%s:</span>',
    h($tag['relationship_type']),
    h($tag['relationship_type']),
    h($tag['relationship_type'])
);
if (!empty($tag['Tag']['id'])) {
    $span_tag = sprintf(
        '<a href="%s" style="%s" class="%s"%s data-tag-id="%s">%s</a>',
        $baseurl . $searchUrl . intval($tag['Tag']['id']),
        $aStyle,
        $aClass,
        isset($aTextModified) ? ' title="' . $aText . '"' : '',
        intval($tag['Tag']['id']),
        isset($aTextModified) ? $aTextModified : $aText
    );
} else {
    $span_tag = sprintf(
        '<span style="%s" class="%s">%s</span>',
        $aStyle,
        $aClass,
        $aText
    );
}
$span_delete = '';
$span_relationship = '';
if ($canModifyAllTags || ($canModifyLocalTags && $tag['Tag']['local'])) {
    $span_relationship = sprintf(
        '<a class="%s" title="%s" role="button" tabindex="0" aria-label="%s" href="%s"><i class="fas fa-project-diagram"></i></a>',
        'black-white tag noPrint modal-open',
        __('Modify Tag Relationship'),
        __('Modify relationship for tag %s', h($tag['Tag']['name'])),
        sprintf(
            '%s/tags/modifyTagRelationship/%s/%s',
            $baseurl,
            h($scope),
            h($tag['id'])
        )
    );
    $span_delete = sprintf(
        '<span class="%s" title="%s" role="%s" tabindex="%s" aria-label="%s" onclick="%s">x</span>',
        'black-white tag useCursorPointer noPrint',
        __('Remove tag'),
        "button",
        "0",
        __('Remove tag %s', h($tag['Tag']['name'])),
        sprintf(
            "removeObjectTagPopup(this, '%s', %s, %s)",
             $scope,
             $id,
             intval($tag['Tag']['id'])
        )
    );
}

echo '<span class="tag-container nowrap">' . $span_scope . $span_relationship_type . $span_tag . $span_relationship . $span_delete . '</span> ';
