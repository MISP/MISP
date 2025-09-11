<?php
if (!isset($canModifyAllTags)) {
    $canModifyAllTags = $isAclTagger && $tagAccess && empty($static_tags_only);
}
if (!isset($canModifyLocalTags)) {
    $canModifyLocalTags = $isAclTagger && $localTagAccess && empty($static_tags_only);
}
if (empty($tag['Tag'])) {
    $tag = ['Tag' => $tag];
}
if (empty($tag['Tag']['colour'])) {
    $tag['Tag']['colour'] = '#0088cc';
}
$aStyle = 'text-decoration: none; background-color:' . h($tag['Tag']['colour']) . ';color:' . $this->TextColour->getTextColour($tag['Tag']['colour']);
$aClass = 'nowrap';
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
        '<span class="%s" title="%s" role="button" tabindex="0" aria-label="%s" href="%s"><i class="fas fa-project-diagram"></i></span>',
        'btn btn-dark modal-open',
        __('Modify Tag Relationship'),
        __('Modify relationship for tag %s', h($tag['Tag']['name'])),
        sprintf(
            '%s/tags/modifyTagRelationship/%s/%s',
            $baseurl,
            h($scope),
            h($tag['Tag']['id'])
        )
    );
    $span_delete = sprintf(
        '<span class="%s" title="%s" role="%s" tabindex="%s" aria-label="%s" onclick="%s"><i class="fas fa-times"></i></span>',
        'btn btn-dark',
        __('Remove tag'),
        "button",
        "0",
        __('Remove tag %s', h($tag['Tag']['name'])),
        sprintf(
            "removeObjectTagPopup(this, '%s', %s, %s)",
             $scope,
             h($id),
             intval($tag['Tag']['id'])
        )
    );
}
echo sprintf(
    '<div class="btn-group btn-group-sm" role="group" aria-label="Basic example">%s%s%s%s%s</div> ',
    !empty($hide_global_scope) ? '' : sprintf(
        '<div type="button" class="btn btn-dark">%s</div>',
        !empty($tag['local']) ? '<i class="fas fa-user"></i>' : '<i class="fas fa-globe-americas"></i>'
    ),
    empty($tag['relationship_type']) ? '' : sprintf(
        '<div class="btn btn-dark" title="%s" aria-label="%s">%s:</div>',
        h($tag['relationship_type']),
        h($tag['relationship_type']),
        h($tag['relationship_type'])
    ),
    sprintf(
        '<button type="button" class="btn border-top border-bottom border-dark" style="background-color:%s;">%s</button>',
        h($tag['Tag']['colour']),
        $span_tag
    ),
    $span_relationship,
    $span_delete
);
