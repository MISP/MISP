<?php
    if (empty($scope)) {
        $scope = 'event';
    }
    $searchUrl = '/events/index/searchtag:';
    switch ($scope) {
        case 'event':
            $id = h($event['Event']['id']);
            if (!empty($missingTaxonomies)) {
                echo __(
                    'Missing taxonomies: <span class="red bold">%s</span><br>',
                    implode(', ', $missingTaxonomies)
                );
            }
            break;
        case 'attribute':
            $id = $attributeId;
            $searchUrl = '/attributes/search/tags:';
            if (!empty($server)) {
                $searchUrl = sprintf("/servers/previewIndex/%s/searchtag:", h($server['Server']['id']));
            }
            break;
    }
    $full = $isAclTagger && $tagAccess && empty($static_tags_only);
    $fullLocal = $isAclTagger && $localTagAccess && empty($static_tags_only);
    $host_org_editor = (int)$me['org_id'] === Configure::read('MISP.host_org_id') && $isAclTagger && empty($static_tags_only);
    $tagData = "";
    foreach ($tags as $tag) {
        if (empty($tag['Tag'])) {
            $tag['Tag'] = $tag;
        }
        if (empty($tag['Tag']['colour'])) {
            $tag['Tag']['colour'] = '#0088cc';
        }
        $aStyle = 'background-color:' . h($tag['Tag']['colour']) . ';color:' . $this->TextColour->getTextColour($tag['Tag']['colour']) . ';';
        $aClass = 'tag nowrap';
        $aText = trim($tag['Tag']['name']);
        $aTextModified = null;
        if (isset($tag_display_style)) {
            if (!isset($tag_display_style) || $tag_display_style == 1) {
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
            '<span class="%s" title="%s" aria-label="%s"><i class="fas fa-%s"></i></span>',
            'black-white tag',
            !empty($tag['local']) ? __('Local tag') : __('Global tag'),
            !empty($tag['local']) ? __('Local tag') : __('Global tag'),
            !empty($tag['local']) ? 'user' : 'globe-americas'
        );
        if (!empty($tag['Tag']['id'])) {
            $span_tag = sprintf(
                '<a href="%s" style="%s" class="%s" title="%s" data-tag-id="%s">%s</a>',
                sprintf(
                    '%s%s%s',
                    $baseurl,
                    $searchUrl,
                    h($tag['Tag']['id'])
                ),
                $aStyle,
                $aClass,
                $aText,
                h($tag['Tag']['id']),
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
        if ($full || ($fullLocal && $tag['Tag']['local'])) {
            $span_delete = sprintf(
                '<span class="%s" title="%s" role="%s" tabindex="%s" aria-label="%s" onClick="%s">x</span>',
                'black-white tag useCursorPointer noPrint',
                __('Remove tag'),
                "button",
                "0",
                __('Remove tag %s', h($tag['Tag']['name'])),
                sprintf(
                    "removeObjectTagPopup(this, '%s', '%s', '%s')",
                     $scope,
                     $id,
                     h($tag['Tag']['id'])
                )
            );
        }
        $tagData .= '<span class="tag-container nowrap">' . $span_scope . $span_tag . $span_delete . '</span> ';
    }
    $buttonData = array();
    if ($full) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" style="%s" onClick="%s">%s</button>',
            __('Add a tag'),
            __('Add a tag'),
            'addTagButton btn btn-inverse noPrint',
            'line-height:10px; padding: 2px;',
            sprintf(
                "popoverPopup(this, '%s%s', '%s', '%s');",
                $id,
                ($scope === 'event') ? '' : ('/' . $scope),
                'tags',
                'selectTaxonomy'
            ),
            '<i class="fas fa-globe-americas"></i> +'
        );
    }
    if ($full || $fullLocal) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" style="%s" onClick="%s">%s</button>',
            __('Add a local tag'),
            __('Add a local tag'),
            'addLocalTagButton btn btn-inverse noPrint',
            'line-height:10px; padding: 2px;',
            sprintf(
                "popoverPopup(this, '%s%s', '%s', '%s')",
                $id,
                ($scope === 'event') ? '' : ('/' . $scope),
                'tags',
                'selectTaxonomy/local:1'
            ),
            '<i class="fas fa-user"></i> +'
        );
    }
    if (!empty($buttonData)) {
        $tagData .= sprintf(
            '<span style="white-space:nowrap;">%s</span>',
            implode(' ', $buttonData)
        );
    }
    echo sprintf(
        '<span class="tag-list-container">%s</span>',
        $tagData
    );
    $tagConflictData = '';
    if (!empty($tagConflicts['global'])) {
        $tagConflictData .= '<div><div class="alert alert-error tag-conflict-notice">';
        $tagConflictData .= '<i class="fas fa-globe-americas icon"></i>';
        $tagConflictData .= '<div class="text-container">';
        foreach ($tagConflicts['global'] as $tagConflict) {
            $tagConflictData .= sprintf(
                '<strong>%s</strong></br>',
                h($tagConflict['conflict'])
            );
            foreach ($tagConflict['tags'] as $tag) {
                $tagConflictData .= sprintf('<span class="apply_css_arrow nowrap">%s</span></br>', h($tag));
            }
        }
        $tagConflictData .= '</div></div></span>';
    }
    if (!empty($tagConflicts['local'])) {
        $tagConflictData .= '<div><div class="alert alert-error tag-conflict-notice">';
        $tagConflictData .= '<i class="fas fa-user icon"></i>';
        $tagConflictData .= '<div class="text-container">';
        foreach ($tagConflicts['local'] as $tagConflict) {
            $tagConflictData .= sprintf(
                '<strong>%s</strong></br>',
                h($tagConflict['conflict'])
            );
            foreach ($tagConflict['tags'] as $tag) {
                $tagConflictData .= sprintf('<span class="apply_css_arrow nowrap">%s</span></br>', h($tag));
            }
        }
        $tagConflictData .= '</div></div></span>';
    }
    echo $tagConflictData;
?>
