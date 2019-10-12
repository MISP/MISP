<?php
    if (empty($scope)) {
        $scope = 'event';
    }
    switch ($scope) {
        case 'event':
            $searchUrl = '/events/index/searchtag:';
            $id = h($event['Event']['id']);
            if (!empty($required_taxonomies)) {
                foreach ($required_taxonomies as $k => $v) {
                    foreach ($tags as $tag) {
                        $temp_tag = explode(':', $tag['Tag']['name']);
                        if (count($temp_tag) > 1) {
                            if ($temp_tag[0] == $v) {
                                unset($required_taxonomies[$k]);
                                break;
                            }
                        }
                    }
                }
                if (!empty($required_taxonomies)) {
                    echo sprintf(
                        'Missing taxonomies: <span class="red bold">%s</span><br />',
                        implode(', ', $required_taxonomies)
                    );
                }
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
        $span_scope = sprintf(
            '<span class="%s" title="%s" aria-label="%s"><i class="fas fa-%s"></i></span>',
            'black-white tag',
            !empty($tag['local']) ? __('Local tag') : __('Global tag'),
            !empty($tag['local']) ? __('Local tag') : __('Global tag'),
            !empty($tag['local']) ? 'user' : 'globe-americas'
        );
        if (!empty($tag['Tag']['id'])) {
            $span_tag = sprintf(
                '<a href="%s" style="%s" class="%s" title="%s">%s</a>',
                sprintf(
                    '%s%s%s',
                    $baseurl,
                    $searchUrl,
                    h($tag['Tag']['id'])
                ),
                $aStyle,
                $aClass,
                $aText,
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
        if ($full) {
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
        $tagData .= '<span class="tag-container nowrap  ">' . $span_scope . $span_tag . $span_delete . '</span> ';
    }
    $buttonData = array();
    if ($full) {
        $buttonData[] = sprintf(
            '<button id="%s" title="%s" role ="button" tabindex="0" aria-label="%s" class="%s" style="%s" onClick="%s">%s</button>',
            'addTagButton',
            __('Add a tag'),
            __('Add a tag'),
            'btn btn-inverse noPrint',
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
    if ($host_org_editor || $full) {
        $buttonData[] = sprintf(
            '<button id="%s" title="%s" role ="button" tabindex="0" aria-label="%s" class="%s" style="%s" onClick="%s">%s</button>',
            'addLocalTagButton',
            __('Add a local tag'),
            __('Add a local tag'),
            'btn btn-inverse noPrint',
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
?>
