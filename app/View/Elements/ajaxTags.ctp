<?php
    if (empty($scope)) {
        $scope = 'event';
    }
    $searchUrl = '/events/index/searchtag:';
    switch ($scope) {
        case 'event':
            $id = intval($event['Event']['id']);
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
        case 'event_report':
            $id = $attributeId;
            $searchUrl = '';
            break;
    }
    $full = $isAclTagger && $tagAccess && empty($static_tags_only);
    $fullLocal = $isAclTagger && $localTagAccess && empty($static_tags_only);
    $tagData = "";
    $tag_display_style = $tag_display_style ?? 1;
    $buttonData = [];

    if ($full) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s">%s</button>',
            __('Add a tag'),
            __('Add a tag'),
            'addTagButton addButton btn btn-inverse noPrint',
            $baseurl . '/tags/selectTaxonomy/' . $id . ($scope === 'event' ? '' : ('/' . $scope)),
            '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
        );
    }
    if ($full || $fullLocal) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s">%s</button>',
            __('Add a local tag'),
            __('Add a local tag'),
            'addLocalTagButton addButton btn btn-inverse noPrint',
            $baseurl . '/tags/selectTaxonomy/local:1/' . $id . ($scope === 'event' ? '' : ('/' . $scope)),
            '<i class="fas fa-user"></i> <i class="fas fa-plus"></i>'
        );
    }

    $highlightedTagsString = "";
    if (isset($highlightedTags) && $scope === 'event') {
        foreach ($highlightedTags as $hTaxonomy) {
            $hButtonData = [];
            if ($full) {
                $hButtonData[] = sprintf(
                    '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s">%s</button>',
                    __('Add a tag'),
                    __('Add a tag'),
                    'addTagButton addButton btn btn-inverse noPrint',
                    sprintf($baseurl . '/tags/selectTag/%u/%u/event', $id, $hTaxonomy['taxonomy']['Taxonomy']['id']),
                    '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
                );
            }

            $hTags = "";
            foreach ($hTaxonomy['tags'] as $hTag) {
                $hTags .= $this->element('rich_tag', [
                    'tag' => $hTag,
                    'tagAccess' => $tagAccess,
                    'localTagAccess' => $localTagAccess,
                    'searchUrl' => $searchUrl,
                    'scope' => $scope,
                    'id' => $id,
                    'tag_display_style' => 2
                ]);
            }
            if (empty($hTags)) {
                $hTags = sprintf('<span class="grey">-%s-</span>', __('none'));
            }

            $highlightedTagsString .= sprintf(
                '<tr><td style="font-weight: bold;text-transform: uppercase;">%s</td></td><td>%s</td><td>%s</td></tr>',
                $hTaxonomy['taxonomy']['Taxonomy']['namespace'],
                $hTags,
                $hButtonData ? '<span style="white-space:nowrap">' . implode('', $hButtonData) . '</span>' : ''
            );

            foreach ($tags as $k => $tag) {
                foreach ($hTaxonomy['tags'] as $hTag) {
                    if ($tag['Tag']['name'] === $hTag['Tag']['name']) {
                        unset($tags[$k]);
                    }
                }
            }
        }
        if (!empty($highlightedTagsString)) {
            $tagData .= sprintf('<table>%s</table>', $highlightedTagsString);
        }
    }

    foreach ($tags as $tag) {
        $tagData .= $this->element('rich_tag', [
            'tag' => $tag,
            'tagAccess' => $tagAccess,
            'localTagAccess' => $localTagAccess,
            'searchUrl' => $searchUrl,
            'scope' => $scope,
            'id' => $id ?? null,
            'tag_display_style' => $tag_display_style
        ]);
    }
    if (!empty($buttonData)) {
        $tagData .= '<span style="white-space:nowrap">' . implode('', $buttonData) . '</span>';
    }
    echo sprintf(
        '<span class="tag-list-container">%s</span>',
        $tagData
    );
    if (!empty($tagConflicts['global'])) {
        echo '<div><div class="alert alert-error tag-conflict-notice">';
        echo '<i class="fas fa-globe-americas icon"></i>';
        echo '<div class="text-container">';
        foreach ($tagConflicts['global'] as $tagConflict) {
            echo sprintf(
                '<strong>%s</strong><br>',
                h($tagConflict['conflict'])
            );
            foreach ($tagConflict['tags'] as $tag) {
                echo sprintf('<span class="apply_css_arrow nowrap">%s</span><br>', h($tag));
            }
        }
        echo '</div></div></span>';
    }
    if (!empty($tagConflicts['local'])) {
        echo '<div><div class="alert alert-error tag-conflict-notice">';
        echo '<i class="fas fa-user icon"></i>';
        echo '<div class="text-container">';
        foreach ($tagConflicts['local'] as $tagConflict) {
            echo sprintf(
                '<strong>%s</strong><br>',
                h($tagConflict['conflict'])
            );
            foreach ($tagConflict['tags'] as $tag) {
                echo sprintf('<span class="apply_css_arrow nowrap">%s</span><br>', h($tag));
            }
        }
        echo '</div></div></span>';
    }
