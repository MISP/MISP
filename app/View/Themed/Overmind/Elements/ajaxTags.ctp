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
            $searchUrl = '/attributes/index/tags:';
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
    $renderAddButtons = empty($hide_add_buttons);
    $popoverPlacement = $popoverPlacement ?? 'right';

    if ($renderAddButtons && $full) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s" data-popover-placement="%s">%s</button>',
            __('Add a tag'),
            __('Add a tag'),
            'addTagButton addButton btn btn-inverse noPrint',
            $baseurl . '/tags/selectTaxonomy/' . h($id) . ($scope === 'event' ? '' : ('/' . $scope)),
            h($popoverPlacement),
            '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
        );
    }
    if ($renderAddButtons && ($full || $fullLocal)) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s" data-popover-placement="%s">%s</button>',
            __('Add a local tag'),
            __('Add a local tag'),
            'addLocalTagButton addButton btn btn-inverse noPrint',
            $baseurl . '/tags/selectTaxonomy/local:1/' . h($id) . ($scope === 'event' ? '' : ('/' . $scope)),
            h($popoverPlacement),
            '<i class="fas fa-user"></i> <i class="fas fa-plus"></i>'
        );
    }
    // AI tag recommendations (A3): anyone who may add a tag here may accept
    // suggestions; without edit rights they land as local tags.
    if (
        $scope === 'event' && $renderAddButtons && ($full || $fullLocal) &&
        Configure::read('Plugin.AI_services_enable') &&
        $this->Acl->canAccess('events', 'aiRecommendTags')
    ) {
        $buttonData[] = sprintf(
            '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" onclick="openGenericModal(\'%s\');">%s</button>',
            __('Recommend tags with AI'),
            __('Recommend tags with AI'),
            'aiRecommendTagsButton addButton btn btn-inverse noPrint',
            h($baseurl . '/events/aiRecommendTags/' . $id),
            '<i class="fas fa-robot"></i>'
        );
    }

    $highlightedTagsString = "";
    if (isset($highlightedTags) && $scope === 'event') {
        foreach ($highlightedTags as $hTaxonomy) {
            $hButtonData = [];
            if ($renderAddButtons && $full) {
                $hButtonData[] = sprintf(
                    '<button title="%s" role="button" tabindex="0" aria-label="%s" class="%s" data-popover-popup="%s" data-popover-placement="%s">%s</button>',
                    __('Add a tag'),
                    __('Add a tag'),
                    'addTagButton addButton btn btn-inverse noPrint',
                    sprintf($baseurl . '/tags/selectTag/%u/%u/event', h($id), $hTaxonomy['taxonomy']['Taxonomy']['id']),
                    h($popoverPlacement),
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

    /*
     * The reader's taxonomy priority, where a caller resolved one.
     *
     * Optional, and absent for most of this element's twenty-odd
     * callers — a feed preview and a server preview are looking at
     * somebody else's data, and a tag-collection index is not a reading
     * surface for a threat. With no plan nothing is called at all, so
     * those callers render the array they were handed
     * (prd/personas/04-label-surfaces.md §6).
     *
     * **Below the highlighted table, and after it took its tags.**
     * An administrator's `taxonomies.highlighted` outranks a profile's
     * pin (D53) for D41's reason: highlighting says *this instance
     * reads these first*, which is a statement about the deployment,
     * and a pin says *I attend to this*, which is a statement about a
     * reader. The highlighted loop above has already lifted those tags
     * out of `$tags`, so what is ordered here is what is left — a
     * pinned-and-highlighted taxonomy is at the top either way, and a
     * pinned one that is not highlighted leads the rest.
     *
     * `labels()` and not `order()`: this column draws a chip per tag,
     * so a pinned `tlp` group has no single slot to win and what
     * matters is that `tlp:red` precedes `tlp:clear` (D51).
     */
    if (!empty($labelPlan)) {
        App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
        $ordered = [];
        foreach ($tags as $tag) {
            $name = $tag['Tag']['name'] ?? ($tag['name'] ?? null);
            $tag['key'] = ValueLabelPriority::namespaceOf($name);
            $tag['name'] = $name;
            $ordered[] = $tag;
        }
        $tags = ValueLabelPriority::labels(
            $ordered,
            $labelPlan,
            ValueLabelPriority::TAXONOMIES
        );
    }
    $tagData .= $this->TagChip->collection($tags, [
        'scope' => $scope,
        'id' => $id ?? null,
        'searchUrl' => $searchUrl,
        'canModifyAll' => $full,
        'canModifyLocal' => $fullLocal,
        'display' => $this->TagChip->displayFromStyle($tag_display_style),
        'track' => $tagTrack ?? null,
    ]);
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
        echo '</div></div></div>';
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
        echo '</div></div></div>';
    }
