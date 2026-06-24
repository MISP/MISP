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
$scopeTitle = !empty($tag['local']) ? __('Local tag') : __('Global tag');
$scopeLabel = $scopeTitle;
$scopeIconClass = 'fas fa-' . (!empty($tag['local']) ? 'user' : 'globe-americas');
if (!empty($tag['Tag']['is_galaxy']) && !empty($tag['Tag']['name'])) {
    $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
    $cluster = $GalaxyCluster->getCluster($tag['Tag']['name'], $this->get('me'));
    if (!empty($cluster['Galaxy']['icon'])) {
        $scopeIconClass = $this->FontAwesome->getClass($cluster['Galaxy']['icon']);
        $scopeTitle = __('Galaxy tag');
        $scopeLabel = __('Galaxy tag');
    }
}

// Beta UI Lightweight Style
// Text black, Background 10% opacity of tag color
$tagColor = h($tag['Tag']['colour']);

// Convert Hex to RGB for opacity
$hex = str_replace('#', '', $tagColor);
if (strlen($hex) == 3) {
    $r = hexdec(substr($hex, 0, 1) . substr($hex, 0, 1));
    $g = hexdec(substr($hex, 1, 1) . substr($hex, 1, 1));
    $b = hexdec(substr($hex, 2, 1) . substr($hex, 2, 1));
} else {
    $r = hexdec(substr($hex, 0, 2));
    $g = hexdec(substr($hex, 2, 2));
    $b = hexdec(substr($hex, 4, 2));
}
$rgba = "rgba($r, $g, $b, 0.7)"; // 70% opacity for icon backgrounds
$tagColorSoft = "rgba($r, $g, $b, 0.12)";
$tagTint1 = "rgba($r, $g, $b, 0.06)";
$tagTint2 = "rgba($r, $g, $b, 0.11)";
$tagTint3 = "rgba($r, $g, $b, 0.16)";
$tagBorder1 = "rgba($r, $g, $b, 0.28)";
$tagBorder2 = "rgba($r, $g, $b, 0.45)";
$tagBorder3 = "rgba($r, $g, $b, 0.62)";

// Calculate relative luminance to determine if we should use white or black icon
// Using the formula: L = 0.2126 * R + 0.7152 * G + 0.0722 * B
$luminance = (0.2126 * $r + 0.7152 * $g + 0.0722 * $b) / 255;
$iconColor = $luminance > 0.5 ? '#000' : '#fff'; // Black for light backgrounds, white for dark

// Style: No background color, light gray border, black text
$aStyle = 'background-color: transparent; border: 1px solid #d0d0d0; color: #000; border-left: none; --tag-color:' . $tagColor . '; --tag-color-soft:' . $tagColorSoft . '; --tag-color-tint-1:' . $tagTint1 . '; --tag-color-tint-2:' . $tagTint2 . '; --tag-color-tint-3:' . $tagTint3 . '; --tag-color-border-1:' . $tagBorder1 . '; --tag-color-border-2:' . $tagBorder2 . '; --tag-color-border-3:' . $tagBorder3 . ';';
$aClass = 'tag nowrap';

$aText = trim($tag['Tag']['name']);
$aTextDisplay = null;
if (strpos($aText, ':') !== false) {
    $parts = explode(':', $aText, 2);
    $taxonomyPart = $parts[0];
    $restPart = $parts[1];
    $predicatePart = $restPart;
    $valuePart = null;
    if (strpos($restPart, '=') !== false) {
        $restParts = explode('=', $restPart, 2);
        $predicatePart = $restParts[0];
        $valuePart = trim($restParts[1]);
        if (strlen($valuePart) >= 2) {
            $firstChar = $valuePart[0];
            $lastChar = substr($valuePart, -1);
            if (($firstChar === '"' || $firstChar === "'") && $lastChar === $firstChar) {
                $valuePart = substr($valuePart, 1, -1);
            }
        }
    }
    $displayPredicate = str_replace(['_', '-'], ' ', $predicatePart);
    $displayValue = $valuePart !== null ? str_replace(['_', '-'], ' ', $valuePart) : null;
    $aTextDisplay = sprintf(
        '<span class="tag-machine"><span class="tag-segment tag-segment-taxonomy">%s</span><span class="tag-segment tag-segment-predicate">%s</span>%s</span>',
        h($taxonomyPart),
        h($displayPredicate),
        $displayValue !== null ? '<span class="tag-segment tag-segment-value">' . h($displayValue) . '</span>' : ''
    );
} else {
    $aTextDisplay = sprintf(
        '<span class="tag-machine"><span class="tag-segment tag-segment-single">%s</span></span>',
        h($aText)
    );
}
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

// Scope icon: Icon color adapts to background brightness (white for dark, black for light)
$span_scope = !empty($hide_global_scope) ? '' : sprintf(
    '<span class="%s" title="%s" role="img" aria-label="%s" style="background-color: %s; color: %s; display: inline-flex; align-items: center; justify-content: center;"><i class="%s" style="font-size: 11px;"></i></span>',
    'tag-scope-icon',
    $scopeTitle,
    $scopeLabel,
    $rgba, // 70% opacity colored background
    $iconColor, // Adaptive icon color based on luminance
    h($scopeIconClass)
);

$span_relationship_type = empty($tag['relationship_type']) ? '' : sprintf(
    '<span class="tag nowrap" style="background-color:transparent; color: #555; border: 1px solid #ccc; border-right: none;" title="%s" aria-label="%s">%s:</span>',
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
        isset($aTextModified) ? $aTextModified : ($aTextDisplay ?? $aText)
    );
} else {
    $span_tag = sprintf(
        '<span style="%s" class="%s">%s</span>',
        $aStyle,
        $aClass,
        $aTextDisplay ?? $aText
    );
}

$span_delete = '';
$span_relationship = '';
if ($canModifyAllTags || ($canModifyLocalTags && $tag['local'])) {
    $span_relationship = sprintf(
        '<a class="%s" title="%s" role="button" tabindex="0" aria-label="%s" href="%s" style="color: %s;"><i class="fas fa-project-diagram"></i></a>',
        'tag-action tag-relationship noPrint modal-open',
        __('Modify Tag Relationship'),
        __('Modify relationship for tag %s', h($tag['Tag']['name'])),
        sprintf(
            '%s/tags/modifyTagRelationship/%s/%s',
            $baseurl,
            h($scope),
            h($tag['id'])
        ),
        '#777'
    );
    $span_delete = sprintf(
        '<span class="%s" title="%s" role="%s" tabindex="%s" aria-label="%s" onclick="%s" style="color: %s; cursor: pointer; margin-left: 2px;">x</span>',
        'tag-action tag-delete useCursorPointer noPrint',
        __('Remove tag'),
        "button",
        "0",
        __('Remove tag %s', h($tag['Tag']['name'])),
        sprintf(
            "removeObjectTagPopup(this, '%s', %s, %s)",
             $scope,
             h($id),
             intval($tag['Tag']['id'])
        ),
        '#999' // Light X
    );
}

// Wrap it all in a span that keeps them together
// Note: We are changing the structure slightly by moving icons 'inside' visual flow if possible.
// The original used separate spans with white-space: nowrap on container.

// Let's modify the output to embed the scope icon INSIDE the tag if possible, or just beside it.
// The user wants "lightweight".
// Standard Galaxy tags are: [Icon] [Name] in one box.

// Let's try to put the scope icon inside the main loop if we can, or just prepended.
// Since $span_tag is an <a> or <span> with the border, we might want to put the icon inside IT if possible?
// But $span_tag content is just text.

// Alternative: Make the CONTAINER the "chip" and the elements inside unstyled?
// No, existing JS likely expects .tag class on the specific element.

// Let's keep them separate but style them to look cohesive.
// If we use the border on the link/span, the icon sits outside.
// To make it look like one unit, we'd need a wrapper.
// But we can just place the icon next to it.

echo '<span class="tag-container nowrap tag-wrapper-beta">' . $span_scope . $span_relationship_type . $span_tag . $span_relationship . $span_delete . '</span> ';
