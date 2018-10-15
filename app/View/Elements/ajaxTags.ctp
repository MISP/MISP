<span style="display:inline-block;">
    <?php
        $full = $isAclTagger && $tagAccess;
        $tagData = "";
        foreach ($tags as $tag) {
            $aStyle = 'display:inline-block; background-color:' . h($tag['Tag']['colour']) . ';color:' . $this->TextColour->getTextColour($tag['Tag']['colour']) . ';';
            $aClass = $full ? 'tagFirstHalf' : 'tag';
            $aText = h($tag['Tag']['name']);
            $aSearchTagUrl = $baseurl . '/events/index/searchtag: ' . h($tag['Tag']['id']);
            $span1 = sprintf('<a href="%s" style="%s" class="%s">%s</a>', $aSearchTagUrl, $aStyle, $aClass, $aText);
            $span2 = '';
            if ($full) {
                $spanClass = "tagSecondHalf useCursorPointer noPrint";
                $spanTitle = __('Remove tag');
                $spanRole = "button";
                $spanTabIndex = "0";
                $spanAriaLabel = __('Remove tag %s', h($tag['Tag']['name']));
                $spanOnClick = "removeObjectTagPopup('event', '" . h($event['Event']['id']) . "', '" . h($tag['Tag']['id']) . "')";
                $span2 = sprintf('<span class="%s" title="%s" role="%s" tabindex="%s" aria-label="%s" onClick="%s">x</span>', $spanClass, $spanTitle, $spanRole, $spanTabIndex, $spanAriaLabel, $spanOnClick);
            }
            $tagData .= '<span style="white-space:nowrap;">' . $span1 . $span2 . '</span>  ';
        }
        $buttonData = "&nbsp;";
        if ($full) {
            $buttonVars = array(
                'addTagButton',
                __('Add a tag'),
                'button',
                '0',
                __('Add a tag'),
                'btn btn-inverse noPrint',
                'line-height:10px; padding: 4px 4px;',
                'getPopup(\'' . h($event['Event']['id']) . '\', \'tags\', \'selectTaxonomy\');'
            );
            $buttonData = vsprintf('<button id="%s" title="%s" role ="%s" tabindex="%s" aria-label="%s" class="%s" style="%s" onClick="%s">+</button>', $buttonVars);
        }
        $tagData .= $buttonData;
    ?>
        <span style="padding:1px; display:flex; display: inline-block; margin-right:2px;word-wrap:break-word;"><?php echo $tagData; ?></span>
</span>
