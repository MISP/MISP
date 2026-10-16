<div style="width:100%;display:inline-block;">
    <?php
        $full = $isAclTagger && $tagAccess;
        $rows = [];
        foreach ($attributeTags as $tag) {
            $rows[] = ['Tag' => isset($tag['Tag']) ? $tag['Tag'] : $tag];
        }
        if (!empty($server)) {
            $searchUrl = '/servers/previewIndex/' . (int)$server['Server']['id'] . '/searchtag:';
        } elseif (!empty($feed)) {
            $searchUrl = '';
        } else {
            $searchUrl = '/attributes/search/tags:';
        }
        echo $this->TagChip->collection($rows, [
            'scope' => 'attribute',
            'id' => $attributeId,
            'searchUrl' => $searchUrl,
            'canModifyAll' => $full,
            'class' => 'pull-left',
        ]);
    ?>
        <div style="float:left">
            <?php
                $addTagButton = '&nbsp;';
                if ($full) {
                    $addTagButton = sprintf(
                        '<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" title="%s" onClick="popoverPopup(this, %s);">+</button>',
                        __("Add tag"),
                        sprintf("'%s/attribute', 'tags', 'selectTaxonomy'", h($attributeId))
                    );
                }
                echo $addTagButton;
            ?>
        </div>
</div>
