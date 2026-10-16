<div style="width:100%;display:inline-block;">
    <?php
        $full = $isAclTagger && $tagAccess;
        $rows = [];
        foreach ($tagCollection['TagCollectionTag'] as $tag) {
            $rows[] = ['Tag' => isset($tag['Tag']) ? $tag['Tag'] : $tag];
        }
        echo $this->TagChip->collection($rows, [
            'scope' => 'tag_collection',
            'id' => $tagCollection['TagCollection']['id'],
            'searchUrl' => '',
            'canModifyAll' => $full,
            'class' => 'pull-left',
        ]);
    ?>
        <div style="float:left">
            <?php
                $addTagButton = '&nbsp;';
                if ($full) {
                    $url = $baseurl . '/tags/selectTaxonomy/' . h($tagCollection['TagCollection']['id']) . '/tag_collection';
                    $addTagButton = sprintf(
                        '<button id="addTagButton" class="btn addButton btn-inverse noPrint" data-popover-popup="%s"><i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i></button>',
                        $url
                    );
                }
                echo $addTagButton;
            ?>
        </div>
</div>
