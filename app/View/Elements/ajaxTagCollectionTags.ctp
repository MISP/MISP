<div style="width:100%;display:inline-block;">
    <?php
        if (empty($context)) {
            $context = 'event';
        }
        $full = $isAclTagger && $tagAccess;
        foreach ($tagCollection['TagCollectionTag'] as $tag):
            if (!isset($tag['Tag'])) $tag = array('Tag' => $tag);
            $tagClass = $full ? 'tagFirstHalf' : 'tag';
    ?>
            <div style="padding:1px; overflow:hidden; white-space:nowrap; display:flex; float:left; margin-right:2px;">
                <div class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></div>
                <?php
                    if ($full):
                ?>
                        <div class="tagSecondHalf useCursorPointer noPrint" title="<?php echo __('Remove tag');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove tag');?>" onClick="removeObjectTagPopup(this, 'tag_collection', '<?php echo h($tagCollection['TagCollection']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
                <?php
                    endif;
                ?>
            </div>
    <?php
        endforeach;
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
