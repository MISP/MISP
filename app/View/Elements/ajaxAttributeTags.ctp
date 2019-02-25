<div style="width:100%;display:inline-block;">
    <?php
        if (empty($context)) {
            $context = 'event';
        }
        $full = $isAclTagger && $tagAccess;
        foreach ($attributeTags as $tag):
            if (!isset($tag['Tag'])) $tag = array('Tag' => $tag);
            $tagClass = $full ? 'tagFirstHalf' : 'tag';
    ?>
            <div style="padding:1px; overflow:hidden; white-space:nowrap; display:flex; float:left; margin-right:2px;">
                <?php
                    if (!empty($server)):
                ?>
                        <a href="<?php echo $baseurl;?>/servers/previewIndex/<?php echo h($server['Server']['id']); ?>/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
                <?php
                    elseif (!empty($feed)):
                ?>
                        <div class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></div>
                <?php
                    else:
                ?>
                        <a href="<?php echo $baseurl;?>/attributes/search/tags:<?php echo h($tag['Tag']['id']); ?>" class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
                <?php
                    endif;
                    if ($full):
                ?>
                        <div class="tagSecondHalf useCursorPointer noPrint" title="<?php echo __('Remove tag');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove tag');?>" onClick="removeObjectTagPopup(this, 'attribute', '<?php echo h($attributeId); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
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
