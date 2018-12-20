<div style="width:100%;display:inline-block;">
    <?php
		if (empty($context)) {
			$context = 'event';
		}
        $full = $isAclTagger && $tagAccess;
        foreach ($tagCollection['TagCollectionElement'] as $tag):
            if (!isset($tag['Tag'])) $tag = array('Tag' => $tag);
            $tagClass = $full ? 'tagFirstHalf' : 'tag';
    ?>
            <div style="padding:1px; overflow:hidden; white-space:nowrap; display:flex; float:left; margin-right:2px;">
                <div class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></div>
                <?php
                    if ($full):
                ?>
                        <div class="tagSecondHalf useCursorPointer noPrint" title="<?php echo __('Remove tag');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove tag');?>" onClick="removeObjectTagPopup('tag_collection', '<?php echo h($tagCollection['TagCollection']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
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
						'<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup(%s);">+</button>',
						sprintf("'%s/tag_collection', 'tags', 'selectTaxonomy'", h($tagCollection['TagCollection']['id']))
					);
				}
				echo $addTagButton;
			?>
        </div>
</div>
