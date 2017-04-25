<div style="width:100%;display:inline-block;">
	<?php
		$full = $isAclTagger && $tagAccess;
		foreach ($attributeTags as $tag):
			$tagClass = $full ? 'tagFirstHalf' : 'tag';
	?>
			<div style="padding:1px; overflow:hidden; white-space:nowrap; display:flex; float:left; margin-right:2px;">
				<a href="<?php echo $baseurl;?>/attributes/search/attributetag:<?php echo h($tag['Tag']['id']); ?>" class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php if ($full): ?>
					<div class="tagSecondHalf useCursorPointer noPrint" title="Remove tag" role="button" tabindex="0" aria-label="Remove tag" onClick="removeObjectTagPopup('attribute', '<?php echo h($attributeId); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
				<?php endif;?>
			</div>
	<?php
		endforeach;
	?>
		<div style="float:left">
			<?php if ($full): ?>
				<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($attributeId); ?>' + '/true', 'tags', 'selectTaxonomy');">+</button>
			<?php else:?>
				&nbsp;
			<?php endif; ?>
		</div>
</div>
