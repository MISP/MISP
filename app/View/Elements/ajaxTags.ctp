<div style="display:inline-block;">
	<?php
		$full = $isAclTagger && $tagAccess;
		foreach ($tags as $tag):
			$tagClass = $full ? 'tagFirstHalf' : 'tag';
	?>
			<div style="padding:1px; overflow:hidden; white-space:nowrap; display:flex; float:left; margin-right:2px;">
				<a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="<?php echo $tagClass; ?>" style="display:inline-block; background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php if ($full): ?>
					<div class="tagSecondHalf useCursorPointer noPrint" title="Remove tag" role="button" tabindex="0" aria-label="Remove tag <?php echo h($tag['Tag']['name']); ?>" onClick="removeObjectTagPopup('event', '<?php echo h($event['Event']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
				<?php endif;?>
			</div>
	<?php
		endforeach;
	?>
		<div style="float:left">
			<?php if ($full): ?>
				<button id="addTagButton" title="Add a tag" role="button" tabindex="0" aria-label="Add a tag" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'tags', 'selectTaxonomy');">+</button>
			<?php else:?>
				&nbsp;
			<?php endif; ?>
		</div>
</div>
