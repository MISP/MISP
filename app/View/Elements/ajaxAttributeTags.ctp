<div style="width:100%;display:inline-block;">
	<?php
		foreach ($attributeTags as $tag): ?>
			<div style="overflow:hidden;white-space:nowrap;float:left;">
				<div style="padding-right:0px;float: left;">
					<?php if ($isAclTagger && $tagAccess): ?>
						<a href="<?php echo $baseurl;?>/attributes/search/attributetag:<?php echo h($tag['Tag']['id']); ?>" class="tagFirstHalf" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
					<?php else: ?>
						<a href="<?php echo $baseurl;?>/attributes/search/attributetag:<?php echo h($tag['Tag']['id']); ?>" class=tag style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
					<?php endif; ?>
				</div>
				<div style="padding-left:0px;padding-right:5px;float:left;">
					<?php if ($isAclTagger && $tagAccess): ?>
						<?php
							echo $this->Form->create('Attribute', array('id' => 'removeAttributeTag_' . h($tag['Tag']['id']),  'url' => '/attributes/removeTag/' . h($attributeId) . '/' . h($tag['Tag']['id']), 'style' => 'margin:0px;'));
						?>
						<div class="tagSecondHalf useCursorPointer noPrint" onClick="removeAttributeTag('<?php echo h($attributeId); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
						<?php
							echo $this->Form->end();
						?>
					<?php else: ?>
						&nbsp;
					<?php endif; ?>
				</div>
			</div>
			<?php
		endforeach;
	?>
		<div style="float:left">
			<?php if ($isAclTagger && $tagAccess): ?>
				<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($attributeId); ?>' + '/true', 'tags', 'selectTaxonomy');">+</button>
			<?php else:?>
				&nbsp;
			<?php endif; ?>
		</div>
</div>
