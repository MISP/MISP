<div style="width:100%;display:inline-block;">
	<?php
		foreach ($tags as $tag): ?>
			<div style="overflow:hidden;white-space:nowrap;float:left;">
				<div style="padding-right:0px;float: left;">
					<?php if ($isAclTagger && $tagAccess): ?>
						<a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="tagFirstHalf" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
					<?php else: ?>
						<a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class=tag style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
					<?php endif; ?>
				</div>
				<div style="padding-left:0px;padding-right:5px;float:left;">
					<?php if ($isAclTagger && $tagAccess): ?>
						<?php
							echo $this->Form->create('Event', array('id' => 'removeTag_' . h($tag['Tag']['id']),  'url' => '/events/removeTag/' . h($event['Event']['id']) . '/' . h($tag['Tag']['id']), 'style' => 'margin:0px;'));
						?>
						<div class="tagSecondHalf useCursorPointer noPrint" onClick="removeEventTag('<?php echo h($event['Event']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
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
				<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'tags', 'selectTaxonomy');">+</button>
			<?php else:?>
				&nbsp;
			<?php endif; ?>
		</div>
</div>
