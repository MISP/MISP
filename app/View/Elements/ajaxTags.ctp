<table>
	<tr>
	<?php
		foreach ($tags as $tag): ?>
			<td style="padding-right:0px;">
				<?php if ($isAclTagger && $tagAccess): ?>
					<a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="tagFirstHalf" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php else: ?>
					<a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class=tag style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php endif; ?>
			</td>
			<?php if ($isAclTagger && $tagAccess): ?>
				<td style="padding-left:0px;padding-right:5px;">
					<?php
						echo $this->Form->create('Event', array('id' => 'removeTag_' . h($tag['Tag']['id']),  'url' => '/events/removeTag/' . h($event['Event']['id']) . '/' . h($tag['Tag']['id']), 'style' => 'margin:0px;'));
					?>
					<span class="tagSecondHalf useCursorPointer noPrint" onClick="removeEventTag('<?php echo h($event['Event']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</span>
					<?php 
						echo $this->Form->end();
					?>
				</td>
			<?php endif; ?>
			<?php 
		endforeach;
		if ($isAclTagger && $tagAccess): ?>
			<td>
				<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'tags', 'selectTaxonomy');">+</button>
			</td>
	<?php 
		else:
				if (empty($tags)) echo '&nbsp;'; 
		endif; 
	?>
	</tr>
</table>
