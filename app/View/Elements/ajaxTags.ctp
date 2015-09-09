<table>
	<tr>
	<?php
		foreach ($tags as $tag): ?>
			<td style="padding-right:0px;">
				<?php if ($isAclTagger): ?>
					<a href="/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="tagFirstHalf" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php else: ?>
					<a href="/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class=tag style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				<?php endif; ?>
			</td>
			<?php if ($isAclTagger): ?>
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
		if ($isAclTagger) : ?>
			<td id ="addTagTD" style="display:none;">
				<?php
					echo $this->Form->create('Event', array('url' => '/events/addTag/' . $event['Event']['id'], 'style' => 'margin:0px;'));
					echo $this->Form->hidden('id', array('value' => $event['Event']['id']));
					echo $this->Form->input('tag', array(
						'options' => array($allTags),
						'value' => 0,
						'label' => false,
						'style' => array('height:22px;padding:0px;margin-bottom:0px;'),
						'onChange' => 'submitTagForm(' . $event['Event']['id'] . ')',
						'class' => 'input-large'));
					echo $this->Form->end();
				?>
			</td>
			<td>
				<button id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;">+</button>
			</td>
	<?php 
		else:
				if (empty($tags)) echo '&nbsp;'; 
		endif; 
	?>
	</tr>
</table>
<script type="text/javascript">
	$('#addTagButton').click(function() {
		$('#addTagTD').show();
		$('#addTagButton').hide();
	});
</script>