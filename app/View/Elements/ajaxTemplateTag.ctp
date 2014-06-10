<td>
	<div id="tag_bubble_<?php echo $tag['Tag']['id']; ?>">
		<table>
			<tr>
				<td style="padding-right:0px;">
					<span class="tagFirstHalf" style="background-color:<?php echo $tag['Tag']['colour'];?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
				</td>
				<td style="padding-left:0px;padding-right:5px;">
					<span class="tagSecondHalf useCursorPointer" onClick="removeTemplateTag('<?php echo $tag['Tag']['id']; ?>', '<?php echo h($tag['Tag']['name']); ?>');">x</span>
				</td>
			</tr>
		</table>
	</div>
</td>