<h2>Attribute Types Histogram</h2>
<table>
	<tr>
		<td colspan="2"><h4 class="histogram-legendH4">Attributes</h4> (you can also choose specific histogram items by clicking on attributes below)</td>
	</tr>
	<tr>
		<td class="membersList-histogram-legend">
			<div class="membersList-histogram-legend-line col">
				<?php
				$cnt = 0;
				foreach ($typeDb as $type => $colour): ?>
				<div class="membersList-histogram-legend-line">
					<div class="membersList-histogram-legend-box" style="display: block;float: left;margin: 4px 6px 0 0;background-color:<?php echo $colour; ?>">&nbsp;</div>
					<div style="display: inline-block;cursor: pointer;<?php if (in_array($type, $selectedTypes)) echo 'font-weight:bold';?>" onClick='toggleHistogramType("<?php echo $type; ?>", [<?php foreach ($selectedTypes as $t) echo '"' . $t . '", ' ?>]);'><?php echo $type;?></div>
				</div>
				<?php
				if($cnt%12==11){?>
			</div>
			<div class="membersList-histogram-legend-line col">
				<?php
				} ?>
				<?php
				$cnt++;
				endforeach;
				?>
			</div>
		</td>
	</tr>
	<tr>
		<td colspan="2"><h4 >Attributes per organization</h4></td>
	</tr>
	<tr>
		<td class="membersList-histogram-left-table">
			<table style="border-spacing:0px !important;">
			<?php
				end($data);
				$lastElement = key($data);
				foreach ($data as $k => $org):
			?>
				<tr>
					<td style="text-align:right"><?php echo h($k);?></td>
					<td <?php echo ($k == $lastElement ? 'class="membersList-histogram-last"' : '');?> style="border-left:1px solid;padding-left:0px;width:500px;border-spacing:0px !important;">
						<ul style="width:<?php echo 600 * $org['total'] / $max;?>px;" class="memberslistBar">
					<?php
						foreach ($org['data'] as $orgType => $orgTypeCount):
					?>
						<li title="<?php echo h($orgType) . ' : ' . $orgTypeCount; ?>" class="type_<?php echo h($orgType); ?>" style="display:block;height:30px;float:left;width:<?php echo (100 * $orgTypeCount / $org['total']);?>%;background:<?php echo $typeDb[$orgType];?>">&nbsp;</li>
						<?php endforeach;?>
						</ul>
					</td>

				</tr>
			<?php endforeach; ?>
			</table>
		</td>
	</tr>
</table>
