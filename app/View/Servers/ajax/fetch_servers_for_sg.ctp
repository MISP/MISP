<div class="confirmation">
<legend>Select instances to add</legend>
	<div style="padding:10px;">
		<table>
			<tr>
				<td style="width:285px;">
					<p>Available Instances</p>
					<select id="leftValues" size="5" multiple style="width:285px;">
						<?php
							foreach ($servers as $server) {
								echo '<option data-url="' . h($server['url']) . '" value="' . h($server['id']) . '" selected>' . h($server['name']) . '</option>';
							}
						?>
					</select>
				</td>
				<td style="width:100%;text-align:center;">
					<span class="btn btn-inverse" id="btnLeft">&lt;&lt;</span>
					<span class="btn btn-inverse" id="btnRight">&gt;&gt;</span>
				</td>
				<td style="width:285px;">
					<p>Added Organisations</p>
					<select id="rightValues" size="5" multiple style="width:285px;"></select>
				</td>
			</tr>
		</table>
		<span role="button" tabindex="0" aria-label="Add servers to sharing group" title="Add servers to sharing group" class="btn btn-primary" style="margin-left:auto;margin-right:auto;width:40px;" onClick="submitPicklistValues('server');">Add</span>
		<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" style="float:right;margin-left:auto;margin-right:auto;width:40px;" onClick="cancelPicklistValues();">Cancel</span>
	</div>
</div>
<script>
$("#btnLeft").click(function () {
	var selectedItem = $("#rightValues option:selected");
	$("#leftValues").append(selectedItem);
});

$("#btnRight").click(function () {
	var selectedItem = $("#leftValues option:selected");
	$("#rightValues").append(selectedItem);
});
</script>
