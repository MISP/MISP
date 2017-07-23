<div id="server_pull_rule_popover" class="ajax_popover_form server_rule_popover">
	<div class="confirmation">
		<legend>Set pull rules</legend>
		<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<div style="padding:10px;">
			<table>
				<tr>
					<td style="width:120px;">
						<p style="color:green;font-weight:bold;">Allowed Tags (OR)</p>
						<select id="tagspullLeftValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span title="Move tag to the list of tags to allow" role="button" tabindex="0" aria-label="Move tag to the list of tags to allow" class="btn btn-inverse" id="tagspullLeftLeft" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'tags', 'Middle', 'Left');">&lt;&lt;</span>
						<span title="Remove tag from the list of tags to allow" role="button" tabindex="0" aria-label="Remove tag from the list of tags to allow" class="btn btn-inverse" id="tagspullLeftRight" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'tags', 'Left', 'Middle');">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<input id="tagspullNewValue" style="width:180px;"></input>
					</td>
					<td style="width:50px;text-align:center;">
						<span title="Remove tag from the list of tags to block" role="button" tabindex="0" aria-label="Remove tag from the list of tags to block" class="btn btn-inverse" id="tagspullRightLeft" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'tags', 'Right', 'Middle');">&lt;&lt;</span>
						<span title="Move tag to the list of tags to block" role="button" tabindex="0" aria-label="Move tag to the list of tags to block" class="btn btn-inverse" id="tagspullRightRight" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'tags', 'Middle', 'Right');">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="color:red;font-weight:bold;">Blocked Tags (AND NOT)</p>
						<select id="tagspullRightValues" size="5" multiple style="width:185px;"></select>
					</td>
				</tr>
				<tr>
					<td class="bold green center" style="padding-bottom:15px;padding-top:15px;">AND</td>
					<td>&nbsp;</td>
					<td>&nbsp;</td>
					<td>&nbsp;</td>
					<td class="bold red center" style="padding-bottom:15px;padding-top:15px;">AND NOT</td>
				</tr>
				<tr>
					<td style="width:120px;">
						<p style="color:green;font-weight:bold;">Allowed Orgs (OR)</p>
						<select id="orgspullLeftValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span title="Move organisation to the list of tags to allow" role="button" tabindex="0" aria-label="Move organisation to the list of organisations to allow" class="btn btn-inverse" id="orgspullLeftLeft" style="padding:2px;"  onClick="serverRuleMoveFilter('pull', 'orgs', 'Middle', 'Left');">&lt;&lt;</span>
						<span title="Remove organisation to the list of tags to allow" role="button" tabindex="0" aria-label="Remove organisation form the list of organisations to allow" class="btn btn-inverse" id="orgspullLeftRight" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'orgs', 'Left', 'Middle');">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<input id="orgspullNewValue" style="width:180px;"></input>
					</td>
					<td style="width:50px;text-align:center;">
						<span title="Remove organisation from the list of tags to allow" role="button" tabindex="0" aria-label="Remove organisation from the list of organisations to block" class="btn btn-inverse" id="orgspullRightLeft" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'orgs', 'Right', 'Middle');">&lt;&lt;</span>
						<span title="Move organisation to the list of tags to block" role="button" tabindex="0" aria-label="Move organisation to the list of organisations to block" class="btn btn-inverse" id="orgspullRightRight" style="padding:2px;" onClick="serverRuleMoveFilter('pull', 'orgs', 'Middle', 'Right');">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="color:red;font-weight:bold;">Blocked Orgs (AND NOT)</p>
						<select id="orgspullRightValues" size="5" multiple style="width:185px;"></select>
					</td>
				</tr>
			</table>
		</div>


			<table>
				<tr>
					<td style="vertical-align:top">
						<span title="Accept changes" role="button" tabindex="0" aria-label="Accept changes" id="PromptYesButton" class="btn btn-primary" onClick="submitServerRulePopulateTagPicklistValues('pull');">Update</span>
					</td>
					<td style="width:540px;">
					</td>
					<td style="vertical-align:top;">
						<span title="Cancel" role="button" tabindex="0" aria-label="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="serverRuleCancel();">Cancel</span>
					</td>
				</tr>
			</table>
		</div>
	</div>
</div>
