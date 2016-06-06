<div id="server_push_rule_popover" class="ajax_popover_form server_rule_popover">
	<div class="confirmation">
		<legend>Set push rules</legend>
		<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<div style="padding:10px;">
			<table>
				<tr>
					<td style="width:120px;">
						<p style="color:green;font-weight:bold;">Allowed Tags</p>
						<select id="tagspushLeftValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span class="btn btn-inverse" id="tagspushLeftLeft" onClick="serverRuleMoveFilter('push', 'tags', 'Middle', 'Left');" style="padding:2px;">&lt;&lt;</span>
						<span class="btn btn-inverse" id="tagspushLeftRight" onClick="serverRuleMoveFilter('push', 'tags', 'Left', 'Middle');" style="padding:2px;">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="font-weight:bold;">Available Tags</p>
						<select id="tagspushMiddleValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span class="btn btn-inverse" id="tagspushRightLeft" onClick="serverRuleMoveFilter('push', 'tags', 'Right', 'Middle');" style="padding:2px;">&lt;&lt;</span>
						<span class="btn btn-inverse" id="tagspushRightRight" onClick="serverRuleMoveFilter('push', 'tags', 'Middle', 'Right');" style="padding:2px;">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="color:red;font-weight:bold;">Blocked Tags</p>
						<select id="tagspushRightValues" size="5" multiple style="width:185px;"></select>
					</td>
				</tr>
			</table>
		</div>
		<div style="padding:10px;">
			<table>
				<tr>
					<td style="width:120px;">
						<p style="color:green;font-weight:bold;">Allowed Organisations</p>
						<select id="orgspushLeftValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span class="btn btn-inverse" id="orgspushLeftLeft" onClick="serverRuleMoveFilter('push', 'orgs', 'Middle', 'Left');" style="padding:2px;">&lt;&lt;</span>
						<span class="btn btn-inverse" id="orgspushLeftRight" onClick="serverRuleMoveFilter('push', 'orgs', 'Left', 'Middle');" style="padding:2px;">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="font-weight:bold;">Available  Organisations</p>
						<select id="orgspushMiddleValues" size="5" multiple style="width:185px;">
						</select>
					</td>
					<td style="width:50px;text-align:center;">
						<span class="btn btn-inverse" id="orgspushRightLeft" onClick="serverRuleMoveFilter('push', 'orgs', 'Right', 'Middle');" style="padding:2px;">&lt;&lt;</span>
						<span class="btn btn-inverse" id="orgspushRightRight" onClick="serverRuleMoveFilter('push', 'orgs', 'Middle', 'Right');" style="padding:2px;">&gt;&gt;</span>
					</td>
					<td style="width:120px;">
						<p style="color:red;font-weight:bold;">Blocked Organisations</p>
						<select id="orgspushRightValues" size="5" multiple style="width:185px;"></select>
					</td>
				</tr>
			</table>
		</div>


			<table>
				<tr>
					<td style="vertical-align:top">
						<span id="PromptYesButton" class="btn btn-primary" onClick="submitServerRulePopulateTagPicklistValues('push');">Update</span>
					</td>
					<td style="width:540px;">
					</td>
					<td style="vertical-align:top;">
						<span class="btn btn-inverse" id="PromptNoButton" onClick="serverRuleCancel();">Cancel</span>
					</td>
				</tr>
			</table>
		</div>
	</div>
</div>
