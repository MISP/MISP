<div class="events">
	<?php echo $this->Form->create('Event');?>
		<fieldset>
			<legend>Filter Event Index</legend>
			<div class="overlay_spacing">
			<?php
				echo $this->Form->input('rule', array(
						'options' => $rules,
						//'empty' => '(Select a filter)',
						'class' => 'input',
						//'label' => 'Add Filtering Rule',
						'onchange' => "indexRuleChange();",
						'style' => 'margin-right:3px;width:120px;',
						'div' => false
				));
				echo $this->Form->input('searchbool', array(
						'options' => array("OR", "NOT"),
						'class' => 'input',
						'label' => false,
						'style'	=> 'display:none;width:62px;margin-right:3px',
						'div' => false
				));

				echo $this->Form->input('searchpublished', array(
						'options' => array('0' => 'No', '1' => 'Yes', '2' => 'Any'),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:503px;',
						'div' => false
				));
				echo $this->Form->input('searchthreatlevel', array(
						'options' => array('1' => 'High', '2' => 'Medium', '3' => 'Low', '4' => 'Undefined'),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:438px;',
						'div' => false
				));
				echo $this->Form->input('searchanalysis', array(
						'options' => array('0' => 'Initial', '1' => 'Ongoing', '2' => 'Completed'),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:438px;',
						'div' => false
				));
				echo $this->Form->input('searchdistribution', array(
						'options' => array('0' => 'Your organisation only', '1' => 'This community only', '2' => 'Connected communities', '3' => 'All communities'),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:438px;',
						'div' => false
				));
				if ($showorg) {
					echo $this->Form->input('searchorg', array(
							'options' => $orgs,
							'class' => 'input',
							'label' => false,
							'style' => 'display:none;width:438px;',
							'div' => false
					));
				}
				echo $this->Form->input('searchtag', array(
						'options' => array($tags),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:438px;',
						'div' => false
				));
				echo $this->Form->input('searchdatefrom', array(
						'div' => 'input clear',
						'class' => 'datepicker',
						'data-date-format' => 'yyyy-mm-dd',
						'label' => false,
						'style' => 'display:none;width:236px;margin-right:3px;',
						'div' => false
				));

				echo $this->Form->input('searchdateuntil', array(
						'class' => 'datepicker',
						'label' => false,
						'data-date-format' => 'yyyy-mm-dd',
						'style' => 'display:none;width:236px;',
						'div' => false
				));
				echo $this->Form->input('searcheventinfo', array(
						'label' => false,
						'class' => 'input-large',
						'style' => 'display:none;width:424px;',
						'div' => false
				));
				if ($isSiteAdmin) {
					echo $this->Form->input('searchemail', array(
							'label' => false,
							'class' => 'input-large',
							'style' => 'display:none;width:424px;',
							'div' => false
					));
				}
				echo $this->Form->input('searcheventid', array(
						'label' => false,
						'class' => 'input-large',
						'style' => 'display:none;width:424px;',
						'div' => false
				));
				echo $this->Form->input('searchhasproposal', array(
						'options' => array('0' => 'No', '1' => 'Yes', '2' => 'Any'),
						'class' => 'input',
						'label' => false,
						'style' => 'display:none;width:503px;',
						'div' => false
				));
				echo $this->Form->input('searchattribute', array(
						'label' => false,
						'class' => 'input-large',
						'style' => 'display:none;width:424px;',
						'div' => false
				));
			?>
			<span id="addRuleButton" class="btn btn-inverse" style="margin-bottom:10px;display:none;">Add</span>
			</div>
		</fieldset>
		<div class="overlay_spacing">
			<?php echo $this->Form->end();?>
			<div id="rule_table">
				<table style="background-color:white;">
					<tr style="width:680px;background-color:#0088cc;color:white;">
						<th style="width:100px;border:1px solid #cccccc;text-align: left;">Target</th>
						<th style="width:567px;border:1px solid #cccccc;border-right:0px;text-align: left;">Value</th>
						<th style="width:10px;border:1px solid #cccccc;border-left:0px;text-align: left;"></th>
					</tr>
					<?php
						$fields = array('published', 'org', 'tag', 'date', 'eventinfo', 'eventid', 'threatlevel', 'analysis', 'distribution', 'attribute', 'hasproposal');
						if ($isSiteAdmin) $fields[] = 'email';
						foreach ($fields as $k => $field):
					?>
						<tr id="row_<?php echo $field; ?>" class="hidden filterTableRow">
							<td id="key_<?php echo $field;?>" style="border:1px solid #cccccc;font-weight:bold;"><?php echo ucfirst($field); ?></td>
							<td id="value_<?php echo $field;?>" style="border:1px solid #cccccc;border-right:0px;"></td>
							<td id="delete_<?php echo $field;?>" style="border:1px solid #cccccc;border-left:0px;"><span class="icon-trash" title="Delete filter" role="button" tabindex="0" aria-label="Delete filter" onClick="indexFilterClearRow('<?php echo $field;?>')"></span></td>
						</tr>
					<?php
						endforeach;
					?>
				</table>
				<table style="background-color:white;width:100%;" id="FilterplaceholderTable">
					<tr class="filterTableRow">
						<td style="border:1px solid #cccccc;border-top:0px;font-weight:bold;width:100%;color:red;">No filters set - add filter terms above.</td>
					</tr>
				</table>
			</div>
			<?php echo $this->Form->create('Event', array('id' => 'test', 'url' => $baseurl . '/events/index'));?>
			<fieldset>
			<?php
				echo $this->Form->input('generatedURL', array(
					'label' => false,
					'class' => 'input',
					'style' => 'width:620px;display:none;',
					'div' => false
				));
			?>
			</fieldset>
			<div id = "generatedURL" style="word-wrap: break-word;"><br />Save this URL if you would like to use the same filter settings again<br /><div style="background-color:#f5f5f5;border: 1px solid #e3e3e3; border-radius:4px;padding:3px;background-color:white;"><span id="generatedURLContent"></span></div></div>
			<br />
			<span role="button" tabindex="0" aria-label="Apply" title="Apply" class="btn btn-primary" onClick="indexApplyFilters();">Apply</span>
			<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;">Cancel</span>
		</div>
</div>
<script type="text/javascript">
var formInfoValues = {};

var typeArray = {
		'tag' : <?php echo $tagJSON; ?>,
		'published' : ["No", "Yes", "Any"],
		'hasproposal' : ["No", "Yes", "Any"],
		'distribution' : [
						{"id" : "0", "value" : "Your organisation only"},
						{"id" : "1", "value" : "This community only"},
						{"id" : "2", "value" : "Connected communities"},
						{"id" : "3", "value" : "All communities"}
						],
		'threatlevel' : [
						{"id" : "1", "value" : "High"},
						{"id" : "2", "value" : "Medium"},
						{"id" : "3", "value" : "Low"},
						{"id" : "4", "value" : "Undefined"}
						],
		'analysis' : [
						{"id" : "0", "value" : "Initial"},
						{"id" : "1", "value" : "Ongoing"},
						{"id" : "2", "value" : "Completed"}
					]
};

var filterContext = "event";

var showorg = <?php echo $showorg == true ? 1 : 0; ?>;
var isSiteAdmin = <?php echo $isSiteAdmin == true ? 1 : 0; ?>;

var publishedOptions = ["No", "Yes", "Any"];

var hasproposalOptions = ["No", "Yes", "Any"];

var filtering = <?php echo $filtering; ?>;

var operators = ["OR", "NOT"];

var allFields = ["published", "tag", "date", "eventinfo", "eventid", "threatlevel", "distribution", "analysis", "attribute", "hasproposal"];

var simpleFilters = ["tag", "eventinfo", "eventid", "threatlevel", "distribution", "analysis", "attribute"];

var differentFilters = ["published", "date", "hasproposal"];

var typedFields = ["tag", "threatlevel", "distribution", "analysis"];

if (showorg == 1) {
	allFields.push("org");
	simpleFilters.push("org");
}

if (isSiteAdmin == 1) {
	allFields.push("email");
	simpleFilters.push("email");
}

var baseurl = "<?php echo $baseurl; ?>";

$(document).ready(function() {
	$('.datepicker').datepicker().on('changeDate', function(ev) {
		$('.dropdown-menu').hide();
	});
	indexEvaluateFiltering();
});

</script>
<?php echo $this->Js->writeBuffer();
