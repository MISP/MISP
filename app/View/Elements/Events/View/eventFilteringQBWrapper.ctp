<div id="eventFilteringQBWrapper" style="padding: 5px; display: none; border: 1px solid #dddddd; border-bottom: 0px;">
    <div id="eventFilteringQB"></div>
    <button id="eventFilteringQBSubmit" type="button" class="btn btn-inverse" style="display:block; margin-left:auto; margin-right: 0"> <i class="fa fa-filter"></i> Filter </button>
</div>

<script>
function triggerEventFilteringTool(clicked) {
	var qbOptions = {
		plugins: {
			'filter-description' : {
				mode: 'inline'
			},
			'unique-filter': null,
			'bt-tooltip-errors': null,
			'not-group': null,
		},
		allow_empty: true,
		display_empty_filter: false,
		conditions: ['OR'],
		lang: {
			operators: {
				equal: 'show'
			}
		},
		filters: [
			{
				"input": "select",
				"type": "string",
				"operators": [
					"equal",
				],
				"unique": false,
				"id": "category",
				"label": "Category",
				"values": {
					"File": "file",
					"Network": "network",
					"Financial": "financial"
				}
			},
			{
				"input": "radio",
				"type": "integer",
				"operators": [
					"equal",
				],
				"unique": true,
				"id": "proposal",
				"label": "Proposal",
				"values": {
					0: "Both",
					1: "Proposal only",
					2: "Exclude proposal"
				}
			},
			{
				"input": "radio",
				"type": "integer",
				"operators": [
					"equal",
				],
				"unique": true,
				"id": "correlation",
				"label": "Correlation",
				"values": {
					0: "Both",
					1: "Correlation only",
					2: "Exclude correlation"
				}
			},
			{
				"input": "radio",
				"type": "integer",
				"operators": [
					"equal",
				],
				"unique": true,
				"id": "warning",
				"label": "Warning",
				"values": {
					0: "Both",
					1: "Warning only",
					2: "Exclude warning"
				}
			},
			{
				"input": "radio",
				"type": "integer",
				"operators": [
					"equal",
				],
				"unique": true,
				"id": "deleted",
				"label": "Deleted",
				"values": {
					0: "Both",
					1: "Deleted only",
					2: "Exclude deleted"
				}
			},
			{
				"input": "radio",
				"type": "integer",
				"operators": [
					"equal",
				],
				"unique": true,
				"id": "includeRelatedTags",
				"label": "Related Tags",
				"values": {
					0: "None",
					1: "Yes"
				}
			},
		],
		rules: rules = {
			condition: 'OR',
			not: false,
			valid: true,
			rules: [
				{
					condition: 'OR',
					rules: [{
						field: 'category',
						id: 'category',
						input: 'select',
						operator: 'equal',
						type: 'string',
						value: 'Financial',
					}]
				},
				{
					field: 'proposal',
					id: 'proposal',
					input: 'radio',
					operator: 'equal',
					type: 'radio',
					value: 0,
				},
				{
					field: 'correlation',
					id: 'correlation',
					input: 'radio',
					operator: 'equal',
					type: 'radio',
					value: 0,
				},
				{
					field: 'warning',
					id: 'warning',
					input: 'radio',
					operator: 'equal',
					type: 'radio',
					value: 0,
				},
				{
					field: 'deleted',
					id: 'deleted',
					input: 'radio',
					operator: 'equal',
					type: 'radio',
					value: 0,
				},
				{
					field: 'includeRelatedTags',
					id: 'includeRelatedTags',
					input: 'radio',
					operator: 'equal',
					type: 'radio',
					value: 0,
				},
			],
			flags: {
				no_add_group: true,
			}
		},
		icons: {
			add_group: 'fa fa-plus-square',
			add_rule: 'fa fa-plus-circle',
			remove_group: 'fa fa-minus-square',
			remove_rule: 'fa fa-minus-circle',
			error: 'fa fa-exclamation-triangle'
	   },
	};


	var $wrapper = $('#eventFilteringQBWrapper');
	var $ev = $('#eventFilteringQB');
	var querybuilderTool = $ev.queryBuilder(qbOptions);
	querybuilderTool = querybuilderTool[0].queryBuilder;
	$wrapper.toggle('blind', 100, { direction: 'up' });
}
</script>
