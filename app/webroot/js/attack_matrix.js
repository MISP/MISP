(function () {
	var clusterNameToIdMapping = new Map();
	var typeaheadDataMatrixSearch;
	var typeaheadOptionMatrix = {
		source: function (query, process) {
			if (typeaheadDataMatrixSearch === undefined) { // caching
				typeaheadDataMatrixSearch = get_typeaheadDataMatrix_search();
			}
			process(typeaheadDataMatrixSearch);
		},
		updater: function(value) {
			if (value !== undefined) {
				// highlight matching cells
				var clusterId = clusterNameToIdMapping.get(value);
				var matchingC = $('.ajax_popover_form .cell-picking[data-cluster-id='+clusterId+']');
				var notMatchingC = $('.ajax_popover_form .cell-picking[data-cluster-id!='+clusterId+']');
				matchingC.css('box-shadow', 'green 0px 0px 4px 2px');
				notMatchingC.css('box-shadow', '');
			}
		},
	}

	$(document).ready(function() {
		$('#attack-matrix-tabscontroller span').off('click.tab').on('click.tab', function (e) {
			$(this).tab('show');
		})

		$('.ajax_popover_form .cell-picking').off('click.picking').on('click.picking', function() {
			// sumbit galaxy
			$('#GalaxyTargetId').val($(this).data('cluster-id'));
			$('#GalaxyViewMitreAttackMatrixForm').submit();
			cancelPopoverForm('#popover_form_large');
		});
		var scoredCells = $('.ajax_popover_form .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		$('.ajax_popover_form #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.ajax_popover_form'); });
		$('#pick-matrix-elem').typeahead(typeaheadOptionMatrix);
		$('.info_container_eventgraph_network .matrix-div-search').hide()

		$('.matrix-interaction').off('click.interaction').on('click.interaction', function(event) {
			var tagName = $(this).attr('data-tag_name');
			$('#attributesFilterField').val(tagName);
			filterAttributes('value', $('#attributesFilterField').data('eventid'));
		});
		var scoredCells = $('.info_container_eventgraph_network .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		$('.info_container_eventgraph_network #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.info_container_eventgraph_network'); });
	
		scoredCells.hover(enteringScoredCell, leavingScoredCell);

		$('span[data-toggle="tab"]').off('shown.resize').on('shown.resize', function (e) {
			var tabId = $(e.target).attr('href');
			resizeHeader(tabId);
		});

	
	});
	
	function resizeHeader(tabId) {
		if (tabId === undefined) {
			tabId = '';
		}
		// resize fixed header div based on dimension of th cell
		$(tabId + ' .matrix-table').each(function() {
			var max_height = 0;
			var div = $(this).find('thead > tr > th > div');
			var cell = $(this).find('thead > tr > th');
			for(var i=0; i<cell.length; i++) {
				var cellH = $(cell[i]).css('height')
				max_height = $(cell[i]).height() > max_height ? $(cell[i]).height() : max_height;
				$(div[i]).css({
					width: $(cell[i]).css('width'),
					height: cellH,
				});
			}
			$(tabId + ' .header-background').css('height', max_height+'px');
		});
	}

	function toggleAttackMatrixCells(jfilterOrig) {
		// get active tab
		var activeTableId = $('#attack-matrix-tabscontroller > li.active > span').attr('href');
		jfilter = jfilterOrig === undefined ? activeTableId : jfilterOrig+' '+activeTableId;

		var visibilityVal, displayVal;
		if($(jfilterOrig+' #checkbox_attackMatrix_showAll').prop('checked')) {
			visibilityVal = 'visible';
			displayVal = 'table-cell';
			displayVal = '';
		} else {
			visibilityVal = 'hidden';
			displayVal = 'none';
		}
	
		$(jfilter+' .heatCell').filter(function() {
			return $(this).attr('data-score') == 0;
		}).css({ 
			visibility: visibilityVal,
		});
		var rowNum = $(jfilter+' .matrix-table > tbody > tr').length;
		var colNum = $(jfilter+' .matrix-table > thead > tr > th').length;

		// hide empty row
		for (var i=1; i<=rowNum; i++) {
			var cellNoValues = $(jfilter+' .matrix-table > tbody > tr:nth-child('+i+') > td').filter(function() {
				return $(this).attr('data-score') == 0 || $(this).attr('data-score') === undefined;
			});
			if (cellNoValues.length == colNum) {
				$(jfilter+' .matrix-table > tbody > tr:nth-child('+i+')').css({ display: displayVal });
			}
		}
	
		// hide empty column
		for (var i=1; i<=colNum; i++) {
			var cellNoValues = $(jfilter+' .matrix-table tr td:nth-child('+i+')').filter(function() {
				return $(this).attr('data-score') == 0 || $(this).attr('data-score') === undefined;
			});
			if (cellNoValues.length == rowNum) {
				$(jfilter+' .matrix-table tr td:nth-child('+i+')').css({ display: displayVal });
				$(jfilter+' .matrix-table tr th:nth-child('+i+')').css({ display: displayVal });
			}
		}
	}
	
	function enteringScoredCell() {
		var score = $(this).attr('data-score');
		adjust_caret_on_scale(score);
	}
	
	function leavingScoredCell() {
		adjust_caret_on_scale(0);
	}
	
	function adjust_caret_on_scale(score) {
		var totWidth = $('#matrix-heatmap-legend').width();
		var maxScore = parseInt($('#matrix-heatmap-maxval').text());
		var x = (parseInt(score)/maxScore)*totWidth;
		$('#matrix-heatmap-legend-caret').css({
			left: x
		});
		$('#matrix-heatmap-legend-caret-value').text(score);
	}

	function get_typeaheadDataMatrix_search() {
		var cells = $('.ajax_popover_form .matrix-table > tbody > tr > td');
		var toret = [];
		cells.each(function() {
			var text = $(this).text();
			var title = $(this).attr('title');
			if (text !== undefined && title !== undefined) {
				toret.push(text + ' ['+ title+']');
				clusterNameToIdMapping.set(text + ' ['+ title+']', $(this).data('cluster-id'));
			}
		});
		return toret;
	}
}());
