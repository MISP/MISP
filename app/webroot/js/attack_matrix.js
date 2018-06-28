(function () {
	var minWidth = 1400;
	var clusterNameToIdMapping = new Map();
	var typeaheadDataMatrixSearch;
	$(document).ready(function() {
		var pickedGalaxies = [];

		$('#attack-matrix-tabscontroller span').off('click.tab').on('click.tab', function (e) {
			$(this).tab('show');
		})

		// form
		$('.ajax_popover_form .cell-picking').off('click.picking').on('click.picking', function() {
			// sumbit galaxy
			if (!$(this).hasClass('cell-picked')) {
				pickedGalaxies.push($(this).data('cluster-id'));
				$(this).addClass('cell-picked');
			} else { // remove class and data from array
				var i = pickedGalaxies.indexOf($(this).data('cluster-id'));
				if (i > -1) {
					pickedGalaxies.splice(i, 1);
				}
				$(this).removeClass('cell-picked');
			}
		});

		if($(window).width() <= minWidth) {
			$('#popover_form_large').css('position', 'absolute');
			$('#popover_form_large').css('left', '10px');
			$('#popover_form_large').css('top', '35px');
		} else {
			$('#popover_form_large').css('position', 'fixed');
			$('#popover_form_large').css('left', '');
		}

		$('.ajax_popover_form .btn-matrix-submit').click(function() {
			$('#GalaxyTargetIds').val(JSON.stringify(pickedGalaxies));
			$('#GalaxyViewMitreAttackMatrixForm').submit();
			cancelPopoverForm('#popover_form_large');
		});
		var scoredCells = $('.ajax_popover_form .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		scoredCells.hover(function() { enteringScoredCell($(this), '.ajax_popover_form'); }, function() { leavingScoredCell('.ajax_popover_form'); });
		$('.ajax_popover_form #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.ajax_popover_form'); });

		// info container
		$('.info_container_eventgraph_network .matrix-interaction').off('click.interaction').on('click.interaction', function(event) {
			var tagName = $(this).attr('data-tag_name');
			$('#attributesFilterField').val(tagName);
			filterAttributes('value', $('#attributesFilterField').data('eventid'));
		});
		var scoredCells = $('.info_container_eventgraph_network .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		$('.info_container_eventgraph_network #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.info_container_eventgraph_network'); });
		scoredCells.hover(function() { enteringScoredCell($(this), '.info_container_eventgraph_network'); }, function() { leavingScoredCell('.info_container_eventgraph_network'); });

		// statistic page
		var scoredCells = $('.statistics_attack_matrix .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		$('.statistics_attack_matrix .matrix-interaction').off('click.interaction').on('click.interaction', function(event) {
			var clusterId = $(this).attr('data-cluster-id');
			window.location = '/galaxy_clusters/view/' + clusterId;
		});
		scoredCells.hover(function() { enteringScoredCell($(this), '.statistics_attack_matrix'); }, function() { leavingScoredCell('.statistics_attack_matrix'); });
		$('.statistics_attack_matrix #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.statistics_attack_matrix'); });
	
		// resize
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
	
	function enteringScoredCell(elem, jfilter) {
		var score = elem.attr('data-score');
		adjust_caret_on_scale(score, jfilter);
	}
	
	function leavingScoredCell(jfilter) {
		adjust_caret_on_scale(0, jfilter);
	}
	
	function adjust_caret_on_scale(score, jfilter) {
		var totWidth = $(jfilter + ' #matrix-heatmap-legend').width();
		var maxScore = parseInt($(jfilter + ' #matrix-heatmap-maxval').text());
		var x = (parseInt(score)/maxScore)*totWidth;
		$(jfilter + ' #matrix-heatmap-legend-caret').css({
			left: x
		});
		$(jfilter + ' #matrix-heatmap-legend-caret-value').text(score);
	}
}());
