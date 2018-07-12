(function () {
	var minWidth = 1400;
	var savedTopOffset;
	var clusterNameToIdMapping = new Map();
	var typeaheadDataMatrixSearch;
	var pickedGalaxies = [];

	$(document).ready(function() {

		$('#attack-matrix-tabscontroller span').off('click.tab').on('click.tab', function (e) {
			$(this).tab('show');
			var jfilter = '.info_container_eventgraph_network';
			var colNum = $(jfilter+' .matrix-table > thead > tr > th :visible').length;
			$('#attackmatrix_div').css('min-width', 100*colNum);
			jfilter = '.ajax_popover_form';
			var colNum = $(jfilter+' .matrix-table > thead > tr > th :visible').length;
			$('#popover_form_large').css('min-width', 100*colNum);
			adapt_position_from_viewport(100*colNum);
		})

		// form
		$('.ajax_popover_form .cell-picking').off('click.picking').on('click.picking', function() {
			pickCell($(this), $(this).data('cluster-id'));
		});

		adapt_position_from_viewport();

		$('.ajax_popover_form .btn-matrix-submit').click(function() {
			makeTagging(pickedGalaxies);
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
			var tagId = $(this).attr('data-cluster-id');
			// trigger contextual menu
			var target = event.target.getBoundingClientRect();
			var parentDom = document.getElementById('matrix_container').getBoundingClientRect();
			var x = target.width/2 - 30; 
			var y = target.height/2 - 14; 
			matrixContextualMenu(event.target, x, y, tagName, tagId, [
				'Tag event',
				'Filter event',
				'Pick cell'
			]);
		});
		var scoredCells = $('.info_container_eventgraph_network .heatCell').filter(function() {
			return $(this).attr('data-score') > 0;
		});
		$('.info_container_eventgraph_network #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.info_container_eventgraph_network'); });
		scoredCells.hover(function() { enteringScoredCell($(this), '.info_container_eventgraph_network'); }, function() { leavingScoredCell('.info_container_eventgraph_network'); });
		$('.btn-matrix-submit').off('click.submit').on('click.submit', function() {
			makeTagging(pickedGalaxies);
		});

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

	function adapt_position_from_viewport(minOverwrite) {
		minOverwrite = minOverwrite !== undefined ? minOverwrite : minWidth;
		minOverwrite = minWidth > minOverwrite ? minWidth : minOverwrite;
		if($(window).width()*0.5+700 <= minOverwrite) {
			$('#popover_form_large').css('position', 'absolute');
			$('#popover_form_large').css('left', '10px');
			var topOff = $('#popover_form_large').offset().top;
			savedTopOffset =  topOff >= $(document).scrollTop() ? topOff - $(document).scrollTop() : topOff;
			$('#popover_form_large').css('top', savedTopOffset+$(document).scrollTop()+'px');
		} else {
			$('#popover_form_large').css('position', 'fixed');
			$('#popover_form_large').css('left', '');
			$('#popover_form_large').css('top', savedTopOffset);
		}
	}

	function matrixContextualMenu(cell, x, y, tagName, tagId, func_name) {
		// get menu if already created
		var should_append = false;
		var div = document.getElementById('matrixContextualMenu');
		if (div !== null) {
			div.remove();
		}
		div = document.createElement('div');
		div.id = 'matrixContextualMenu';
		cell.appendChild(div);
		
		div = $(div);
		div.empty();
		div.css('position', 'absolute');
		div.css('left', x+'px');
		div.css('top', y+'px');
		for (var i=0; i<func_name.length; i++) {
			var span = $(document.createElement('span'));
			span.addClass('icon-matrix-contextual-menu');
			span.attr('title', func_name[i]);
			switch(func_name[i]) {
				case 'Tag event':
					span.addClass('fa fa-tag');
					span.click(function(evt) { 
						if(confirm('Are you sure you want to attach ' + tagName + ' to this event?')) {
							makeTagging([tagId]);
						}
						div.remove();
					});
					break;
				case 'Filter event':
					span.addClass('fa fa-filter');
					span.click(function(evt) { 
						filterEvent(tagName, tagId);
						div.remove();
					});
					break;
				case 'Pick cell':
					if ($(cell).hasClass('cell-picked')) {
						span.addClass('fa fa-times');
					} else {
						span.addClass('fa fa-check');
					}
					span.click(function(evt) { 
						pickCell($(cell), tagId);
						div.remove();
					});
					break;
				default:
					span.addClass('fa fa-filter');
					span.click(function(evt) { 
						filterEvent(tagName, tagId);
						div.remove();
					});
					break;
			}
			div.append(span);
		}
		// register onClick on matrixTable to dismiss the menu
		$('.matrix-table > tbody > tr > td ').off('click.dismissCM').one('click.dismissCM', function(e) {
			if (!$(this).hasClass('heatCell')) {
				div.remove();
			}
		});
		// register onLeave on the cell to dismiss the menu
		$(cell).off('mouseleave.dismissCM').one('mouseleave.dismissCM', function(e) {
			div.remove();
		});
	}

	function makeTagging(tagIds) {
		$('#GalaxyTargetIds').val(JSON.stringify(tagIds));
		$('#GalaxyViewMitreAttackMatrixForm').submit();
	}

	function filterEvent(tagName, tagId) {
		$('#attributesFilterField').val(tagName);
		filterAttributes('value', $('#attributesFilterField').data('eventid'));
	}

	function pickCell(cell, tagId) {
		if (!cell.hasClass('cell-picked')) {
			pickedGalaxies.push(tagId);
			cell.addClass('cell-picked');
		} else { // remove class and data from array
			var i = pickedGalaxies.indexOf(tagId);
			if (i > -1) {
				pickedGalaxies.splice(i, 1);
			}
			cell.removeClass('cell-picked');
		}

		if (pickedGalaxies.length > 0) {
			$('.matrix-div-submit').show();
		} else {
			$('.matrix-div-submit').hide();
		}
	}
}());
