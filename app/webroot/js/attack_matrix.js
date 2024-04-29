(function () {
	var pickedGalaxies = [];

	var chosen_options = {
		width: '100%',
	};

	$(function() {

		$('#attack-matrix-tabscontroller span').off('click.tab').on('click.tab', function (e) {
			$(this).tab('show');
		});

		// form
		$('.ajax_popover_form .cell-picking').off('click.picking').on('click.picking', function() {
			pickCell($(this), $(this).data('cluster-id'));
		});

		adapt_position_from_viewport();
		var firstTabId = $('#attack-matrix-tabscontroller span[data-toggle="tab"]:first').attr('href');
		resizeHeader(firstTabId);

		$('.ajax_popover_form .btn-matrix-submit').click(function() {
			makeTagging(pickedGalaxies);
			cancelPopoverForm('#popover_matrix');
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
			//var parentDom = document.getElementById('matrix_container').getBoundingClientRect();
			var x = target.width/2 - 30;
			var y = target.height/2 - 14;
			matrixContextualMenu(event.target, x, y, tagName, tagId, [
				'Attach cluster to event',
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
		$('.statistics_attack_matrix .matrix-interaction').off('click.interaction').on('click.interaction', function() {
			var clusterId = $(this).attr('data-cluster-id');
			window.location = baseurl + '/galaxy_clusters/view/' + clusterId;
		});
		scoredCells.hover(function() { enteringScoredCell($(this), '.statistics_attack_matrix'); }, function() { leavingScoredCell('.statistics_attack_matrix'); });
		$('.statistics_attack_matrix #checkbox_attackMatrix_showAll').off('click.showAll').on('click.showAll', function() { toggleAttackMatrixCells('.statistics_attack_matrix'); });

		// resize
		$('span[data-toggle="tab"]').off('shown.resize').on('shown.resize', function (e) {
			var tabId = $(e.target).attr('href');
			resizeHeader(tabId);
		});

		$('#attack-matrix-chosen-select').chosen(chosen_options).on('change', function(event, selected) {
			if (selected !== undefined) {
				var clusterId = selected.selected;
				clusterId = clusterId === undefined ? selected.deselected : clusterId;
				if (clusterId !== undefined) {
					var $option = $('td[data-cluster-id="' + clusterId + '"]');
					pickCell($option, clusterId, false);
				}
			}
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
		var jfilter = jfilterOrig === undefined ? activeTableId : jfilterOrig+' '+activeTableId;

		var visibilityVal, displayVal;
		if ($(jfilterOrig+' #checkbox_attackMatrix_showAll').prop('checked')) {
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

	function adapt_position_from_viewport() {
        $('#popover_matrix').css('top', document.documentElement.scrollTop + 120 + 'px');
	}

	function matrixContextualMenu(cell, x, y, tagName, tagId, func_name) {
		// get menu if already created
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
				case 'Attach cluster to event':
					span.addClass('fa fa-tag');
					span.click(function() {
						if(confirm('Are you sure you want to attach ' + tagName + ' to this event?')) {
							makeTagging([tagId]);
						}
						div.remove();
					});
					break;
				case 'Filter event':
					span.addClass('fa fa-filter');
					span.click(function() {
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
					span.click(function() {
						pickCell($(cell), tagId);
						div.remove();
					});
					break;
				default:
					span.addClass('fa fa-filter');
					span.click(function() {
						filterEvent(tagName, tagId);
						div.remove();
					});
					break;
			}
			div.append(span);
		}
		// register onClick on matrixTable to dismiss the menu
		$('.matrix-table > tbody > tr > td').off('click.dismissCM').one('click.dismissCM', function() {
			if (!$(this).hasClass('heatCell')) {
				div.remove();
			}
		});
		// register onLeave on the cell to dismiss the menu
		$(cell).off('mouseleave.dismissCM').one('mouseleave.dismissCM', function() {
			div.remove();
		});
	}

	function makeTagging(tagIds) {
		$('#GalaxyViewGalaxyMatrixForm #GalaxyTargetIds').val(JSON.stringify(tagIds));
		if ($('#GalaxyAttributeIds').length > 0) {
			$('#GalaxyAttributeIds').val(getSelected());
		}
		$('#GalaxyViewGalaxyMatrixForm').submit();
	}

	function filterEvent(tagName, tagId) {
		$('#attributesFilterField').val(tagName);
		filterAttributes('value');
	}

	function pickCell(cell, clusterId, recurseChosen) {
		recurseChosen = recurseChosen === undefined ? true : recurseChosen;
		clusterId = parseInt(clusterId);

		var $cells = $('td[data-cluster-id="' + clusterId + '"]');
		if (!cell.hasClass('cell-picked')) {
			pickedGalaxies.push(clusterId);
			$cells.addClass('cell-picked');
		} else { // remove class and data from array
			var i = pickedGalaxies.indexOf(clusterId);
			if (i > -1) {
				pickedGalaxies.splice(i, 1);
			}
			$cells.removeClass('cell-picked');
		}

		var $select = $('#attack-matrix-chosen-select');
		if (recurseChosen) {
			$select.val(pickedGalaxies).trigger('chosen:updated');
		}

		if (pickedGalaxies.length > 0) {
			$('.submit-container').show();
		} else {
			$('.submit-container').hide();
		}
	}
}());
