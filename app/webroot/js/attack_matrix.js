(function () {
	$(document).ready(function() {
		var pickingMode = $('#matrix_container').data('picking-mode');
		if (pickingMode) {
			$('.ajax_popover_form .cell-picking').click(function() {
				// sumbit galaxy
				$('#GalaxyTargetId').val($(this).data('cluster-id'));
				$('#GalaxyViewMitreAttackMatrixForm').submit();
				cancelPopoverForm('#popover_form_large');
			});
			var scoredCells = $('.ajax_popover_form .heatCell').filter(function() {
				return $(this).attr('data-score') > 0;
			});
			$('#checkbox_attackMatrix_showAll').click(function() { toggleAttackMatrixCells('.ajax_popover_form'); });
		} else {
			$('.matrix-interaction').click(function(event) {
				var tagName = $(this).attr('data-tag_name');
				$('#attributesFilterField').val(tagName);
				filterAttributes('value', $('#attributesFilterField').data('eventid'));
			});
			var scoredCells = $('.info_container_eventgraph_network .heatCell').filter(function() {
				return $(this).attr('data-score') > 0;
			});
			$('#checkbox_attackMatrix_showAll').click(function() { toggleAttackMatrixCells('.info_container_eventgraph_network'); });
		}
	
	
		scoredCells.tooltip({ 
			container: 'body',
			placement: 'top',
		});
		
		scoredCells.hover(enteringScoredCell, leavingScoredCell);
	
		toggleAttackMatrixCells();
	});
	
	function toggleAttackMatrixCells(jfilter) {
		var visibilityVal, displayVal;
		if($(jfilter+' #checkbox_attackMatrix_showAll').prop('checked')) {
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
		for (var i=1; i<=rowNum; i++) {
			var cellNoValues = $(jfilter+' .matrix-table > tbody > tr:nth-child('+i+') > td').filter(function() {
				return $(this).attr('data-score') == 0 || $(this).attr('data-score') === undefined;
			});
			if (cellNoValues.length == colNum) {
				$(jfilter+' .matrix-table > tbody > tr:nth-child('+i+')').css({ display: displayVal });
			}
		}
	
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
}());
