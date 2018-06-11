$(document).ready(function() {
	$('.matrix-interaction').click(function(event) {
		console.log($(this).attr('data-tag_name'));
	});

	$('#checkbox_attackMatrix_showAll').click(function() { toggleAttackMatrixCells(); });

	var scoredCells = $('.heatCell').filter(function() {
		return $(this).attr('data-score') > 0;
	});

	scoredCells.tooltip({ 
		container: 'body',
		placement: 'right',
	});
	
	scoredCells.hover(enteringScoredCell, leavingScoredCell);

	toggleAttackMatrixCells();
});

function toggleAttackMatrixCells() {
	var visibilityVal, displayVal;
	if($('#checkbox_attackMatrix_showAll').prop('checked')) {
		visibilityVal = 'visible';
		displayVal = 'table-cell';
		displayVal = '';
	} else {
		visibilityVal = 'hidden';
		displayVal = 'none';
	}

	$('.heatCell').filter(function() {
		return $(this).attr('data-score') == 0;
	}).css({ 
		visibility: visibilityVal,
	});
	var rowNum = $('.matrix-table > tbody > tr').length;
	var colNum = $('.matrix-table > thead > tr > th').length;
	for (var i=0; i<rowNum; i++) {
		var cellNoValues = $('.matrix-table > tbody > tr:nth-child('+i+') > td').filter(function() {
			return $(this).attr('data-score') == 0 || $(this).attr('data-score') === undefined;
		});
		if (cellNoValues.length == colNum) {
			$('.matrix-table > tbody > tr:nth-child('+i+')').css({ display: displayVal });
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
