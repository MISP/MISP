<div class="input-group input-daterange">
<?php
	echo $this->Form->input('first_seen', array(
			'div' => 'input clear larger-input-field',
			'style' => 'width: 240px;',
			'required' => false,
			'label' => __('First seen (UTC nano)') . '<span class="fa fa-calendar label-icon"></span>'
			));
	echo $this->Form->input('last_seen', array(
			'div' => 'input text larger-input-field',
			'style' => 'width: 240px;',
			'required' => false,
			'label' => __('Last seen (UTC nano)') . '<span class="fa fa-calendar label-icon"></span>'
			));
?>
</div>

<div class="input clear"></div>

<div class="clear">
	<label style="display: inline-block">
		<input id="seen_precision_tool" type="checkbox" style="margin-top: 0px;"></select>
    			<?php echo(__('Enable precision tool'))?>
		<span class="fa fa-clock-o"></span>
	</label>
</div>


<script>
var controller = "<?php echo(substr(ucfirst($this->params->controller), 0, -1)); ?>"; // get current controller name fo that we can access all form fields
var time_vals = [
	['Hour', 23, 1000*1000*1000*60*60],
	['Minute', 59, 1000*1000*1000*60],
	['Second', 59, 1000*1000*1000],
	['ms', 999, 1000*1000],
	['us', 999, 1000],
	['ns', 999, 1],
];


function format_nano_to_time(nanosec) {
	var nanoStr = String(nanosec);
	var milli = parseInt(nanosec/1000000);
	var micro = nanoStr.slice(-6, -3);
	var nano = nanoStr.slice(-3);
	var d = new Date(milli);
	var s = (d.toISOString().split('T')[1]).slice(0, -1);
	if (micro != 0) {
		s += String(micro);
	} else if (micro == 0 && nano != 0) {
		s += "000";
	}
	s += nano != 0 ? String(nano) : "";
	return s;
}

function get_slider_and_input(type, scale, factor, max) {
	var row = $('<tr></tr>');
	var td1 = $('<td></td>');
	var td2 = $('<td></td>');
	var td3 = $('<td></td>');
	var label = $('<span>'+scale+'</span>').css({fontWeight: 'bold'});
	var input = $('<input id="input-time-'+type+'-'+scale+'" type="number" min=0 max='+max+' step=1 value=0 factor='+factor+'></input>').css({width: '50px', margin: '5px'});
	var slider_width = "<?php if ($ajax) { echo '200px'; } else { echo '300px'; } ?>";
	var slider = $('<input id="slider-time-'+type+'-'+scale+'" type="range" min=0 max='+max+' step=1 value=0 factor='+factor+'></input>').css({width: slider_width, margin: '5px'});
	
	row.append(td1.append(label))
	   .append(td2.append(input))
	   .append(td3.append(slider))
	return row;
}

function reflect_change_on_sliders(seen, skip_input_update) {
	if (seen == 'both' || seen == 'first') {
		var f_nanosec = $('#'+controller+'FirstSeen').val();
		if (f_nanosec === '') {
			f_nanosec = null;
			var f_nano = 0;
			var f_micro = 0;
			var f_milli = 0;
			var f_milli = 0;
			var f_sec = 0;
			var f_min = 0;
			var f_hour = 0;
			var f_d = null;
		} else {
			var f_nano = parseInt(f_nanosec.slice(-3));
			var f_micro = parseInt(f_nanosec.slice(-6, -3));
			var f_milli = parseInt(f_nanosec/1000000);
			var f_d = new Date(f_milli);
			var f_milli = parseInt(f_d.getUTCMilliseconds());
			var f_sec = parseInt(f_d.getUTCSeconds());
			var f_min = parseInt(f_d.getUTCMinutes());
			var f_hour = parseInt(f_d.getUTCHours());
		}
		// mirror slider and input field
		$('#input-time-first-'+time_vals[0]).val(f_hour);
		$('#slider-time-first-'+time_vals[0]).val(f_hour);

		$('#input-time-first-'+time_vals[1]).val(f_min);
		$('#slider-time-first-'+time_vals[1]).val(f_min);

		$('#input-time-first-'+time_vals[2]).val(f_sec);
		$('#slider-time-first-'+time_vals[2]).val(f_sec);

		$('#input-time-first-'+time_vals[3]).val(f_milli);
		$('#slider-time-first-'+time_vals[3]).val(f_milli);

		$('#input-time-first-'+time_vals[4]).val(f_micro);
		$('#slider-time-first-'+time_vals[4]).val(f_micro);

		$('#input-time-first-'+time_vals[5]).val(f_nano);
		$('#slider-time-first-'+time_vals[5]).val(f_nano);

		$('#'+controller+'FirstSeen').datepicker('setDate', f_d);
	}

	else if (seen == 'both' || seen == 'last') {
		var l_nanosec = $('#'+controller+'LastSeen').val();
		if (l_nanosec === '') {
			l_nanosec = null;
			var l_nano = 0;
			var l_micro = 0;
			var l_milli = 0;
			var l_milli = 0;
			var l_sec = 0;
			var l_min = 0;
			var l_hour = 0;
			var l_d = null;
		} else {
			var l_nano = parseInt(l_nanosec.slice(-3));
			var l_micro = parseInt(l_nanosec.slice(-6, -3));
			var l_milli = parseInt(l_nanosec/1000000);
			var l_d = new Date(l_milli);
			var l_milli = parseInt(l_d.getUTCMilliseconds());
			var l_sec = parseInt(l_d.getUTCSeconds());
			var l_min = parseInt(l_d.getUTCMinutes());
			var l_hour = parseInt(l_d.getUTCHours());
		}
		// mirror slider and input field
		$('#input-time-last-'+time_vals[0]).val(l_hour);
		$('#slider-time-last-'+time_vals[0]).val(l_hour);

		$('#input-time-last-'+time_vals[1]).val(l_min);
		$('#slider-time-last-'+time_vals[1]).val(l_min);

		$('#input-time-last-'+time_vals[2]).val(l_sec);
		$('#slider-time-last-'+time_vals[2]).val(l_sec);

		$('#input-time-last-'+time_vals[3]).val(l_milli);
		$('#slider-time-last-'+time_vals[3]).val(l_milli);

		$('#input-time-last-'+time_vals[4]).val(l_micro);
		$('#slider-time-last-'+time_vals[4]).val(l_micro);

		$('#input-time-last-'+time_vals[5]).val(l_nano);
		$('#slider-time-last-'+time_vals[5]).val(l_nano);

		$('#'+controller+'LastSeen').datepicker('setDate', l_d);
	}
	if (!skip_input_update) {
		reflect_change_on_input(seen);
	}
}

function reflect_change_on_input(seen) {
	if ($('#seen_precision_tool').prop('checked')) {
		var first_val = 0;
		if (seen == 'both' || seen == 'first') {
			$('#precision_tool_first').find('input[type="number"]').each(function() {
				first_val += $(this).val()*$(this).attr('factor');
			});
			if($("#"+controller+"FirstSeen").val() !== '') {
				var the_date = $("#"+controller+"FirstSeen").val().slice(0, 10);
				$("#"+controller+"FirstSeen").val(the_date + '@' + format_nano_to_time(first_val));
			}
		}

		if (seen == 'both' || seen == 'last') {
			var last_val = 0;
			$('#precision_tool_last').find('input[type="number"]').each(function() {
				last_val += $(this).val()*$(this).attr('factor');
			});
			if($("#"+controller+"LastSeen").val() !== '') {
				var the_date = $("#"+controller+"LastSeen").val().slice(0, 10);
				$("#"+controller+"LastSeen").val(the_date + '@' + format_nano_to_time(last_val));
			}
		}
	}
}
$(document).ready(function() {
	$('.input-daterange').datepicker({
		preventMultipleSet: true,
		skipSettingDateOnPaste: true,
		format: 'mm/dd/yyyy',
		todayHighlight: true
	});
	
	// create sliders
	var div = $('<div id="precision_tool" class="precision-tool" style="display: none"></div>');
	var content = $('<table id="precision_tool_first" style="float: left;"></table>');
	for (var i=0; i<time_vals.length; i++) {
		var type = time_vals[i][0];
		var max = time_vals[i][1];
		var factor = time_vals[i][2];
		var row = get_slider_and_input('first', type, factor, max)
		content.append(row);
	}
	div.append(content);
	var content = $('<table id="precision_tool_last" style="float:left; margin-left: 15px;"></table>');
	for (var i=0; i<time_vals.length; i++) {
		var type = time_vals[i][0];
		var max = time_vals[i][1];
		var factor = time_vals[i][2];
		var row = get_slider_and_input('last', type, factor, max)
		content.append(row);
	}
	div.append(content);
	var sliders_container = "<?php if ($this->params->controller === 'attributes') { echo 'fieldset'; } else { echo '#meta-div'; } ?>";
	$(sliders_container).append(div);

	time_vals.forEach(function(elem) {
		$('#input-time-first-'+elem[0]).on('input', function(e) {
			$('#slider-time-first-'+elem[0]).val($(this).val());
			reflect_change_on_input('first');
		});
		$('#slider-time-first-'+elem[0]).on('input', function(e) {
			$('#input-time-first-'+elem[0]).val($(this).val());
			reflect_change_on_input('first');
		});

		$('#input-time-last-'+elem[0]).on('input', function(e) {
			$('#slider-time-last-'+elem[0]).val($(this).val());
			reflect_change_on_input('last');
		});
		$('#slider-time-last-'+elem[0]).on('input', function(e) {
			$('#input-time-last-'+elem[0]).val($(this).val());
			reflect_change_on_input('last');
		});
	});

	$('#seen_precision_tool').change(function(e) {
		if(e.target.checked) {
			$('#precision_tool').show();
		} else {
			$('#precision_tool').hide();
		}
	});

	$('#'+controller+'FirstSeen').on("focus", function(event) {
		$('#seen_precision_tool').prop('checked', true);
		$('#precision_tool').show();
	});
	$('#'+controller+'LastSeen').on("focus", function(event) {
		$('#seen_precision_tool').prop('checked', true);
		$('#precision_tool').show();
	});
	
	$('#'+controller+'FirstSeen').on("focusout", function(event) {
		if ($('#seen_precision_tool').prop('checked')) {
			reflect_change_on_input('first');
		}
	});
	$('#'+controller+'LastSeen').on("focusout", function(event) {
		if ($('#seen_precision_tool').prop('checked')) {
			reflect_change_on_input('last');
		}
	});

	$('#'+controller+'LastSeen').on("paste", function(event) {
		// prefetch clipboard text and apply change
		var datetimeString;
		if (event.originalEvent.clipboardData && event.originalEvent.clipboardData.types
		    && $.inArray('text/plain', event.originalEvent.clipboardData.types) !== -1) {
			datetimeString = event.originalEvent.clipboardData.getData('text/plain');
		}
		else if (window.clipboardData) {
			datetimeString = window.clipboardData.getData('Text');
		}
		$(this).val(datetimeString);
		reflect_change_on_sliders('last', true);
		event.preventDefault();
	});

	$('#'+controller+'FirstSeen').on("paste", function(event) {
		// prefetch clipboard text and apply change
		var datetimeString;
		if (event.originalEvent.clipboardData && event.originalEvent.clipboardData.types
		    && $.inArray('text/plain', event.originalEvent.clipboardData.types) !== -1) {
			datetimeString = event.originalEvent.clipboardData.getData('text/plain');
		}
		else if (window.clipboardData) {
			datetimeString = window.clipboardData.getData('Text');
		}
		$(this).val(datetimeString);
		reflect_change_on_sliders('last', true);
		event.preventDefault();
	});

	$('form').submit(function( event ) {
		reflect_change_on_input('both');
	});

	reflect_change_on_sliders('both');

});
</script>
