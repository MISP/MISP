<?php echo $this->Html->script('moment-with-locales'); ?>

<div class="input-group input-daterange">
<?php
	echo $this->Form->input('first_seen', array(
			'div' => 'input clear larger-input-field',
			'style' => 'width: 240px;',
			'required' => false,
			'label' => __('First seen') . '<span class="fa fa-calendar label-icon"></span>'
			));
	echo $this->Form->input('last_seen', array(
			'div' => 'input text larger-input-field',
			'style' => 'width: 240px;',
			'required' => false,
			'label' => __('Last seen') . '<span class="fa fa-calendar label-icon"></span>'
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
	['us', 999, 1],
];

class MicroDatetime {
	constructor(value) {
		if (value === undefined || value === "") {
			this.moment = undefined;
			this.micro = 0;
		} else {
			this.isoMicroRegex = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})T(?<hour>\d{2}):(?<min>\d{2}):(?<sec>\d{2}).(?<milli>\d{3})(?<micro>\d*)(?<tz>\D\S*)/g;
			this.tzRegex = /(?<datetime>.{23})(?<tz>\D\S*)/g;

			// check if ISO 8601 format
			if (String(value).includes('T')) {
				value = String(value);
				this.moment = new moment(value);
				this.micro = this.isoMicroRegex.exec(value).groups.micro;
			} else { // UNIX timestamp (in sec)
				var timestamp = parseInt(value);
				var timestamp_str = String(timestamp);
				if (timestamp === '' || timestamp === undefined || timestamp === null || isNaN(timestamp)) {
					this.moment = moment(0);
					this.micro = 0;
				} else {
					var all_milli = parseInt(timestamp)*1000;
					all_milli = isNaN(all_milli) || all_milli === undefined ? 0 : all_milli;
					this.moment = new Date(all_milli);
					this.micro = 0;
				}
			}
		}
	}

	get_microISO() {
		if (this.moment === undefined || this.moment === null) {
			return "";
		}
		var tz = this.tzRegex.exec(this.moment.toISOString(true)).groups.tz;
		var str = this.moment.toISOString(true);
		str = str.replace(tz, pad_zero(this.micro, 3)+tz);
		return str;
	}
}

function pad_zero(val, pad) {
	var ret = '';
	for (var i=0; i<(pad-String(val).length); i++) {
		ret += '0';
	}
	ret += String(val);
	return ret;
}

function get_slider_and_input(type, scale, factor, max) {
	var row = $('<tr></tr>');
	var td1 = $('<td></td>');
	var td2 = $('<td></td>');
	var td3 = $('<td></td>');
	var label = $('<span>'+scale+'</span>').css({fontWeight: 'bold'});
	var input = $('<input id="input-time-'+type+'-'+scale+'" type="number" min=0 max='+max+' step=1 value=0 factor='+factor+' scale='+scale+'></input>').css({width: '50px', margin: '5px'});
	var slider_width = '200px';
	var slider = $('<input id="slider-time-'+type+'-'+scale+'" type="range" min=0 max='+max+' step=1 value=0 factor='+factor+' scale='+scale+'></input>').css({width: slider_width, margin: '5px'});
	
	row.append(td1.append(label))
	   .append(td2.append(input))
	   .append(td3.append(slider))
	return row;
}

function reflect_change_on_sliders(seen, skip_input_update) {
	if (seen == 'both' || seen == 'first') {
		var f_val = $('#'+controller+'FirstSeen').val();
		var f_microdatetime = new MicroDatetime(f_val);

		// mirror slider and input field
		$('#input-time-first-'+time_vals[4]).val(f_microdatetime.micro);
		$('#slider-time-first-'+time_vals[4]).val(f_microdatetime.micro);

		$('#'+controller+'FirstSeen').datepicker('setDate', f_microdatetime.moment);
	}

	if (seen == 'both' || seen == 'last') {
		var l_val = $('#'+controller+'LastSeen').val();
		var l_microdatetime = new MicroDatetime(l_val);

		// mirror slider and input field
		$('#input-time-last-'+time_vals[4]).val(f_microdatetime.micro);
		$('#slider-time-last-'+time_vals[4]).val(f_microdatetime.micro);

		$('#'+controller+'LastSeen').datepicker('setDate', l_microdatetime.moment);
	}

	if (!skip_input_update) {
		reflect_change_on_input(seen);
	}
}

// get data stored in sliders
function get_time_from_slider(which) {
	var micro = 0;
	var dp = which == 'first' ? $('#'+controller+'FirstSeen') : $('#'+controller+'LastSeen');
	var t = dp.datepicker('getDate');
	t = t === null ? new Date(0) : t;
	$('#precision_tool_'+which).find('input[type="number"]').each(function() {
		switch($(this).attr('scale')) {
			case 'us':
				micro = parseInt($(this).val());
				break;
		}
	});
	microdatetime = new MicroDatetime(t.toISOString(true));
	microdatetime.micro = micro;
	return microdatetime
}

function reflect_change_on_input(seen) {
	if ($('#seen_precision_tool').prop('checked')) {
		if (seen == 'both' || seen == 'first') {
			var microdatetime = get_time_from_slider('first');
			if($("#"+controller+"FirstSeen").val() !== '') {
				$("#"+controller+"FirstSeen").val(microdatetime.get_microISO());
			}
		}

		if (seen == 'both' || seen == 'last') {
			var microdatetime = get_time_from_slider('last');
			if($("#"+controller+"LastSeen").val() !== '') {
				$("#"+controller+"LastSeen").val(microdatetime.get_microISO());
			}
		}
	}
}
$(document).ready(function() {
	$('.input-daterange').datepicker({
		preventMultipleSet: true,
		//format: 'mm/dd/yyyy',
		format: {
			toDisplay: function(date, format, lang) {
				var d = moment(date.toISOString(true));
				return d.toISOString(true);
			},
			toValue: function(str, format, lang) {
				var ret = typeof str === 'object' ? str : new MicroDatetime(str).moment;
				return new Date(ret.valueOf());
			}
		},
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
	
	//$('#'+controller+'FirstSeen').on("focusout", function(event) {
	//	if ($('#seen_precision_tool').prop('checked')) {
	//		//reflect_change_on_input('first');
	//	}
	//});
	//$('#'+controller+'LastSeen').on("focusout", function(event) {
	//	if ($('#seen_precision_tool').prop('checked')) {
	//		//reflect_change_on_input('last');
	//	}
	//});

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
		reflect_change_on_sliders('first', true);
		event.preventDefault();
	});

	$('form').submit(function( event ) {
		reflect_change_on_input('both');
	});

	reflect_change_on_sliders('both', false);

});
</script>
