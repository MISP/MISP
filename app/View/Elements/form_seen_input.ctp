<?php echo $this->Html->script('moment-with-locales'); ?>

<div class="input-group">
<?php
	echo $this->Form->input('first_seen', array(
			'type' => 'text',
			'div' => 'input hidden',
			'required' => false,
			));
	echo $this->Form->input('last_seen', array(
			'type' => 'text',
			'div' => 'input hidden',
			'required' => false,
			));
?>
</div>

<div class="input clear"></div>


<script>
var controller = "<?php echo(substr(ucfirst($this->params->controller), 0, -1)); ?>"; // get current controller name fo that we can access all form fields
var time_vals = [
	['Hour', 23, 1000*1000*60*60],
	['Minute', 59, 1000*1000*60],
	['Second', 59, 1000*60],
	['ms', 999, 1000],
	['us', 999, 1],
];

class MicroDatetime {
	constructor(value) {
		this.isoDatetimeMicroRegex = /(\d{4})-(\d{2})-(\d{2})T(\d{2})\:(\d{2})\:(\d{2})\.(\d{3})(\d*)(\D\S*)/g;
		this.isotimeMicroRegex = /(\d{2})\:(\d{2})\:(\d{2})\.(\d{3})(\d*)(\D\S*)/g;
		this.numberRegex = /^(\-|\+)?([0-9]+|Infinity)$/g;

		if (value === undefined || value === "") {
			this.moment = undefined;
			this.micro = 0;
		} else {
			// check if timestamp UNIX timestamp (in sec)
			if (this.numberRegex.test(value)) {
				var timestamp = parseInt(value);
				var timestamp_str = String(timestamp);
				if (timestamp === '' || timestamp === undefined || timestamp === null || isNaN(timestamp)) {
					this.moment = moment(0);
					this.micro = 0;
				} else {
					var all_milli = parseInt(timestamp)*1000;
					all_milli = isNaN(all_milli) || all_milli === undefined ? 0 : all_milli;
					this.moment = moment(all_milli);
					this.micro = 0;
				}
			// check if only a time
			} else { // let moment parse the date
				try {
					value = String(value);
					this.moment = new moment(value);
					if (this.moment.isValid()) {
						var res = this.isoDatetimeMicroRegex.exec(value);
						var micro_str = res !== null ? res[8] : 0;
						this.micro = parseInt(micro_str);
						this.micro = isNaN(this.micro) ? 0 : this.micro;
					} else {
						this.moment = undefined;
						this.micro = 0;
						showMessage('fail', 'Failed to parse the date: <strong>' + value + '</strong>');
					}
				} catch (err) {
					if (this.isotimeMicroRegex.test(value)) {
						this.moment = moment(value, "HH:mm:ss.SSSSSSZ");
						if (this.moment.isValid()) {
							var res = this.isotimeMicroRegex.exec(value);
							var micro_str = res !== null ? res[8] : 0;
							this.micro = parseInt(micro_str);
							this.micro = isNaN(this.micro) ? 0 : this.micro;
						} else {
							this.moment = undefined;
							this.micro = 0;
							showMessage('fail', 'Failed to parse the date: ' + value);
						}
					}
				}
			}
		}
	}

	get_microISO() {
		if (this.moment === undefined || this.moment === null) {
			return "";
		}
		var tz = this.moment.format('Z');
		var str = this.moment.toISOString(true);
		str = str.replace(tz, pad_zero(this.micro, 3)+tz);
		return str;
	}

	get_date() {
		if (this.moment === undefined || this.moment === null) {
			return "";
		}
		return this.moment.format('YYYY/MM/DD');
	}

	get_time() {
		if (this.moment === undefined || this.moment === null) {
			return "";
		}
		return this.moment.format('HH:mm:ss.SSS')
		    + String(pad_zero(this.micro, 3))
		    + this.moment.format('Z');
	}

	has_date() {
		return this.moment !== undefined;
	}

	has_time() {
		if (this.moment === undefined) {
			return false;
		} else {
			return this.moment.get('hour') != 0 
			    || this.moment.get('minute') != 0
			    || this.moment.get('second') != 0
			    || this.moment.get('millisecond') != 0
			    || this.micro != 0;
		}
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

function reflect_change_on_sliders(seen, skip_input_update, overwrite) {
	if (seen == 'both' || seen == 'first') {
		var f_val = overwrite === undefined ? $('#'+controller+'FirstSeen').val() : overwrite;
		var f_microdatetime = new MicroDatetime(f_val);
		var hours = f_microdatetime.moment !== undefined ? f_microdatetime.moment.hours() : 0;
		var minutes = f_microdatetime.moment !== undefined ? f_microdatetime.moment.minutes() : 0;
		var seconds = f_microdatetime.moment !== undefined ? f_microdatetime.moment.seconds() : 0;
		var milli = f_microdatetime.moment !== undefined ? f_microdatetime.moment.milliseconds() : 0;
		var d = f_microdatetime.moment !== undefined ? f_microdatetime.get_date() : undefined;

		// mirror slider and input field
		$('#input-time-first-'+time_vals[0]).val(hours);
		$('#slider-time-first-'+time_vals[0]).val(hours);

		$('#input-time-first-'+time_vals[1]).val(minutes);
		$('#slider-time-first-'+time_vals[1]).val(minutes);

		$('#input-time-first-'+time_vals[2]).val(seconds);
		$('#slider-time-first-'+time_vals[2]).val(seconds);

		$('#input-time-first-'+time_vals[3]).val(milli);
		$('#slider-time-first-'+time_vals[3]).val(milli);

		$('#input-time-first-'+time_vals[4]).val(f_microdatetime.micro);
		$('#slider-time-first-'+time_vals[4]).val(f_microdatetime.micro);

		$('#date_fs').datepicker('setDate', d);
		$('#time_fs').val(f_microdatetime.get_time());
	}

	if (seen == 'both' || seen == 'last') {
		var l_val = overwrite === undefined ? $('#'+controller+'LastSeen').val() : overwrite;
		var l_microdatetime = new MicroDatetime(l_val);
		var hours = l_microdatetime.moment !== undefined ? l_microdatetime.moment.hours() : 0;
		var minutes = l_microdatetime.moment !== undefined ? l_microdatetime.moment.minutes() : 0;
		var seconds = l_microdatetime.moment !== undefined ? l_microdatetime.moment.seconds() : 0;
		var milli = l_microdatetime.moment !== undefined ? l_microdatetime.moment.milliseconds() : 0;
		var d = l_microdatetime.moment !== undefined ? l_microdatetime.get_date() : undefined;

		// mirror slider and input field
		$('#input-time-last-'+time_vals[0]).val(hours);
		$('#slider-time-last-'+time_vals[0]).val(hours);

		$('#input-time-last-'+time_vals[1]).val(minutes);
		$('#slider-time-last-'+time_vals[1]).val(minutes);

		$('#input-time-last-'+time_vals[2]).val(seconds);
		$('#slider-time-last-'+time_vals[2]).val(seconds);

		$('#input-time-last-'+time_vals[3]).val(milli);
		$('#slider-time-last-'+time_vals[3]).val(milli);

		$('#input-time-last-'+time_vals[4]).val(l_microdatetime.micro);
		$('#slider-time-last-'+time_vals[4]).val(l_microdatetime.micro);

		$('#date_ls').datepicker('setDate', d);
		$('#time_ls').val(l_microdatetime.get_time());
	}

	if (!skip_input_update) {
		reflect_change_on_input(seen);
	}
}

// get data stored in sliders
function get_time_from_slider(which) {
	var micro = 0;
	var mom;
	var dp = which == 'first' ? $('#date_fs') : $('#date_ls');
	var timej = which == 'first' ? $('#time_fs') : $('#time_ls');
	if (dp.val() != "") { // no time without a date
		mom = dp.datepicker('getDate');
		mom = mom === null ? moment(0) : moment(mom.toISOString());
		if (timej.val() != "") {
			$('#precision_tool_'+which).find('input[type="number"]').each(function() {
				switch($(this).attr('scale')) {
					case 'us':
						micro = parseInt($(this).val());
						break;
					case 'ms':
						mom.set('ms', parseInt($(this).val()));
						break;
					case 'Second':
						mom.set('s', parseInt($(this).val()));
						break;
					case 'Minute':
						mom.set('m', parseInt($(this).val()));
						break;
					case 'Hour':
						mom.set('h', parseInt($(this).val()));
						break;
				}
			});
		} else { // no time, setting it UTC noon
			micro = 0;
			mom.set('h', 0);
		}
	}
	microdatetime = new MicroDatetime();
	microdatetime.moment = mom;
	microdatetime.micro = micro;
	return microdatetime;
}

function reflect_change_on_input(seen, full) {
	if ($('#seen_precision_tool').prop('checked')) {
		if (seen == 'both' || seen == 'first') {
			var microdatetime = get_time_from_slider('first');
			if($('#date_fs').val() !== '') {
				$("#time_fs").val(microdatetime.get_time());
			}
		}

		if (seen == 'both' || seen == 'last') {
			var microdatetime = get_time_from_slider('last');
			if($('#date_ls').val() !== '') {
				$("#time_ls").val(microdatetime.get_time());
			}
		}
	}
}

function reflect_change_on_form() {
	var microdatetime = get_time_from_slider('first');
	if (microdatetime.moment !== undefined) {
		$('#'+controller+'FirstSeen').val(microdatetime.get_microISO());
	} else {
		$('#'+controller+'FirstSeen').val("");
	}
	var microdatetime = get_time_from_slider('last');
	if (microdatetime.moment !== undefined) {
		$('#'+controller+'LastSeen').val(microdatetime.get_microISO());
	} else {
		$('#'+controller+'LastSeen').val("");
	}
}

$(document).ready(function() {

	var sliders_container = "<?php if ($this->params->controller === 'attributes') { echo 'fieldset'; } else { echo '#meta-div'; } ?>";
	var inputs_container = $('<div class="input-group input-daterange"></div>');
	// create separate date and time input
	var date_div_fs = $('<div class="input clear larger-input-field" style="margin-left: 10px;"></div>').append(
		$('<label><?php echo __('First seen date') . '<span class="fa fa-calendar label-icon"></span>'; ?><input id="date_fs" type="text" style="width: 240px;"></input></label>')
	);
	$(inputs_container).append(date_div_fs);
	var date_div_ls = $('<div class="input text larger-input-field"></div>').append(
		$('<label><?php echo __('Last seen date') . '<span class="fa fa-calendar label-icon"></span>'; ?><input id="date_ls" type="text" style="width: 240px;"></input></label>')
	);
	$(inputs_container).append(date_div_ls);
	$(sliders_container).append(inputs_container);

	var time_div_fs = $('<div class="input clear larger-input-field" style="margin-left: 10px;"></div>').append(
		$('<label><?php echo __('First seen time') . '<span class="fa fa-clock-o label-icon"></span>'; ?><input id="time_fs" type="text" style="width: 240px; text-align: center;"></input></label>')
	);
	$(sliders_container).append(time_div_fs);
	var time_div_ls = $('<div class="input larger-input-field"></div>').append(
		$('<label><?php echo __('Last seen time') . '<span class="fa fa-clock-o label-icon"></span>'; ?><input id="time_ls" type="text" style="width: 240px; text-align: center;"></input></label>')
	);
	$(sliders_container).append(time_div_ls);

	// create checkbox
	var div_checkbox_prec_tool = $('<div class="clear checkbox" style="margin-left: 10px;"></div>').append(
	    $('<label style="display: inline-block"><input id="seen_precision_tool" type="checkbox" style="margin-top: 0px;"></input><?php echo(__('Enable precision tool'))?><span class="fa fa-bullseye label-icon"</span></label>')
	);
	$(sliders_container).append(div_checkbox_prec_tool);

	// create sliders
	var div = $('<div id="precision_tool" class="precision-tool clear" style="display: none"></div>');
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

	$('#time_fs').on("focus", function(event) {
		$('#seen_precision_tool').prop('checked', true);
		$('#precision_tool').show();
	});
	$('#time_ls').on("focus", function(event) {
		$('#seen_precision_tool').prop('checked', true);
		$('#precision_tool').show();
	});

	$('#time_fs').on("input", function(event) {
		reflect_change_on_sliders('first', false, $(this).val());
	});
	$('#time_ls').on("input", function(event) {
		reflect_change_on_sliders('last', false, $(this).val());
	});
	
	$('#time_fs').on("paste", function(event) {
		// prefetch clipboard text and apply change
		var datetimeString;
		if (event.originalEvent.clipboardData && event.originalEvent.clipboardData.types
		    && $.inArray('text/plain', event.originalEvent.clipboardData.types) !== -1) {
			datetimeString = event.originalEvent.clipboardData.getData('text/plain');
		}
		else if (window.clipboardData) {
			datetimeString = window.clipboardData.getData('Text');
		}
		$('#'+controller+'FirstSeen').val(datetimeString);
		reflect_change_on_sliders('first', false);
		event.preventDefault();
	});

	$('#time_ls').on("paste", function(event) {
		// prefetch clipboard text and apply change
		var datetimeString;
		if (event.originalEvent.clipboardData && event.originalEvent.clipboardData.types
		    && $.inArray('text/plain', event.originalEvent.clipboardData.types) !== -1) {
			datetimeString = event.originalEvent.clipboardData.getData('text/plain');
		}
		else if (window.clipboardData) {
			datetimeString = window.clipboardData.getData('Text');
		}
		$('#'+controller+'LastSeen').val(datetimeString);
		reflect_change_on_sliders('last', false);
		event.preventDefault();
	});

	$('#AttributeForm').submit(function( event ) {
		reflect_change_on_form();
	});

	var d1 = new MicroDatetime($('#'+controller+'FirstSeen').val());
	var d2 = new MicroDatetime($('#'+controller+'LastSeen').val());
	if (d1.has_date() || d2.has_date()) {
		$('#date_fs').val(d1.get_date());
		$('#date_ls').val(d2.get_date());
	}
	if (d1.has_time() || d2.has_time()) {
		$('#seen_precision_tool').prop('checked', true);
		$('#precision_tool').show();
		$('#time_fs').val(d1.get_time());
		$('#time_ls').val(d2.get_time());
	}

	$('.input-daterange').datepicker({
		preventMultipleSet: true,
		format: 'yyyy/mm/dd',
		todayHighlight: true
	})
	reflect_change_on_sliders('both', true);

});
</script>
