<?php echo $this->Html->script('moment-with-locales'); ?>

<script>
<?php
    $temp = explode('_', $this->params->controller);
    if (count($temp) > 1) {
        $temp = array_map(function($i, $str) {
            return $i > 0 ? substr(ucfirst($str), 0, -1) : ucfirst($str);
        }, array_keys($temp), $temp);
        $temp = implode('', $temp);
    } else {
        $temp = substr(ucfirst($this->params->controller), 0, -1);
    }
?>
var controller = "<?php echo $temp; ?>"; // get current controller name so that we can access all form fields

function reflect_change_on_form() {
    var first_seen = '';
    if ($('#date_fs').val() !== '') {
        first_seen += $('#date_fs').val();
        if ($("#time_fs").val() !== '') {
            first_seen += 'T' + $('#time_fs').val();
        }
    }
    var last_seen = '';
    if ($('#date_ls').val() !== '') {
        last_seen += $('#date_ls').val();
        if ($("#time_ls").val() !== '') {
            last_seen += 'T' + $('#time_ls').val();
        }
    }
    $('#'+controller+'FirstSeen').val(first_seen);
    $('#'+controller+'LastSeen').val(last_seen);
}

function extractDatetimePart(text) {
    try {
        var split = text.split('T')
        return {
            date: split[0],
            time: split[1]
        }
    } catch (error) {
        return { date: '', time: ''}
    }
}

$(document).ready(function() {
    var sliders_container = "#bothSeenSliderContainer"
    var inputs_container = $('<div class="input-group input-daterange"></div>');
    // create separate date and time input
    var date_div_fs = $('<div class="input clear larger-input-field" style="margin-left: 10px;"></div>').append(
        $('<label><?php echo __('First seen date') . '<span class="fas fa-calendar label-icon"></span>'; ?><input id="date_fs" type="text" style="width: 240px;"></input></label>')
    );
    $(inputs_container).append(date_div_fs);
    var date_div_ls = $('<div class="input text larger-input-field"></div>').append(
        $('<label><?php echo __('Last seen date') . '<span class="fas fa-calendar label-icon"></span>'; ?><input id="date_ls" type="text" style="width: 240px;"></input></label>')
    );
    $(inputs_container).append(date_div_ls);
    $(sliders_container).append(inputs_container);

    var time_div_fs = $('<div class="input clear larger-input-field" style="margin-left: 10px;"></div>').append(
        $('<label><?php echo __('First seen time') . '<span class="fas fa-clock label-icon"></span>'; ?><input id="time_fs" type="text" style="width: 240px; text-align: center; margin-bottom: 0px" placeholder="HH:MM:SS.ssssss+TT:TT"></input></label>'),
        $('<span class="apply_css_arrow"></span>').text('<?php echo __('Expected format: HH:MM:SS.ssssss+TT:TT') ?>')
    );
    $(sliders_container).append(time_div_fs);
    var time_div_ls = $('<div class="input larger-input-field"></div>').append(
        $('<label><?php echo __('Last seen time') . '<span class="fas fa-clock label-icon"></span>'; ?><input id="time_ls" type="text" style="width: 240px; text-align: center; margin-bottom: 0px" placeholder="HH:MM:SS.ssssss+TT:TT"></input></label>'),
        $('<span class="apply_css_arrow"></span>').text('<?php echo __('Expected format: HH:MM:SS.ssssss+TT:TT') ?>')
    );
    $(sliders_container).append(time_div_ls);

    $('#'+controller+'FirstSeen').closest('form').submit(function( event ) {
        reflect_change_on_form();
    });

    var d1 = extractDatetimePart($('#'+controller+'FirstSeen').val());
    var d2 = extractDatetimePart($('#'+controller+'LastSeen').val());
    $('#date_fs').val(d1.date);
    $('#time_fs').val(d1.time);
    $('#date_ls').val(d2.date);
    $('#time_ls').val(d2.time);

    $('.input-daterange').datepicker({
        preventMultipleSet: true,
        format: 'yyyy-mm-dd',
        todayHighlight: true
    })
});
</script>
