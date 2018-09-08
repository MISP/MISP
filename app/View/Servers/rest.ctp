<div class="servers form">
	<div style="position:absolute;right:40px;width:300px;top:90px;">
		<label for="TemplateSelect">Templates</label>
		<?php
			$options = '<option value="">None</option>';
			foreach ($allValidApis as $endpoint_url => $endpoint_data) {
				$options .= sprintf('<option value="%s">%s</option>', $endpoint_url, $endpoint_data['api_name']);
			}
			echo sprintf('<select id="TemplateSelect">%s</select>', $options);
		?>
		<div id="apiInfo"></div>
	</div>
<?php echo $this->Form->create('Server');?>
    <fieldset>
        <legend><?php echo __('REST client');?></legend>
    <?php
        echo $this->Form->input('method', array(
            'label' => __('Relative path to query'),
            'options' => array(
                'GET' => 'GET',
                'POST' => 'POST'
            )
        ));
        ?>
            <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('url', array(
            'label' => __('Relative path to query'),
            'class' => 'input-xxlarge'
        ));
	?>
		<div class="input clear" style="width:100%;">
	<?php
		echo $this->Form->input('use_full_path', array(
			'label' => 'Use full path - disclose my apikey',
            'type' => 'checkbox'
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('show_result', array(
            'type' => 'checkbox'
        ));
		echo $this->Form->input('skip_ssl_validation', array(
			'type' => 'checkbox',
			'label' => 'Skip SSL validation'
		));

    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('header', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'default' => !empty($this->request->data['Server']['header']) ? $this->request->data['Server']['header'] : $header
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('body', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge'
        ));
    ?>
        <div class="input clear" style="width:100%;">
		<div id="template_description" style="display:none;width:700px;" class="alert alert-error">Fill out the JSON template above, make sure to replace all placeholder values. Fields with the value "optional" can be removed.</div>
    <?php
        echo $this->Form->submit('Run query', array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
        <hr />
	</fieldset>
    <?php
        $formats = array('Raw', 'JSON', 'HTML');
        if (!empty($data['data'])):
            echo sprintf('<h3>%s</h3>', __('Response'));
            echo sprintf('<div><span class="bold">%s</span>: %d</div>', __('Response code'), h($data['code']));
            echo sprintf('<div><span class="bold">%s</span>: %s</div>', __('Request duration'), h($data['duration']));
            echo sprintf('<div class="bold">%s</div>', __('Headers'));
            foreach ($data['headers'] as $header => $value) {
				if (is_array($value)) {
					$value = implode(',', $value);
				}
            	echo sprintf('&nbsp;&nbsp;<span class="bold">%s</span>: %s<br />', h($header), h($value));
    		}
            $format_toggles = '';
            foreach ($formats as $k => $format) {
              $position = '';
              if ($k == 0) {
                $position = '-left';
              }
              if ($k == (count($formats) -1)) {
                $position = '-right';
              }
              $format_toggles .= sprintf('<span class="btn btn-inverse qet toggle%s format-toggle-button" data-toggle-type="%s">%s</span>', $position, $format, $format);
            }
            echo sprintf('<div style="padding-bottom:24px;">%s</div>', $format_toggles);
            echo sprintf('<div class="hidden" id="rest-response-hidden-container">%s</div>', h($data['data']));
            echo '<div id="rest-response-container"></div>';
        endif;
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'rest'));
?>
<script type="text/javascript">
	// tooltips
	var thread = null;
	function setApiInfoBox() {
		clearTimeout(thread);
		var $this = $(this);
		var payload = {
			"url": $('#ServerUrl').val()
		};
		if (payload) {
			thread = setTimeout(
				function() {
					$.ajax({
						type: "POST",
						url: '/servers/getApiInfo',
						data: payload,
						success:function (data, textStatus) {
							$('#apiInfo').html(data);
						}
					});
				},
				1000
			);
		} else {
			$('#apiInfo').empty();
		}
	}

	$(document).ready(function () {
		var allValidApis = <?php echo json_encode($allValidApis); ?>;
		insertRawRestResponse();
		$('.format-toggle-button').bind('click', function() {
			$('#rest-response-container').empty();
			if ($(this).data('toggle-type') == 'Raw') {
				insertRawRestResponse();
			} else if ($(this).data('toggle-type') == 'HTML') {
				insertHTMLRestResponse();
			} else if ($(this).data('toggle-type') == 'JSON') {
				insertJSONRestResponse();
			}
		});
		$('#ServerUrl').keyup(function() {
			setApiInfoBox();
		});
		$('#TemplateSelect').change(function() {
			var selected_template = $('#TemplateSelect').val();
			if (selected_template !== '') {
				$('#template_description').show();
				$('#ServerMethod').val('POST');
				$('#ServerUrl').val(allValidApis[selected_template].url);
				$('#ServerBody').val(allValidApis[selected_template].body);
				setApiInfoBox();
			}
		});
	});
</script>
