<div class="servers form">
<?php echo $this->Form->create('Server');?>
    <fieldset>
        <legend><?php echo __('REST client');?></legend>
		<div style="position:absolute;right:40px;width:300px;" id="apiInfo"></div>
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
	$(document).ready(function () {
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
		var thread = null;
		$('#ServerUrl').keyup(function() {
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
		});
	});
</script>
