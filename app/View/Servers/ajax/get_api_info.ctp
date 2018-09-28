<div class="dashboard_element">
	<?php
		if (!empty($api_info['api_info'])) {
			echo '<h4 class="blue bold">API info</h4>';
			foreach ($api_info['api_info'] as $key => $value) {
				if (!empty($value)) {
					if (is_array($value)) {
						foreach ($value as $k => $v) {
							$value[$k] = h($v);
						}
						if (isset($value['OR']) || isset($value['AND']) || isset($value['NOT'])) {
							$temp = array();
							foreach ($value as $k => $v) {
								$temp[] = $k . ': ' . implode(', ', $v);
							}
							$value = $temp;
						}
						$value = implode('<br />', $value);
					} else {
						$value = h($value);
					}
					echo sprintf('<span class=blue>%s</span>:<br /><div style="padding-left:10px;">%s</div>', ucfirst(h($key)), $value);
				}
			}
		}
	?>
</div>
