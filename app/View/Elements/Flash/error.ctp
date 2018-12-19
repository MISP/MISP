<div class="alert alert-error">
    <button type="button" class="close" data-dismiss="alert">&times;</button>
    <?php
        $message = h($message);
		if (strpos('$flashErrorMessage', $message) >= 0) {
			$message = str_replace('$flashErrorMessage', '<span class="useCursorPointer underline bold" onClick="flashErrorPopover();">here</span>', $message);
		}
		echo $message;
                if (isset($params['url'])) {
                    if (isset($params['urlName'])) {
                        echo '<a href="' . h($params['url']) . '">' . h($params['urlName']) . '</a>';
                    } else {
                        echo '<a href="' . h($params['url']) . '">' .  h($params['url']) . '</a>';
                    }
                }
	    if ($this->Session->read('flashErrorMessage')) {
			echo sprintf('<div class="hidden" id="flashErrorMessage">%s</div>', $this->element('flashErrorMessage', array('message' => $this->Session->read('flashErrorMessage'))));
		}
	?>
</div>
