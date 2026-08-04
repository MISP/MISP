<div class="alert alert-error">
    <button type="button" class="close" data-dismiss="alert">&times;</button>
    <?php
        $message = h($message);
        if (strpos('$flashErrorMessage', $message) >= 0 && $this->Session->read('flashErrorMessage')) {
            $toReplace = sprintf('<a href="#" data-content="%s" data-toggle="popover" class="bold">%s</a>', h($this->Session->read('flashErrorMessage')), __("here"));
            $message = str_replace('$flashErrorMessage', $toReplace, $message);
        }
        echo $message;
        if (isset($params['url'])) {
            if (isset($params['urlName'])) {
                echo '<a href="' . h($params['url']) . '">' . h($params['urlName']) . '</a>';
            } else {
                echo '<a href="' . h($params['url']) . '">' .  h($params['url']) . '</a>';
            }
        }
    ?>
</div>
