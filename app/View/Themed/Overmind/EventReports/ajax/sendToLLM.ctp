<?php
/*
 * Minimal view rendered by sendToLLM (GET, AJAX only).
 * The visible confirmation is handled by the inline BS5 modal in
 * eventReport_content.ctp
 */
echo $this->Form->create('EventReport');
echo $this->Form->end();
?>