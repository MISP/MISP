<div class="posts form">
<?php echo $this->Form->create('Post');?>
	<fieldset>
		<legend>Add Post</legend>
	<?php
		$quote = '';
		// If it is a new thread, let the user enter a subject
		if (empty($thread_id) && empty($target_type)) {
			echo $this->Form->input('title', array(
					'label' => 'Thread Subject',
					'class' => 'input-xxlarge'
				));
		} else {
			echo $this->Form->input('title', array(
					'label' => 'Thread Subject',
					'class' => 'input-xxlarge',
					'disabled' => 'true',
					'default' => $title
			));
		}
		if ($target_type === 'post') {
			echo $this->Form->input('responseTo', array(
					'label' => 'In response to',
					'type' => 'textarea',
					'div' => 'input clear',
					'class' => 'input-xxlarge',
					'disabled' => 'true',
					'default' => h($previous)
			));
			$quote = '[QUOTE]' . $previous . '[/QUOTE]' . "\n";
		}
		?>
		<div class="input clear">
			<button type="button" title="Insert a quote - just paste your quote between the [quote][/quote] tags." class="toggle-left btn btn-inverse qet" id = "quote"  onclick="insertQuote()">Quote</button>
			<button type="button" title="Insert a link to an event - just enter the event ID between the [event][/event] tags." class="toggle btn btn-inverse qet" id = "event"  onclick="insertEvent()">Event</button>
			<button type="button" title="Insert a link to a discussion thread - enter the thread's ID between the [thread][/thread] tags." class="toggle-right btn btn-inverse qet" id = "thread"  onclick="insertThread()">Thread</button>
		</div>
		<?php 
		echo $this->Form->input('message', array(
				'label' => false,
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'default' => h($quote)
		));
	?>
	</fieldset>
	<script type="text/javascript"> 
		function insertQuote() {
			document.getElementById("PostMessage").value+="[Quote][/Quote]"; 
		}
		function insertEvent() {
			document.getElementById("PostMessage").value+="[Event][/Event]"; 
		}
		function insertThread() {
			document.getElementById("PostMessage").value+="[Thread][/Thread]"; 
		}
	</script>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'add'));
?>
