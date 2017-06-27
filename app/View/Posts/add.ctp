<div class="posts form">
<?php echo $this->Form->create('Post');?>
	<fieldset>
		<legend>Add Post</legend>
	<?php
		$quote = '';
		// If it is a new thread, let the user enter a subject
		if (empty($thread_id) && empty($target_type)):
			echo $this->Form->input('title', array(
					'label' => 'Thread Subject',
					'class' => 'input-xxlarge'
				));
		else:
		?>
			<div class="input text">
				<label for="PostTitle">Thread Subject</label>
				<input class = "input-xxlarge" disabled="disabled" value="<?php echo h($title);?>" id="PostTitle" type="text">
			</div>
		<?php
		endif;
		if ($target_type === 'post'):
		?>
			<div class="input clear">
				<label for="PostResponseTo">In response to</label>
				<textarea class="input-xxlarge" disabled="disabled" cols="30" rows="6" id="PostResponseTo"><?php echo h($previous); ?></textarea>
			</div>
		<?php
			$quote = '[QUOTE]' . $previous . '[/QUOTE]' . "\n";
		endif;
		?>
		<div class="input clear">
			<button type="button" title="Insert a quote - just paste your quote between the [quote][/quote] tags." class="toggle-left btn btn-inverse qet" id = "quote"  onclick="insertQuote()">Quote</button>
			<button type="button" title="Insert a link to an event - just enter the event ID between the [event][/event] tags." class="toggle btn btn-inverse qet" id = "event"  onclick="insertEvent()">Event</button>
			<button type="button" title="Insert a link to a discussion thread - enter the thread's ID between the [thread][/thread] tags." class="toggle-right btn btn-inverse qet" id = "thread"  onclick="insertThread()">Thread</button>
			<button type="button" title="Insert a link [link][/link] tags." class="toggle-right btn btn-inverse qet" id="link" onclick="insertLink()">Link</button>
			<button type="button" title="Insert a code [code][/code] tags." class="toggle-right btn btn-inverse qet" id="code" onclick="insertCode()">Code</button>
		</div>
		<?php
		echo $this->Form->input('message', array(
				'label' => false,
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'default' => $quote
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
		function insertLink() {
			document.getElementById("PostMessage").value+="[Link][/Link]";
		}
		function insertCode() {
			document.getElementById("PostMessage").value+="[Code][/Code]";
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
