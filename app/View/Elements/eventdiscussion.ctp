<div id="top">
	<div class="pagination">
        <?php
        if (!empty($posts)):
        ?>
			<ul>
        <?php
	        $this->Paginator->options(array(
	            'update' => '#top',
	            'evalScripts' => true,
	            'before' => '$(".loading").show()',
	            'complete' => '$(".loading").hide()',
	        ));

	            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
	            echo $this->Paginator->numbers(array('modulus' => 10, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
	            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
	        ?>
	        </ul>
	    </div>
	    <div id = "posts">
			<?php
				foreach ($posts as $post) {
			?>
					<a name="message_<?php echo h($post['Post']['id']);?>"></a>
					<table class="discussionBox" id=<?php echo '"' . h($post['Post']['id']) . '"';?> >
						<tr>
							<td class="discussionBoxTD discussionBoxTDtop" colspan="2">
							<div>
								<table style="width:100%">
									<tr>
										<td>
			<?php
											echo 'Date: ' . h($post['Post']['date_created']);
			?>
										</td>
										<td style="text-align:right">
											<a href="#top" class="whitelink">Top</a> |
											<a href="<?php echo "#".$post['Post']['id']; ?>" class="whitelink">#<?php echo h($post['Post']['id'])?></a>
										</td>
									</tr>
								</table>
							</div>
							</td>
						</tr>
						<tr>
							<td class="discussionBoxTD discussionBoxTDMid discussionBoxTDMidLeft">
								<?php
								if (isset($post['User']['Organisation'])) {
									$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS . h($post['User']['Organisation']['name']) . '.png';
									if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($post['User']['Organisation']['name']) . '.png', array('alt' => h($post['User']['Organisation']['name']), 'title' => h($post['User']['Organisation']['name']), 'style' => 'width:48px; height:48px'));
									else echo $this->Html->tag('span', h($post['User']['Organisation']['name']), array('class' => 'welcome', 'style' => 'float:center;'));
								} else {
									echo 'Deactivated user';
								}
								?>
							</td>
							<td class="discussionBoxTD discussionBoxTDMid discussionBoxTDMidRight">
			<?php
									echo $this->Command->convertQuotes(nl2br(h($post['Post']['contents'])));
									if ($post['Post']['post_id'] !=0 || ($post['Post']['date_created'] != $post['Post']['date_modified'])) {
			?>
										<br /><br />
			<?php
									}
									if ($post['Post']['post_id'] != 0) {
			?>
										<span style="font-style:italic">
											In reply to post
											<a href="<?php echo "#".h($post['Post']['post_id']); ?>">#<?php echo h($post['Post']['post_id'])?></a>
										</span>
			<?php
									}
									if ($post['Post']['date_created'] != $post['Post']['date_modified']) {
										echo '<span style="font-style:italic">Message edited at ' . h($post['Post']['date_modified']) . '<span>';
									}
			?>
							</td>
						</tr>
						<tr>
							<td class="discussionBoxTD discussionBoxTDbottom" colspan = "2">
								<table style="width:100%">
									<tr>
										<td>
											<?php echo h($post['User']['email']); ?>
										</td>
										<td style="text-align:right">
			<?php
										if (!$isSiteAdmin) {
											if ($post['Post']['user_id'] == $myuserid) {
												echo $this->Html->link('', array('controller' => 'posts', 'action' => 'edit', h($post['Post']['id']), h($context)), array('class' => 'icon-edit', 'title' => 'Edit'));
												echo $this->Form->postLink('', array('controller' => 'posts', 'action' => 'delete', h($post['Post']['id']), h($context)), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this post?'));
											} else {
			?>
												<a href="<?php echo $baseurl.'/posts/add/post/'.h($post['Post']['id']); ?>" class="icon-comment" title = "Reply"></a>
			<?php
											}
										} else {
											echo $this->Html->link('', array('controller' => 'posts', 'action' => 'edit', h($post['Post']['id']), h($context)), array('class' => 'icon-edit', 'title' => 'Edit'));
											echo $this->Form->postLink('', array('controller' => 'posts', 'action' => 'delete', h($post['Post']['id']), h($context)), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this post?'));
			?>
												<a href = "<?php echo $baseurl.'/posts/add/post/'.h($post['Post']['id']); ?>" class="icon-comment" title = "Reply"></a>
			<?php

										}
			?>
										</td>
									</tr>
								</table>
							</td>
						</tr>
					</table>
					<br />
			<?php
				}
			?>
			</div>
			<p>
	    <?php
	    echo $this->Paginator->counter(array(
	    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	    ));
	    ?>
	    </p>
	    <div class="pagination">
	        <ul>
	        <?php
	            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
	            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
	            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
	        ?>
	        </ul>
	    </div>
    <?php endif; ?>
	<div class="comment">
	<?php
		if (isset($currentEvent)) $url = '/posts/add/event/' . $currentEvent;
		else $url = '/posts/add/thread/' . $thread_id;
		echo $this->Form->create('Post', array('url' => $url));
	?>
		<fieldset>
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
			));
		?>
		</fieldset>
		<button class="btn btn-primary" onClick="submitMessageForm('<?php echo h($url);?>', 'PostViewForm', 'top'); return false;">Send</button>
	<?php
		echo $this->Form->end();
	?>
	</div>
</div>
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
	<?php if (isset($post_id) && $post_id): ?>
		$(document).ready(function() {
			location.hash = "#message_<?php echo h($post_id); ?>";
		});
	<?php endif; ?>
</script>
<?php echo $this->Js->writeBuffer();?>
