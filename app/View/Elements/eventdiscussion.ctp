<div id="top">
	<?php 
		foreach ($posts as $post) {
	?>
			<table class="discussionBox" id=<?php echo '"' . h($post['id']) . '"';?> >
				<tr>
					<td class="discussionBoxTD discussionBoxTDtop" colspan="2">
					<div>
						<table style="width:100%">
							<tr>
								<td>
	<?php 
									echo 'Date: ' . h($post['date_created']);
	?>					
								</td>
								<td style="text-align:right">
									<a href = #top class = "whitelink">Top</a> |
									<a href = #<?php echo $post['id']; ?> class = "whitelink">#<?php echo h($post['id'])?></a>
								</td>
							</tr>
						</table>
					</div>
					</td>
				</tr>
				<tr>
					<td class="discussionBoxTD discussionBoxTDMid discussionBoxTDMidLeft">
						<?php 
							echo $this->Html->image('orgs/' . h($post['User']['org']) . '.png', array('alt' => h($post['User']['org']), 'title' => h($post['User']['org']), 'style' => 'width:48px; height:48px'));
						?>
					</td>
					<td class="discussionBoxTD discussionBoxTDMid discussionBoxTDMidRight">
	<?php 
							echo $this->Command->convertQuotes(nl2br(h($post['contents'])));
							if ($post['post_id'] !=0 || ($post['date_created'] != $post['date_modified'])) {
	?>
								<br /><br />
	<?php 
							}
							if ($post['post_id'] != 0) {
	?>
								<span style="font-style:italic">
									In reply to post
									<a href = #<?php echo h($post['post_id']); ?>>#<?php echo h($post['post_id'])?></a>
								</span>
	<?php 
							}
							if ($post['date_created'] != $post['date_modified']) {
								echo '<span style="font-style:italic">Message edited at ' . h($post['date_modified']) . '<span>';
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
									if ($post['user_id'] == $myuserid) {
										echo $this->Html->link('', array('controller' => 'posts', 'action' => 'edit', h($post['id'])), array('class' => 'icon-edit', 'title' => 'Edit'));
										echo $this->Form->postLink('', array('controller' => 'posts', 'action' => 'delete', h($post['id'])), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this post?'));
									} else {
	?>
										<a href = "<?php echo Configure::read('CyDefSIG.baseurl') . '/posts/add/post/' . h($post['id']); ?>" class="icon-comment" title = "Reply"></a>
	<?php 							
									}
								} else {
									echo $this->Html->link('', array('controller' => 'posts', 'action' => 'edit', h($post['id'])), array('class' => 'icon-edit', 'title' => 'Edit'));
									echo $this->Form->postLink('', array('controller' => 'posts', 'action' => 'delete', h($post['id'])), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this post?'));
	?>
										<a href = "<?php echo Configure::read('CyDefSIG.baseurl') . '/posts/add/post/' . h($post['id']); ?>" class="icon-comment" title = "Reply"></a>
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