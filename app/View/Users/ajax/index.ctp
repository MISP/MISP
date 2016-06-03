<div>
<h3>Members of <?php echo h($org);?></h3>
	<div class="pagination">
        <ul>
        <?php
	        $this->Paginator->options(array(
	            'update' => '.span12',
	            'evalScripts' => true,
	            'before' => '$(".progress").show()',
	            'complete' => '$(".progress").hide()',
	        ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
        </ul>
    </div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('email');?></th>
			<th>Role</th>
			<th>GPGKey set</th>
			<th>Certificate (x509) set</th>
			<th><?php echo $this->Paginator->sort('nids_sid');?></th>
			<?php
				if ($isSiteAdmin):
			?>
				<th>Last login</th>
				<th>Terms accepted</th>
				<th>Change password</th>
				<th>API key</th>
			<?php
				endif;
			?>
			<th>Actions</th>
	</tr>
	<?php
		$boolean_field = array('termsaccepted', 'change_pw');
		foreach ($users as $user):
	?>
			<tr>
	<?php
			foreach ($user_fields as $field):

	?>
				<td class="short" ondblclick="document.location ='/admin/users/view/<?php echo $user['User']['id'];?>'">
				<?php
				// here I am
					switch ($field) {
						case 'gpgkey':
							if (!empty($user['User'][$field])) echo 'Yes';
							else echo 'No';
							break;
						case 'termsaccepted':
						case 'change_pw':
							if ($user['User'][$field]) echo 'Yes';
							else echo 'No';
							break;
						case 'current_login':
							echo $user['User'][$field] ? h(date('Y-m-d', $user['User'][$field])) : 'N/A';
							break;
						case 'role':
				?>
					<a href="/roles/view/<?php echo $user['Role']['id']; ?>"><?php echo h($user['Role']['name']); ?></a>
				<?php
							break;
						default:
							echo h($user['User'][$field]);
					}
				?>&nbsp;
				</td>
	<?php
			endforeach;
	?>
				<td class="short action-links">
					<?php if ($isSiteAdmin): ?>
						<a href='/admin/users/edit/<?php echo $user['User']['id'];?>' class = "icon-edit" title = "Edit"></a>
					<?php
						echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $user['User']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete %s?', $user['User']['email']));
					?>
					<?php endif; ?>
			<a href='/users/view/<?php echo $user['User']['id']; ?>' class = "icon-list-alt" title = "View"></a>

				</td>
			</tr>
	<?php
		endforeach; ?>
	</table>
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
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
