<table class="table table-striped table-hover table-condensed">
	<tr>
		<th><?php echo $this->Paginator->sort('id');?></th>
		<th><?php echo $this->Paginator->sort('org_ci', 'Org');?></th>
		<th><?php echo $this->Paginator->sort('role_id', 'Role');?></th>
		<th><?php echo $this->Paginator->sort('email');?></th>
		<th><?php echo $this->Paginator->sort('authkey');?></th>
		<th><?php echo $this->Paginator->sort('autoalert');?></th>
		<th><?php echo $this->Paginator->sort('contactalert');?></th>
		<th><?php echo $this->Paginator->sort('gpgkey');?></th>
		<?php if (Configure::read('SMIME.enabled')): ?>
			<th><?php echo $this->Paginator->sort('certif_public', 'SMIME');?></th>
		<?php endif; ?>
		<th><?php echo $this->Paginator->sort('nids_sid');?></th>
		<th><?php echo $this->Paginator->sort('termsaccepted');?></th>
		<th><?php echo $this->Paginator->sort('current_login', 'Last login');?></th>
		<th><?php echo $this->Paginator->sort('date_created', 'Created');?></th>
		<?php
			if (Configure::read('Plugin.CustomAuth_enable') && !Configure::read('Plugin.CustomAuth_required')):
		?>
			<th><?php echo $this->Paginator->sort('external_auth_required', Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication');?></th>
		<?php
			endif;
		?>
		<th><?php echo $this->Paginator->sort('disabled');?></th>
		<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
		foreach ($users as $user): ?>
			<tr <?php echo $user['User']['disabled'] ? 'class="deleted_row"' : '';?>>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo h($user['User']['id']); ?>&nbsp;
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<a href="/organisations/view/<?php echo $user['Organisation']['id'];?>"><?php echo h($user['Organisation']['name']); ?>&nbsp;</a>
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])); ?>
				</td>
				<td ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo h($user['User']['email']); ?>&nbsp;
				</td>
				<td ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" class="quickSelect <?php echo $user['Role']['perm_auth'] ? 'bold' : 'grey'; ?>">
					<?php echo h($user['User']['authkey']); ?>&nbsp;
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo $user['User']['autoalert']? 'Yes' : 'No'; ?>
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo $user['User']['contactalert']? 'Yes' : 'No'; ?>
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo $user['User']['gpgkey']? 'Yes' : 'No'; ?>
				</td>
				<?php if (Configure::read('SMIME.enabled')): ?>
					<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
						<?php echo $user['User']['certif_public']? 'Yes' : 'No'; ?>
					</td>
				<?php endif; ?>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo h($user['User']['nids_sid']); ?>&nbsp;
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo ($user['User']['termsaccepted'] == 1) ? "Yes" : "No"; ?>
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="<?php echo !$user['User']['current_login'] ? 'N/A' : h(date("Y-m-d H:i:s",$user['User']['current_login']));?>">
					<?php echo !$user['User']['current_login'] ? 'N/A' : h(date("Y-m-d",$user['User']['current_login'])); ?>&nbsp;
				</td>
				<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="<?php echo !$user['User']['current_login'] ? 'N/A' : h(date("Y-m-d H:i:s",$user['User']['current_login']));?>">
					<?php echo !$user['User']['date_created'] ? 'N/A' : h(date("Y-m-d",$user['User']['date_created'])); ?>&nbsp;
				</td>
				<?php
					if (Configure::read('Plugin.CustomAuth_enable') && !Configure::read('Plugin.CustomAuth_required')):
				?>
					<td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="">
						<?php echo ($user['User']['external_auth_required'] ? 'Yes' : 'No'); ?>
					</td>
				<?php
					endif;
				?>
				<td class="short <?php if ($user['User']['disabled']) echo 'red bold';?>" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
					<?php echo ($user['User']['disabled'] ? 'Yes' : 'No'); ?>
				</td>
				<td class="short action-links">
					<?php
						if (($isAclAdmin && (($user['User']['org_id'] == $me['org_id'])) || ('1' == $me['id'])) || ($isSiteAdmin)):
					?>
							<span role="button" tabindex="0" aria-label="Initiate password refresh" title="Initiate password refresh" class="icon-refresh useCursorPointer" onClick="initiatePasswordReset('<?php echo $user['User']['id']; ?>');" title="Create new credentials and inform user" role="button" tabindex="0" aria-label="Create new credentials and inform user"></span>
					<?php
							echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $user['User']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
							echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $user['User']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s? It is highly recommended to never delete users but to disable them instead.', $user['User']['id']));
						endif;
					?>
					<?php echo $this->Html->link('', array('admin' => true, 'action' => 'view', $user['User']['id']), array('class' => 'icon-list-alt', 'title' => 'View')); ?>
				</td>
			</tr>
	<?php
		endforeach;
	?>
</table>
