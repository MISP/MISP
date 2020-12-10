<table class="table table-striped table-hover table-condensed">
    <tr>
        <th><?php echo $this->Paginator->sort('id', __('ID'));?></th>
        <th><?php echo $this->Paginator->sort('org_ci', __('Org'));?></th>
        <th><?php echo $this->Paginator->sort('role_id', __('Role'));?></th>
        <th><?php echo $this->Paginator->sort('email');?></th>
        <?php if (empty(Configure::read('Security.advanced_authkeys'))): ?>
        <th><?php echo $this->Paginator->sort('authkey');?></th>
        <?php endif; ?>
        <th><?php echo $this->Paginator->sort('autoalert', __('Event alert'));?></th>
        <th><?php echo $this->Paginator->sort('contactalert', __('Contact alert'));?></th>
        <th><?php echo $this->Paginator->sort('gpgkey', __('PGP Key'));?></th>
        <?php if (Configure::read('SMIME.enabled')): ?>
            <th><?php echo $this->Paginator->sort('certif_public', 'S/MIME');?></th>
        <?php endif; ?>
        <th><?php echo $this->Paginator->sort('nids_sid', __('NIDS SID'));?></th>
        <th><?php echo $this->Paginator->sort('termsaccepted', __('Terms accepted'));?></th>
        <th><?php echo $this->Paginator->sort('current_login', __('Last login'));?></th>
        <th><?php echo $this->Paginator->sort('date_created', __('Created'));?></th>
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
                    <a href="<?php echo $baseurl; ?>/organisations/view/<?php echo $user['Organisation']['id'];?>"><?php echo h($user['Organisation']['name']); ?>&nbsp;</a>
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])); ?>
                </td>
                <td ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo h($user['User']['email']); ?>&nbsp;
                </td>
                <?php if (empty(Configure::read('Security.advanced_authkeys'))): ?>
                <td class="bold<?= $user['Role']['perm_auth'] ? '' : ' grey'; ?>">
                    <span class="privacy-value quickSelect" data-hidden-value="<?= h($user['User']['authkey']) ?>">****************************************</span>&nbsp;<i class="privacy-toggle fas fa-eye useCursorPointer" title="<?= __('Reveal hidden value') ?>"></i>
                </td>
                <?php endif; ?>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo $user['User']['autoalert']? __('Yes') : __('No'); ?>
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo $user['User']['contactalert']? __('Yes') : __('No'); ?>
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo $user['User']['gpgkey']? 'Yes' : 'No'; ?>
                </td>
                <?php if (Configure::read('SMIME.enabled')): ?>
                    <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                        <?php echo $user['User']['certif_public']? __('Yes') : __('No'); ?>
                    </td>
                <?php endif; ?>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo h($user['User']['nids_sid']); ?>&nbsp;
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo ($user['User']['termsaccepted'] == 1) ? __("Yes") : __("No"); ?>
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="<?php echo !$user['User']['current_login'] ? __('N/A') : h(date("Y-m-d H:i:s",$user['User']['current_login']));?>">
                    <?php echo !$user['User']['current_login'] ? __('N/A') : h(date("Y-m-d", $user['User']['current_login'])); ?>&nbsp;
                </td>
                <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="<?php echo !$user['User']['current_login'] ? 'N/A' : h(date("Y-m-d H:i:s",$user['User']['current_login']));?>">
                    <?php echo !$user['User']['date_created'] ? __('N/A') : h(date("Y-m-d", $user['User']['date_created'])); ?>&nbsp;
                </td>
                <?php
                    if (Configure::read('Plugin.CustomAuth_enable') && !Configure::read('Plugin.CustomAuth_required')):
                ?>
                    <td class="short" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';" title="">
                        <?php echo ($user['User']['external_auth_required'] ? __('Yes') : __('No')); ?>
                    </td>
                <?php
                    endif;
                ?>
                <td class="short <?php if ($user['User']['disabled']) echo 'red bold';?>" ondblclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $user['User']['id']), true);?>';">
                    <?php echo ($user['User']['disabled'] ? __('Yes') : __('No')); ?>
                </td>
                <td class="short action-links">
                    <?php
                        if (($isAclAdmin && (($user['User']['org_id'] == $me['org_id'])) || ('1' == $me['id'])) || ($isSiteAdmin)):
                    ?>
                            <span role="button" tabindex="0" class="fa fa-sync useCursorPointer" onClick="initiatePasswordReset('<?php echo $user['User']['id']; ?>');" title="<?php echo __('Create new credentials and inform user');?>" aria-label="<?php echo __('Create new credentials and inform user');?>"></span>
                    <?php
                            echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $user['User']['id']), array('class' => 'fa fa-edit', 'title' => __('Edit'), 'aria-label' => __('Edit')));
                            echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $user['User']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete # %s? It is highly recommended to never delete users but to disable them instead.', $user['User']['id']));
                        endif;
                    ?>
                    <?php echo $this->Html->link('', array('admin' => true, 'action' => 'view', $user['User']['id']), array('class' => 'fa fa-eye', 'title' => __('View'), 'aria-label' => __('View'))); ?>
                </td>
            </tr>
    <?php
        endforeach;
    ?>
</table>
