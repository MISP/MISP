<?php
$buttonAddStatus = $isAclAdd ? 'button_on':'button_off';
$mayModify = ($isSiteAdmin || ($isAdmin && ($user['User']['org_id'] == $me['org_id'])));
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
?>
<div class="users view">
<h2><?php  echo __('User');?></h2>
    <dl style="width:800px;">
        <dt><?php echo __('Id'); ?></dt>
        <dd>
            <?php echo h($user['User']['id']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Org'); ?></dt>
        <dd>
            <a href="<?php echo $baseurl?>/organisations/view/<?php echo h($user['Organisation']['id']); ?>"><?php echo h($user['Organisation']['name']); ?></a>
            &nbsp;
        </dd>
        <dt><?php echo __('Role'); ?></dt>
        <dd>
            <?php echo $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Email'); ?></dt>
        <dd>
            <?php echo h($user['User']['email']); ?>&nbsp;<a class="icon-envelope" href="<?php echo $baseurl; ?>/admin/users/quickEmail/<?php echo h($user['User']['id']); ?>"></a>
            &nbsp;
        </dd>
        <dt><?php echo __('Autoalert'); ?></dt>
        <dd>
            <?php
                echo (h($user['User']['autoalert']) == 0)? __('No') : __('Yes'); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Contactalert'); ?></dt>
        <dd>
            <?php echo h(0 == ($user['User']['contactalert'])) ? __('No') : __('Yes'); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Authkey'); ?></dt>
        <dd>
            <span class="quickSelect"><?php echo h($user['User']['authkey']); ?></span>
            (<?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id']));?>)
            &nbsp;
        </dd>
        <dt><?php echo __('Invited By'); ?></dt>
        <dd>
            <?php echo h($user2['User']['email']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Org admin');?></dt>
        <dd>
            <?php

                foreach ($user['User']['orgAdmins'] as $orgAdminId => $orgAdminEmail):
            ?>
                    <a href="<?php echo $baseurl; ?>/admin/users/view/<?php echo h($orgAdminId); ?>"><?php echo h($orgAdminEmail); ?></a>
                    <a class="icon-envelope" href="<?php echo $baseurl; ?>/admin/users/quickEmail/<?php echo h($orgAdminId); ?>"></a>
            <?php
                if ($orgAdminEmail !== end($user['User']['orgAdmins'])) {
                    echo '<br />';
                }
                endforeach;
            ?>
            &nbsp;
        </dd>
        <dt><?php echo __('GnuPG key'); ?></dt>
        <dd class="quickSelect <?php echo $user['User']['gpgkey'] ? 'green' : 'bold red'; ?>">
            <?php echo $user['User']['gpgkey'] ? nl2br(h($user['User']['gpgkey'])) : "N/A"; ?>
        </dd>
        <?php
            if (!empty($user['User']['gpgkey'])):
        ?>
            <dt><?php echo __('GnuPG fingerprint');?></dt>
            <dd class="quickSelect bold <?php echo $user['User']['fingerprint'] ? 'green': 'red'; ?>">
                <?php
                    echo $user['User']['fingerprint'] ? chunk_split(h($user['User']['fingerprint']), 4, ' ') : 'N/A';
                ?>
            </dd>
            <dt><?php echo __('GnuPG status');?></dt>
            <dd class="bold <?php echo (empty($user['User']['pgp_status']) || $user['User']['pgp_status'] != __('OK')) ? 'red': 'green'; ?>">
                <?php
                    echo !empty($user['User']['pgp_status']) ? h($user['User']['pgp_status']) : __('N/A');
                ?>
            </dd>
        <?php
            endif;
        ?>
        <?php if (Configure::read('SMIME.enabled')): ?>
            <dt><?php echo __('SMIME Public certificate'); ?></dt>
            <dd class="quickSelect red">
                <?php echo (h($user['User']['certif_public'])) ? $this->Utility->space2nbsp(nl2br(h($user['User']['certif_public']))) : __("N/A"); ?>
            </dd>
        <?php endif; ?>
        <dt><?php echo __('Nids Sid'); ?></dt>
        <dd>
            <?php echo h($user['User']['nids_sid']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Termsaccepted'); ?></dt>
        <dd>
            <?php
if (h($user['User']['termsaccepted']) == 1) {
                        echo __("Yes");
} else {
                        echo __("No");
}?>
            &nbsp;
        </dd>
                <dt><?php echo __('Password change'); ?></dt>
        <dd>
            <?php
if (h($user['User']['change_pw']) == 1) {
                        echo __("Yes");
} else {
                        echo __("No");
}?>
            &nbsp;
        </dd>
        <dt><?php echo __('Newsread'); ?></dt>
        <dd>
            <?php echo $user['User']['newsread'] ? date('Y/m/d H:i:s', h($user['User']['newsread'])) : __('N/A'); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Disabled'); ?></dt>
        <dd <?php if ($user['User']['disabled']) echo 'class="visibleDL notPublished"';?>>
            <?php echo $user['User']['disabled'] ? __('Yes') : __('No'); ?>
            &nbsp;
        </dd>
    </dl>
    <br />
    <a href="<?php echo $baseurl . '/admin/users/view/' . h($user['User']['id']) . '.json'; ?>" class="btn btn-inverse" download>Download user profile for data portability</a>
    <br />
    <div id="userEvents"></div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'viewUser'));
?>
<script type="text/javascript">
    $(document).ready(function () {
        $.ajax({
            url: '<?php echo $baseurl . "/events/index/searchemail:" . urlencode(h($user['User']['email'])); ?>',
            type:'GET',
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            error: function(){
                $('#userEvents').html(__('An error has occurred, please reload the page.'));
            },
            success: function(response){
                $('#userEvents').html(response);
            },
            complete: function() {
                $(".loading").hide();
            }
        });
    });
</script>
