<div class="users view">
<h2><?php  echo __('User');?></h2>
    <dl style="width:700px;">
        <dt><?php echo __('Id'); ?></dt>
        <dd>
            <?php echo h($user['User']['id']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Email'); ?></dt>
        <dd>
            <?php echo h($user['User']['email']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Org'); ?></dt>
        <dd>
            <?php echo h($user['Organisation']['name']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Role'); ?></dt>
        <dd>
            <?php echo $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Autoalert'); ?></dt>
        <dd>
            <?php echo h(0 == ($user['User']['autoalert'])) ? 'No' : 'Yes'; ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Contactalert'); ?></dt>
        <dd>
            <?php echo h(0 == ($user['User']['contactalert'])) ? 'No' : 'Yes'; ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Authkey'); ?></dt>
        <dd>
            <?php
                if ($user['Role']['perm_auth']):
            ?>
                <span class="quickSelect"><?php echo h($user['User']['authkey']); ?></span>
            <?php
                    if (!Configure::read('MISP.disableUserSelfManagement') || $isAdmin):
                        echo ' (' . $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id'])) . ')';
                    endif;
                else:
                    echo "<a onclick=\"requestAPIAccess();\" style=\"cursor:pointer;\">". __('Request API access') . "</a>";
                endif;
            ?>
            &nbsp;
        </dd>
        <dt><?php echo __('NIDS Start SID'); ?></dt>
        <dd>
            <?php echo h($user['User']['nids_sid']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Termsaccepted'); ?></dt>
        <dd>
            <?php echo h((0 == $user['User']['termsaccepted'])? __('No') : __('Yes')); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('GnuPG key'); ?></dt>
        <dd class="quickSelect <?php echo $user['User']['gpgkey'] ? 'green' : 'bold red'; ?>">
            <?php echo $user['User']['gpgkey'] ? nl2br(h($user['User']['gpgkey'])) : __("N/A"); ?>
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
            <dd class="bold <?php echo (empty($user['User']['pgp_status']) || $user['User']['pgp_status'] != 'OK') ? 'red': 'green'; ?>">
                <?php
                    echo !empty($user['User']['pgp_status']) ? h($user['User']['pgp_status']) : 'N/A';
                ?>
            </dd>
        <?php
            endif;
        ?>
        <?php if (Configure::read('SMIME.enabled')): ?>
            <dt><?php echo __('SMIME Public certificate'); ?></dt>
            <dd class="red quickSelect">
                <?php echo (h($user['User']['certif_public'])) ? $this->Utility->space2nbsp(nl2br(h($user['User']['certif_public']))) : "N/A"; ?>
            </dd>
        <?php endif; ?>
    </dl>
    <br />
    <a href="<?php echo $baseurl . '/users/view/me.json'; ?>" class="btn btn-inverse" download>Download user profile for data portability</a>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));
?>
