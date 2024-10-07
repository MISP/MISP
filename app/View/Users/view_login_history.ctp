<?php
echo sprintf('<div%s>', !$this->request->is('ajax') ? ' class="index"' : '');

?>
    <style>
        .device-overview {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin: 20px 0;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 10px;
            box-shadow: 0 5px 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
        }
        .device-name {
            font-size: 15px;
        }
</style>
<?php
foreach ($data as $entry) {
    $platform = h(strtolower($entry['platform']));
    if (str_contains($platform, 'win')) $platform = 'windows';
    if (str_contains($platform, 'macosx')) $platform = 'apple';
    if (str_contains($platform, 'ios')) $platform = 'apple';
    $bgcolor = 'white';
    if (str_contains($entry['status'], 'malicious')) $bgcolor = '#ffdddd';
    elseif (str_contains($entry['status'], 'trusted')) $bgcolor = '#ddffdd';
?>
    <div class="device-overview" style="background-color:<?= $bgcolor ?>;">
        <div>
        <span class="device-icon fab fa-<?= h(strtolower($platform))?>" style="font-size:30px;"></span>
        <span class="device-icon fab fa-<?= h(strtolower($entry['browser']))?>" style="font-size:30px;"></span>
        </div>
        <h3 class="device-name"><?= h($entry['platform']) ?>, <?= h($entry['browser']) ?></h3>
        <div class="device-location">
            <?= $this->Icon->countryFlag($entry['region']);?>
            <span class="device-info"><?= h($entry['region']). ' ('. h($entry['ip']). ')' ?></span>
        </div>
        <div><?= h($entry['actions']) ?></div>
        <div><?= h($entry['first_seen'])." - ".h($entry['last_seen']) ?></div>
        <?php if ('malicious' == $entry['status']) { ?>
            <i class="fas fa-bug" style="color:red; font-size:30px;"></i>
        <?php } elseif ('trusted'  == $entry['status']) { ?>
            <i class="fas fa-shield-alt" style="color:green; font-size:30px;"></i>
        <?php } elseif (str_contains($entry['status'], 'likely')) { 
            echo ("<div>".h($entry['status'])."</div>");
        }
        if ('unknown' == $entry['status'] || str_contains($entry['status'], 'likely')) { 
            echo "<div>";
            echo $this->Form->postLink(__('This was me'),array('controller' => 'userLoginProfiles', 'action'=>'trust', $entry['id']),array('class' => 'btn btn-inverse', 'style' => '', 'confirm' => __('Are you sure you want to mark this device as trusted?')));
            echo "&nbsp;";
            echo $this->Form->postLink(__('Report malicious'),array('controller' => 'userLoginProfiles', 'action'=>'malicious', $entry['id']),array('class' => 'btn btn-inverse','confirm' => __('Was this connection suspicious or malicious? If yes, you will be forced to change your password.')));
            echo "</div>";
        } ?>
    </div>


<?php
}

echo sprintf(
    '&nbsp;<a href="%s" class="btn btn-inverse">%s</a>',
    sprintf(
        '%s/userLoginProfiles/index/%s',
        $baseurl,
        $user_id
    ),
    __('Review user login profiles')
);
echo '</div>';

if (!$this->request->is('ajax')) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));
}
