<div class="roles form">
<?php echo $this->Form->create('Role'); ?>
    <fieldset>
        <legend><?php echo __('Add Role');?></legend>
        <?php
            echo $this->Form->input('restricted_to_site_admin', array(
                'type' => 'checkbox',
                'class' => 'checkbox readonlyenabled',
                'label' => __('Restrict to site admins')
            ));
        ?>
            <div class = 'input clear'></div>
        <?php
            echo $this->Form->input('name');
            echo $this->Form->input('permission', array('type' => 'select', 'label' => __('Permissions'), 'options' => $options), array('value' => '3'));
        ?>
        <div class = 'input clear'></div>
        <?php
            echo $this->Form->input('memory_limit', array('label' => __('Memory limit') .  ' (' . h($default_memory_limit) . ')'));
            echo $this->Form->input('max_execution_time', array('label' => __('Maximum execution time') . ' (' . h($default_max_execution_time) . ')'));
        ?>
        <div class = 'input clear'></div>
        <?php
            echo $this->Form->input('enforce_rate_limit', array(
                'type' => 'checkbox',
                'label' => __('Enforce search rate limit')
            ));
        ?>
        <div class = 'input clear'></div>
        <div id="rateLimitCountContainer">
            <?php
                echo $this->Form->input('rate_limit_count', array('label' => __('# of searches / 15 min')));
            ?>
        </div>
        <div class = 'input clear'></div>
        <?php
            $counter = 1;
            foreach ($permFlags as $k => $flag):
        ?>
                <div class="permFlags<?php echo ' ' . ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled'); ?>">
        <?php
                    echo $this->Form->input($k, array(
                        'type' => 'checkbox',
                        'class' => 'checkbox ' . ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled'),
                        'checked' => false,
                        'label' => Inflector::humanize(substr($k, 5))
                    ));
                    if ($counter%3 == 0) echo "<div class = 'input clear'></div>";
                    $counter++;
        ?>
                </div>
        <?php
            endforeach;
        ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'addRole'));
?>

<script type="text/javascript">
    $(document).ready(function() {
        checkRolePerms();
        checkRoleEnforceRateLimit();
        $(".checkbox, #RolePermission").change(function() {
            checkRolePerms();
        });
        $("#RoleEnforceRateLimit").change(function() {
            checkRoleEnforceRateLimit();
        });
    });
</script>
<?php echo $this->Js->writeBuffer();
