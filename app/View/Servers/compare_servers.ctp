<?php
    $serverTemplate = array(
        'id', 'name', 'url'
    );
?>
<div class="index">
    <h2><?php echo __('Server events overlap analysis matrix');?></h2>
    <?php
        if (count($servers) >= 2):
    ?>
        <div>
            <table class="table table-striped table-hover table-condensed" style="width:100px;">
                <tr>
                        <th>&nbsp;</th>
                    <?php
                    foreach ($servers as $server):
                        $popover = '';
                        foreach ($serverTemplate as $element) {
                            $popover .= '<span class=\'bold\'>' . Inflector::humanize($element) . '</span>: <span class=\'bold blue\'>' . h($server['Server'][$element]) . '</span><br>';
                        }
                  ?>
                    <th>
                        <div data-toggle="popover" data-content="<?= $popover; ?>" data-trigger="hover">
                            <?= 'S' . h($server['Server']['id']) ?>
                        </div>
                    </th>
                  <?php
                    endforeach;
                  ?>
                </tr>
              <?php
                foreach ($servers as $item):
                    $popover = '';
                    foreach ($serverTemplate as $element) {
                        $popover .= '<span class=\'bold\'>' . Inflector::humanize($element) . '</span>: <span class=\'bold blue\'>' . h($item['Server'][$element]) . '</span><br>';
                    }
              ?>
                <tr>
                    <td class="short">
                        <div data-toggle="popover" data-content="<?php echo $popover;?>" data-trigger="hover">
                            <?= __('Server #%s: %s', h($item['Server']['id']), h($item['Server']['name'])) ?>
                        </div>
                    </td>
                        <?php
                        foreach ($servers as $item2):
                            $percentage = $count = null;
                            if (isset($overlap[$item['Server']['id']][$item2['Server']['id']])) {
                                $percentage = $overlap[$item['Server']['id']][$item2['Server']['id']]['percentage'];
                                $count = $overlap[$item['Server']['id']][$item2['Server']['id']]['events'];
                            }

                            $class = 'bold';
                            if ($percentage !== null) {
                                if ($percentage <= 5) {
                                    $class .= ' green';
                                } else if ($percentage <= 50) {
                                    $class .= ' orange';
                                } else {
                                    $class .= ' red';
                                }
                            }

                            if ($percentage === null) {
                                $popover = '';
                            } else if ($percentage == 0) {
                                $popover = __('None or less than 1 % of the events of %s is contained in %s (%s matching events)', $item['Server']['name'], $item2['Server']['name'], $count);
                            } else if ($percentage > 0) {
                                $popover = __('%s % of the events of %s is contained in %s (%s matching events)', $percentage, $item['Server']['name'], $item2['Server']['name'], $count);
                            }
                            ?>
                                <td class="<?= h($class); ?>">
                                    <div data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover">
                                        <?= $percentage === null ? '-' : h($percentage) . '&nbsp;%' ?>
                                    </div>
                                </td>
                            <?php
                        endforeach;
                      ?>
                </tr>
              <?php
                endforeach;
              ?>
            </table>
        </div>
    <?php
        else:
            echo '<p class="red bold">Not enough remote servers. Make sure you have at least 2 server that are enabled and available.</p>';
        endif;
    ?>
</div>
<script type="text/javascript">
    $(function(){
        popoverStartup();
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'compareServers'));
