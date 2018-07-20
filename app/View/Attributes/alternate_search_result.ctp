<div class="event index">
    <h2><?php echo __('Alternate Search Results'); ?></h2>
    <p><?php echo __('This is a list of events that match the given search criteria sorted according to the percentage of matched attributes that are marked as IDS signatures (blue = IDS matches, red = non IDS matches).'); ?></p>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?php echo __('Event id'); ?></th>
            <th><?php echo __('Org'); ?></th>
            <th><?php echo __('Event info'); ?></th>
            <th><?php echo __('Event date'); ?></th>
            <th><?php echo __('Event graph'); ?></th>
            <th><?php echo __('Matches'); ?></th>
            <th><?php echo __('Attribute Count'); ?></th>

        </tr>

    <?php
        foreach ($events as $event) {
            ?>
            <tr>
                <td class="short"><a href="<?php echo $baseurl;?>/events/view/<?php echo h($event['Event']['id']); ?>"><?php echo h($event['Event']['id']); ?></a></td>
                <td class="short">
                    <?php
                        echo $this->OrgImg->getOrgImg(array('name' => $event['Event']['Orgc']['name'], 'id' => $event['Event']['Orgc']['id'], 'size' => 24));
                    ?>
                </td>
                <td>
                    <?php
                        if (strlen(h($event['Event']['info'])) > 63) {
                            echo substr(h($event['Event']['info']), 0, 60) . '...';
                        } else  echo h($event['Event']['info']);
                    ?>
                </td>
                <td class="short"><?php echo h($event['Event']['date']); ?></td>
                <?php
                    $to_ids =  100 * h($event['to_ids']) / (h($event['to_ids']) + h($event['no_ids']));
                ?>
                <td>
                    <div class="progress" style="width:300px;">
                        <div class="bar bar-info" style="width:<?php echo $to_ids . '%'; ?>"></div>
                        <div class="bar bar-danger" style="width:<?php echo 100-$to_ids . '%'; ?>"></div>
                        <span style="position:absolute;width:300px;color:white;display: block;text-align:center;"><?php echo intval($to_ids) . '%'; ?></span>
                    </div>
                </td>
                <td class="short"><?php echo h($event['to_ids']) + h($event['no_ids']) ?></td>
                <td class="short"><?php echo h($event['Event']['attribute_count']) ?></td>
            </tr>
            <?php
        }
    ?>
    </table>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'searchAttributes'));
?>
