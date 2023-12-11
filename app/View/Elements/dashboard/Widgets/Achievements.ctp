<div>
<?php
/*
* This layout is split in two parts, the top part is the achiements already
* unlocked and the bottom part contains the one to get next.
*
* The data array to be passed has therefore 2 root keys: locked and unlocked.
* Each one is a list of item, each item must contain:
*   - icon (url to img file)
    - title (text description)
    - help_page (optional, link to an article)
*
* So the structure of the $data parameter must be something like:
* { 'locked': [{ 'icon': '/path/to/img.png', 'title': 'my great achievement', 'help_page': 'http://wikimedia'}, {...}], 'unlocked': [{...}]}
*/
    echo '<h3>'.__("Achievements Unlocked!").'</h3>';
    if(empty($data['unlocked'])) {
        echo '<p>'.__("You don't have any achievement yet. Check them below to get started!").'</p>';
    } else {
        echo '<table class="table table-striped table-hover table-condensed">';
        foreach ($data['unlocked'] as $item) {
            echo '<tr>';
            echo '<td><img class="badge-img" width=48 src='.h($item['icon']).' alt="badge"/></td>';
            echo '<td><div class="badge-description">'.h($item['title']).'</div></td>';
            echo '</tr>';
        }
        echo '</table>';
    }
    echo '<h3>'.__("Next on your list:").'</h3>';
    if(empty($data['locked'])) {
        echo '<p>'.__("Well done! You got them all.").'</p>';
    } else {
        echo '<table class="table table-striped table-hover table-condensed">';
        foreach ($data['locked'] as $item) {
            echo '<tr>';
            echo '<td><img class="badge-img" width=48 src='.h($item['icon']).' alt="badge"/></td>';
            echo '<td><div class="badge-description">'.h($item['title']).'</div></td>';
            if(!empty($item['help_page'])) {
                echo '<td><a href='.h($item['help_page']).' target="_blank">'.__("Read more here").'</a></td>';
            }
            echo '</tr>';
        }
        echo '</table>';
    }
?>
</div>

<style widget-scoped>
.badge-description {
    font-size: 11pt;
    padding: 5px;
    height: 43px;
    width: 100%;
}
.badge-img {
    padding-top: 5px;
    width: 48px;
    max-width: 48px;
}
</style>
