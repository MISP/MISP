<div>
<p>
<?php
    /*
    * Display orgs logos
    * The input is a list of item.
    * Each item is expected to contain an org object with the name and id populated
    *
    * Example:
    * [{'Organisation' => array('name' => 'orgA', 'id' => 1)}, {'Organisation' => ...}]
    *
    */
    foreach ($data as $org) {
        echo '<a href="/organisations/view/'.h($org['Organisation']['id']).'" title="'.h($org['Organisation']['name']).'" target="_blank">';
        $img_data =  $this->OrgImg->getOrgImg(array('name' => $org['Organisation']['name'], 'id' => $org['Organisation']['id'], 'size' => 48), true, true);
        if (strncmp($img_data, "<span", 5) === 0) {  // the org has not uploaded a logo
            // We simulate a Logo where we take the first letter of the name
            $letter = substr($org['Organisation']['name'],0,1);
            echo '<div class="logo-box">'.$letter.'</div>';
        } else {
            echo $img_data;
        }
            echo '</a>';
    }
?>
</p>
</div>

<style widget-scoped>
.logo-box {
  display: inline-block;
  width: 44px;
  height: 29px;
  border: 2px solid white;
  background-color: rgb(240,240,240);
  color: rgb(0,136,204);
  font-size: 30px;
  text-align: center;
  vertical-align: middle;
  padding-top: 15px;
  text-transform: uppercase;
  font-weight: bold;
}
</style>
