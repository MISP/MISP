<?php
$seed = mt_rand();
?>

<span style="margin: 0px 3px; display: inline-flex; flex-direction: column; gap: 2px; font-size: 75%">
   <?php foreach ($tagRelationshipTags as $i => $tagRelTag): ?>
      <span class="useCursorPointer tag-rel-tag-<?= $seed ?> <?= $i == 0 ? 'apply_css_arrow' : '' ?>" style="<?= $i == 0 ? '' : 'margin-left: 14px; margin-top: 2px;' ?>">
         <?php
         $name = $tagRelTag['Tag']['name'];
         $shortName = $name;
         if (strlen($name) <= 16) {
            $shortName = $name;
         } else {
            $exploded = explode('="', $name);
            if (count($exploded) > 1) {
               $shortName = substr($exploded[1], 0, -1);
            } else {
               $exploded = explode(':', $name);
               if (count($exploded) > 1) {
                  $shortName = $exploded[1];
               }
            }
         }
         ?>
         <?= $this->element('tag', ['tag' => ['Tag' => ['colour' => $tagRelTag['Tag']['colour'], 'name' => $shortName,]]]) ?>
      </span>
      <span class="useCursorPointer hidden tag-rel-tag-<?= $seed ?> <?= $i == 0 ? 'apply_css_arrow' : '' ?>" style="<?= $i == 0 ? '' : 'margin-left: 14px; margin-top: 2px;' ?>">
         <?= $this->element('tag', ['tag' => $tagRelTag]) ?>
      </span>
   <?php endforeach; ?>
</span>

<script>
   $(document).ready(function() {
      $('.tag-rel-tag-<?= $seed ?>').click(function() {
         $(this).parent().children().each(function() {
            $(this).toggle()
         })
      })
   })
</script>