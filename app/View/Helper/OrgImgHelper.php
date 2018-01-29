<?php
App::uses('AppHelper', 'View/Helper');

// Helper to retrieve org images with the given parameters
	class OrgImgHelper extends AppHelper {
    public function getOrgImg($options) {
      $imgPath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS;
      $imgOptions = array();
      $possibleFields = array('id', 'name');
      $size = !empty($options['size']) ? $options['size'] : 48;
      foreach ($possibleFields as $field) {
        if (isset($options[$field]) && file_exists($imgPath . $options[$field] . '.png')) {
          $imgOptions[$field] = $options[$field] . '.png';
          break;
        }
      }
      if (!empty($imgOptions)) {
        foreach ($imgOptions as $field => $imgOption) {
        ?>
          <img
            src="/img/orgs/<?php echo $imgOption; ?>"
            title = "<?php echo isset($imgOptions['name']) ? h($imgOptions['name']) : h($imgOptions['id']); ?>"
            style = "<?php echo 'width:' . h($size) . 'px; height:' . h($size) . 'px'; ?>"
          />
        <?php
        }
      } else {
      ?>
        <span class="welcome" style="float:left"><?php echo $options['name']; ?></span>
      <?php
      }
    }
	}
?>
