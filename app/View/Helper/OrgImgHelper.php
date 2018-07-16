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
					<a href="/organisations/view/<?php echo empty($options['id']) ? h($options['name']) : h($options['id']); ?>">
	          <img
	            src="/img/orgs/<?php echo $imgOption; ?>"
	            title = "<?php echo isset($imgOptions['name']) ? h($imgOptions['name']) : h($imgOptions['id']); ?>"
	            style = "<?php echo 'width:' . h($size) . 'px; height:' . h($size) . 'px'; ?>"
	          />
					</a>
        <?php
					break;
        }
      } else {
      ?>
        <a href="/organisations/view/<?php echo empty($options['id']) ? h($options['name']) : h($options['id']); ?>">
					<span class="welcome" style="float:left"><?php echo h($options['name']); ?></span>
				</a>
      <?php
      }
    }
	}
?>
