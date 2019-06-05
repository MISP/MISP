<?php
App::uses('AppHelper', 'View/Helper');

// Helper to retrieve org images with the given parameters
    class OrgImgHelper extends AppHelper {
        public function getOrgImg($options, $returnData = false, $raw = false) {
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
                    if ($raw) {
                        $result = sprintf(
                            '<img src="%s/img/orgs/%s" title = "%s" style = "width: %spx; height: %spx;"/>',
                            h(Configure::read('MISP.baseurl')),
                            $imgOption,
                            isset($options['name']) ? h($options['name']) : h($options['id']),
                            h($size),
                            h($size)
                        );
                    } else {
                        $result = sprintf(
                            '<a href="%s/organisations/view/%s"><img src="%s/img/orgs/%s" title = "%s" style = "width: %spx; height: %spx;"/></a>',
                            h(Configure::read('MISP.baseurl')),
                            (empty($options['id']) ? h($options['name']) : h($options['id'])),
                            h(Configure::read('MISP.baseurl')),
                            $imgOption,
                            isset($options['name']) ? h($options['name']) : h($options['id']),
                            h($size),
                            h($size)
                        );
                    }
                    break;
                }
            } else {
                if ($raw) {
                    $result = sprintf(
                        '<span class="welcome">%s</span>',
                        h($options['name'])
                    );
                } else {
                    $result = sprintf(
                        '<a href="%s/organisations/view/%s"><span class="welcome">%s</span></a>',
                        h(Configure::read('MISP.baseurl')),
                        (empty($options['id']) ? h($options['name']) : h($options['id'])),
                        h($options['name'])
                    );
                }

            }
            if ($returnData) {
                return $result;
            } else {
                echo $result;
            }
        }
    }
?>
