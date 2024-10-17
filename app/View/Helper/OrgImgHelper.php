<?php
App::uses('AppHelper', 'View/Helper');
App::uses('FileAccessTool', 'Lib/Tools');

// Helper to retrieve org images with the given parameters
class OrgImgHelper extends AppHelper
{
    const IMG_PATH = APP . 'files' . DS . 'img' . DS . 'orgs' . DS;

    /** @var array */
    private $imageCache = [];

    public function getNameWithImg(array $organisation, $link = null)
    {
        if (!isset($organisation['Organisation'])) {
            return '';
        }

        $orgImgName = $this->findOrgImage($organisation['Organisation']);
        $baseurl = $this->_View->viewVars['baseurl'];
        if (!$link) {
            $link = $baseurl . '/organisations/view/' . (empty($organisation['Organisation']['id']) ? h($organisation['Organisation']['name']) : h($organisation['Organisation']['id']));
        }
        if ($orgImgName) {
            $base64 = $this->_View->Image->base64(self::IMG_PATH . $orgImgName);
            return sprintf('<a href="%s" style="background-image: url(\'%s\')" class="orgImg">%s</a>', $link, $base64, h($organisation['Organisation']['name']));
        } else {
            return sprintf('<a href="%s">%s</a>', $link, h($organisation['Organisation']['name']));
        }
    }

    /**
     * @param array $organisation
     * @param int $size
     * @param bool $withLink
     * @return string
     */
    public function getOrgLogo(array $organisation, $size, $withLink = true)
    {
        if (isset($organisation['Organisation'])) {
            $options = $organisation['Organisation'];
        } else {
            $options = $organisation;
        }
        $options['size'] = $size;
        return $this->getOrgImg($options, true, !$withLink);
    }

    /**
     * @param array $organisation
     * @return string|null
     */
    public function getOrgLogoAsBase64(array $organisation)
    {
        $orgImgName = $this->findOrgImage($organisation);
        if ($orgImgName) {
            return $this->_View->Image->base64(self::IMG_PATH . $orgImgName);
        }
        return null;
    }

    /**
     * @deprecated
     */
    public function getOrgImg($options, $returnData = false, $raw = false)
    {
        $orgImgName = $this->findOrgImage($options);
        $baseurl = $this->_View->viewVars['baseurl'];
        if ($orgImgName) {
            $size = !empty($options['size']) ? $options['size'] : 48;
            $result = sprintf(
                '<img src="%s" title="%s" width="%s" height="%s">',
                $this->_View->Image->base64(self::IMG_PATH . $orgImgName),
                isset($options['name']) ? h($options['name']) : h($options['id']),
                (int)$size,
                (int)$size
            );

            if (!$raw && !empty($options['id'])) {
                $result = sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    empty($options['id']) ? h($options['name']) : h($options['id']),
                    $result
                );
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
                    $baseurl,
                    empty($options['id']) ? h($options['name']) : h($options['id']),
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

    /**
     * @param array $options
     * @return string|null
     */
    private function findOrgImage(array $options)
    {
        if (isset($options['id']) && array_key_exists($options['id'], $this->imageCache)) {
            return $this->imageCache[$options['id']];
        }

        $image = null;
        foreach (['id', 'name', 'uuid'] as $field) {
            if (isset($options[$field])) {
                foreach (['png', 'svg'] as $extensions) {
                    if (file_exists(self::IMG_PATH . $options[$field] . '.' . $extensions)) {
                        $image = $options[$field] . '.' . $extensions;
                        break 2;
                    }
                }
            }
        }

        if (isset($options['id'])) {
            $this->imageCache[$options['id']] = $image;
        }

        return $image;
    }
}
