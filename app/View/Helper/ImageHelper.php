<?php
App::uses('AppHelper', 'View/Helper');
App::uses('FileAccessTool', 'Lib/Tools');

class ImageHelper extends AppHelper
{
    /** @var array */
    private $imageCache = [];

    /**
     * @param string $imagePath Path to file
     * @return string
     * @throws Exception
     */
    public function base64($imagePath)
    {
        if (isset($this->imageCache[$imagePath])) {
            return $this->imageCache[$imagePath];
        }

        $ext = pathinfo($imagePath, PATHINFO_EXTENSION);
        if ($ext === 'svg') {
            $mime = 'image/svg+xml';
        } else if ($ext === 'png') {
            $mime = 'image/png';
        } else {
            throw new InvalidArgumentException("Only SVG and PNG images are supported");
        }

        $fileContent = base64_encode(FileAccessTool::readFromFile($imagePath));
        $base64 = "data:$mime;base64,$fileContent";

        return $this->imageCache[$imagePath] = $base64;
    }
}