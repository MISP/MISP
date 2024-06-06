<?php
App::uses('AppHelper', 'View/Helper');
App::uses('FileAccessTool', 'Lib/Tools');

class ImageHelper extends AppHelper
{
    /** @var array */
    private $imageCache = [];

    /**
     * Converts image file to data format
     * @param string $imagePath Path to file
     * @return string
     * @throws Exception
     */
    public function base64($imagePath)
    {
        if (isset($this->imageCache[$imagePath])) {
            return $this->imageCache[$imagePath];
        }

        $ext = strtolower(pathinfo($imagePath, PATHINFO_EXTENSION));
        if ($ext === 'svg') {
            $mime = 'image/svg+xml';
        } else if ($ext === 'png') {
            $mime = 'image/png';
        } else {
            throw new InvalidArgumentException("Only SVG and PNG images are supported, '$ext' file provided.");
        }

        try {
            $fileContent = FileAccessTool::readFromFile($imagePath);
        } catch (Exception $e) {
            CakeLog::warning($e);
            return 'data:null'; // in case file doesn't exists or is not readable
        }

        $fileContentEncoded = base64_encode($fileContent);
        $base64 = "data:$mime;base64,$fileContentEncoded";

        return $this->imageCache[$imagePath] = $base64;
    }
}