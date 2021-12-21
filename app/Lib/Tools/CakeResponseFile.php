<?php
class CakeResponseFile extends CakeResponse
{
    /**
     * Modified version that supports also TmpFileTool and File
     *
     * @param string|TmpFileTool|File $path
     * @param array $options
     * @throws Exception
     */
    public function file($path, $options = array())
    {
        if ($path instanceof TmpFileTool) {
            $this->header('Content-Length', $path->size());
            $this->_clearBuffer();
            $this->_file = $path;
        } else if ($path instanceof File) {
            $options += array(
                'name' => null,
                'download' => null
            );

            if ($options['download']) {
                $name = $options['name'] === null ? $path->name : $options['name'];
                $this->download($name);
                $this->header('Content-Transfer-Encoding', 'binary');
            }

            $this->header('Accept-Ranges', 'bytes');
            $httpRange = env('HTTP_RANGE');
            if (isset($httpRange)) {
                $this->_fileRange($path, $httpRange);
            } else {
                $this->header('Content-Length', filesize($path->path));
            }

            $this->_clearBuffer();
            $this->_file = $path;
        } else {
            parent::file($path, $options);
        }
    }

    /**
     * This method supports TmpFileTool and also provides optimised variant for sending file from `File` object
     * @param File|TmpFileTool $file
     * @param array $range
     * @return bool
     * @throws Exception
     */
    protected function _sendFile($file, $range)
    {
        set_time_limit(0);
        session_write_close();

        if ($file instanceof TmpFileTool) {
            foreach ($file->intoChunks() as $chunk) {
                if (!$this->_isActive()) {
                    $file->close();
                    return false;
                }
                echo $chunk;
            }
        } else {
            $handler = fopen($file->path, 'rb');
            if ($handler === false) {
                throw new Exception("File $file->path doesn't exists anymore or is not readable.");
            }

            $end = $start = false;
            if ($range && is_array($range)) {
                list($start, $end) = $range;
            }
            if ($start !== false) {
                fseek($handler, $start);
            }

            $bufferSize = 8192;
            while (!feof($handler)) {
                if (!$this->_isActive()) {
                    $file->close();
                    return false;
                }
                $offset = ftell($handler);
                if ($end && $offset >= $end) {
                    break;
                }
                if ($end && $offset + $bufferSize >= $end) {
                    $bufferSize = $end - $offset + 1;
                }
                echo fread($handler, $bufferSize);
            }
            fclose($handler);
        }
        $this->_flushBuffer();
        return true;
    }

    /**
     * Faster version that do not do redundant check
     * @return bool
     */
    protected function _isActive()
    {
        return connection_status() === CONNECTION_NORMAL;
    }
}
