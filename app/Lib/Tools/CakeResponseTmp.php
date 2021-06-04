<?php
class CakeResponseTmp extends CakeResponse
{
    public function file($path, $options = array())
    {
        if ($path instanceof TmpFileTool) {
            $this->header('Content-Length', $path->size());
            $this->_clearBuffer();
            $this->_file = $path;
        } else {
            parent::file($path, $options);
        }
    }

    /**
     * @param File|TmpFileTool $file
     * @param array $range
     * @return bool
     * @throws Exception
     */
    protected function _sendFile($file, $range)
    {
        if ($file instanceof TmpFileTool) {
            set_time_limit(0);
            session_write_close();

            foreach ($file->intoChunks() as $chunk) {
                if (!$this->_isActive()) {
                    $file->close();
                    return false;
                }
                echo $chunk;
                $this->_flushBuffer();
            }
            return true;
        } else {
            return parent::_sendFile($file, $range);
        }
    }
}
