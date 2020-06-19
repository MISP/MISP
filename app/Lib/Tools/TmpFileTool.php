<?php
class TmpFileTool
{
    /**
     * @var resource
     */
    private $tmpfile;

    /**
     * @param int $maxInMemory How many bytes should keep in memory before creating file on disk. By default is is 2 MB.
     * @throws Exception
     */
    public function __construct($maxInMemory = null)
    {
        if ($maxInMemory === null) {
            $maxInMemory = 2 * 1024 * 1024;
        }
        $this->tmpfile = fopen("php://temp/maxmemory:$maxInMemory", "w+");
        if ($this->tmpfile === false) {
            throw new Exception('Could not create temporary file.');
        }
    }

    /**
     * @param string $content
     * @throws Exception
     */
    public function write($content)
    {
        if (fwrite($this->tmpfile, $content) === false) {
            if ($this->tmpfile === null) {
                throw new Exception('Could not write to finished temporary file.');
            }
            $tmpFolder = sys_get_temp_dir();
            $freeSpace = disk_free_space($tmpFolder);
            throw new Exception("Could not write to temporary file in $tmpFolder folder. Maybe not enough space? ($freeSpace bytes left)");
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    public function finish()
    {
        fseek($this->tmpfile, 0);
        $final = stream_get_contents($this->tmpfile);
        if ($final === false) {
            throw new Exception("Could not read from temporary file.");
        }
        fclose($this->tmpfile);
        $this->tmpfile = null;
        return $final;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function __toString()
    {
        return $this->finish();
    }
}
