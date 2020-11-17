<?php
class TmpFileTool
{
    /** @var resource */
    private $tmpfile;

    /** @var string */
    private $separator;

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
     * Write data to stream with separator. Separator will be prepend to content for next call.
     * @param string|Generator $content
     * @param string $separator
     * @throws Exception
     */
    public function writeWithSeparator($content, $separator)
    {
        if (isset($this->separator)) {
            if ($content instanceof Generator) {
                $this->write($this->separator);
                foreach ($content as $part) {
                    $this->write($part);
                }
            } else {
                $this->write($this->separator . $content);
            }
        } else {
            if ($content instanceof Generator) {
                foreach ($content as $part) {
                    $this->write($part);
                }
            } else {
                $this->write($content);
            }
        }
        $this->separator = $separator;
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
     * Get one line from file parsed as CSV.
     *
     * @param string $delimiter
     * @param string $enclosure
     * @param string $escape
     * @return Generator
     * @throws Exception
     */
    public function csv($delimiter = ',', $enclosure = '"', $escape = "\\")
    {
        $this->rewind();
        $line = 0;
        while (!feof($this->tmpfile)) {
            $result = fgetcsv($this->tmpfile, 0, $delimiter, $enclosure, $escape);
            if ($result === false) {
                throw new Exception("Could not read line $line from temporary CSV file.");
            }
            $line++;
            yield $result;
        }
        fclose($this->tmpfile);
        $this->tmpfile = null;
    }

    /**
     * @return Generator
     * @throws Exception
     */
    public function lines()
    {
        $this->rewind();
        while (!feof($this->tmpfile)) {
            $result = fgets($this->tmpfile);
            if ($result === false) {
                throw new Exception('Could not read line from temporary file.');
            }
            yield $result;
        }
        fclose($this->tmpfile);
        $this->tmpfile = null;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function finish()
    {
        $this->rewind();
        $final = stream_get_contents($this->tmpfile);
        if ($final === false) {
            throw new Exception('Could not read from temporary file.');
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

    /**
     * Seek to start of file.
     *
     * @throws Exception
     */
    private function rewind()
    {
        if (fseek($this->tmpfile, 0) === -1) {
            throw new Exception('Could not seek to start of temporary file.');
        }
    }
}
