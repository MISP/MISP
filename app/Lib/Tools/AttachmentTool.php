<?php
App::uses('AWSS3Client', 'Tools');

class AttachmentTool
{
    const ZIP_PASSWORD = 'infected';
    const ADVANCED_EXTRACTION_SCRIPT_PATH = APP . 'files/scripts/generate_file_objects.py';

    /** @var AWSS3Client */
    private $s3client;

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return bool
     * @throws Exception
     */
    public function exists($eventId, $attributeId, $path_suffix = '')
    {
        return $this->_exists(false, $eventId, $attributeId, $path_suffix);
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return bool
     * @throws Exception
     */
    public function shadowExists($eventId, $attributeId, $path_suffix = '')
    {
        return $this->_exists(true, $eventId, $attributeId, $path_suffix);
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return bool
     * @throws Exception
     */
    protected function _exists($shadow, $eventId, $attributeId, $path_suffix = '')
    {
        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $path = $this->getPath($shadow, $eventId, $attributeId, $path_suffix);
            return $s3->exist($path);
        } else {
            try {
                $this->_getFile($shadow, $eventId, $attributeId, $path_suffix);
            } catch (NotFoundException $e) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return string
     * @throws Exception
     */
    public function getContent($eventId, $attributeId, $path_suffix = '')
    {
        return $this->_getContent(false, $eventId, $attributeId, $path_suffix);
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return string
     * @throws Exception
     */
    public function getShadowContent($eventId, $attributeId, $path_suffix = '')
    {
        return $this->_getContent(true, $eventId, $attributeId, $path_suffix);
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $path_suffix
     * @return string
     * @throws Exception
     */
    protected function _getContent($shadow, $eventId, $attributeId, $path_suffix = '')
    {
        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $path = $this->getPath($shadow, $eventId, $attributeId, $path_suffix);
            return $s3->download($path);
        } else {
            $file = $this->_getFile($shadow, $eventId, $attributeId, $path_suffix);
            $result = $file->read();
            if ($result === false) {
                throw new Exception("Could not read file '{$file->path}'.");
            }
            return $result;
        }
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return File
     * @throws Exception
     */
    public function getFile($eventId, $attributeId, $pathSuffix = '')
    {
        return $this->_getFile(false, $eventId, $attributeId, $pathSuffix);
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return File
     * @throws Exception
     */
    public function getShadowFile($eventId, $attributeId, $pathSuffix = '')
    {
        return $this->_getFile(true, $eventId, $attributeId, $pathSuffix);
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return File
     * @throws Exception
     */
    protected function _getFile($shadow, $eventId, $attributeId, $pathSuffix = '')
    {
        $path = $this->getPath($shadow, $eventId, $attributeId, $pathSuffix);

        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $content = $s3->download($path);

            $file = new File($this->tempFileName());
            if (!$file->write($content)) {
                throw new Exception("Could not write temporary file '{$file->path}'.");
            }

        } else {
            $filepath = $this->attachmentDir() . DS . $path;
            $file = new File($filepath);
            if (!$file->exists()) {
                throw new NotFoundException("File '$filepath' does not exists.");
            }
        }

        return $file;
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $data
     * @param string $pathSuffix
     * @return bool
     * @throws Exception
     */
    public function save($eventId, $attributeId, $data, $pathSuffix = '')
    {
        return $this->_save(false, $eventId, $attributeId, $data, $pathSuffix);
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $data
     * @param string $pathSuffix
     * @return bool
     * @throws Exception
     */
    public function saveShadow($eventId, $attributeId, $data, $pathSuffix = '')
    {
        return $this->_save(true, $eventId, $attributeId, $data, $pathSuffix);
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $data
     * @param string $pathSuffix
     * @return bool
     * @throws Exception
     */
    protected function _save($shadow, $eventId, $attributeId, $data, $pathSuffix = '')
    {
        $path = $this->getPath($shadow, $eventId, $attributeId, $pathSuffix);

        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $s3->upload($path, $data);

        } else {
            $path = $this->attachmentDir() . DS . $path;
            $file = new File($path, true);
            if (!$file->write($data)) {
                throw new Exception("Could not save attachment to file '$path'.");
            }
        }

        return true;
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return bool
     * @throws Exception
     */
    public function delete($eventId, $attributeId, $pathSuffix = '')
    {
        return $this->_delete(false, $eventId, $attributeId, $pathSuffix);
    }

    /**
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return bool
     * @throws Exception
     */
    public function deleteShadow($eventId, $attributeId, $pathSuffix = '')
    {
        return $this->_delete(true, $eventId, $attributeId, $pathSuffix);
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return bool Return true if file was deleted, `false` if file doesn't exists.
     * @throws Exception
     */
    protected function _delete($shadow, $eventId, $attributeId, $pathSuffix = '')
    {
        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $path = $this->getPath($shadow, $eventId, $attributeId, $pathSuffix);
            $s3->delete($path);
        } else {
            try {
                $file = $this->_getFile($shadow, $eventId, $attributeId, $pathSuffix);
            } catch (NotFoundException $e) {
                return false;
            }

            if (!$file->delete()) {
                throw new Exception(__('Delete of file attachment failed. Please report to administrator.'));
            }
        }

        return true;
    }

    /**
     * Deletes all attributes and shadow attributes files.
     *
     * @param int $eventId
     * @return bool
     * @throws Exception
     */
    public function deleteAll($eventId)
    {
        if ($this->attachmentDirIsS3()) {
            $s3 = $this->loadS3Client();
            $s3->deleteDirectory($eventId);
        } else {
            $dirPath = $this->attachmentDir();

            foreach (array($dirPath, $dirPath . DS . 'shadow') as $dirPath) {
                $folder = new Folder($dirPath . DS . $eventId);
                if ($folder->pwd() && !$folder->delete()) {
                    throw new Exception("Delete of directory '{$folder->pwd()}' failed: " . implode(', ', $folder->errors()));
                }
            }
        }

        return true;
    }

    /**
     * It is not possible to use PHP extensions for compressing. The reason is, that extensions support just AES encrypted
     * files, but these files are not supported in Windows and in Python. So the only solution is to use 'zip' command.
     *
     * @param string $originalFilename
     * @param string $content
     * @param string $md5
     * @return string Content of zipped file
     * @throws Exception
     */
    public function encrypt($originalFilename, $content, $md5)
    {
        $tempDir = $this->tempDir();

        $contentsFile = new File($tempDir . DS . $md5, true);
        if (!$contentsFile->write($content)) {
            throw new Exception("Could not write content to file '{$contentsFile->path}'.");
        }
        $contentsFile->close();

        $fileNameFile = new File($tempDir . DS . $md5 . '.filename.txt', true);
        if (!$fileNameFile->write($originalFilename)) {
            throw new Exception("Could not write original file name to file '{$fileNameFile->path}'.");
        }
        $fileNameFile->close();

        $zipFile = new File($tempDir . DS . $md5 . '.zip');

        $exec = [
            'zip',
            '-j', // junk (don't record) directory names
            '-P', // use standard encryption
            self::ZIP_PASSWORD,
            escapeshellarg($zipFile->path),
            escapeshellarg($contentsFile->path),
            escapeshellarg($fileNameFile->path),
        ];

        try {
            $this->execute($exec);
            $zipContent = $zipFile->read();
            if ($zipContent === false) {
                throw new Exception("Could not read content of newly created ZIP file.");
            }

            return $zipContent;

        } catch (Exception $e) {
            throw new Exception("Could not create encrypted ZIP file '{$zipFile->path}'.", 0, $e);

        } finally {
            $fileNameFile->delete();
            $contentsFile->delete();
            $zipFile->delete();
        }
    }

    /**
     * @param string $content
     * @param array $hashTypes
     * @return array
     * @throws InvalidArgumentException
     */
    public function computeHashes($content, array $hashTypes = array())
    {
        $validHashes = array('md5', 'sha1', 'sha256');
        $hashes = [];
        foreach ($hashTypes as $hashType) {
            if (!in_array($hashType, $validHashes)) {
                throw new InvalidArgumentException("Hash type '$hashType' is not valid hash type.");
            }
            $hashes[$hashType] = hash($hashType, $content);
        }
        return $hashes;
    }

    /**
     * @param string $pythonBin
     * @param string $filePath
     * @return array
     * @throws Exception
     */
    public function advancedExtraction($pythonBin, $filePath)
    {
        return $this->executeAndParseJsonOutput([
            $pythonBin,
            self::ADVANCED_EXTRACTION_SCRIPT_PATH,
            '-p',
            escapeshellarg($filePath),
        ]);
    }

    /**
     * @param string $pythonBin
     * @return array
     * @throws Exception
     */
    public function checkAdvancedExtractionStatus($pythonBin)
    {
        return $this->executeAndParseJsonOutput([$pythonBin, self::ADVANCED_EXTRACTION_SCRIPT_PATH, '-c']);
    }

    private function tempFileName()
    {
        $randomName = (new RandomTool())->random_str(false, 12);
        return $this->tempDir() . DS . $randomName;
    }

    /**
     * @return string
     */
    private function tempDir()
    {
        return Configure::read('MISP.tmpdir') ?: sys_get_temp_dir();
    }

    /**
     * @return string
     */
    private function attachmentDir()
    {
        return Configure::read('MISP.attachments_dir') ?: (APP . 'files');
    }

    /**
     * Naive way to detect if we're working in S3
     * @return bool
     */
    public function attachmentDirIsS3()
    {
        return substr(Configure::read('MISP.attachments_dir'), 0, 2) === "s3";
    }

    /**
     * @return AWSS3Client
     */
    private function loadS3Client()
    {
        if ($this->s3client) {
            return $this->s3client;
        }

        $client = new AWSS3Client();
        $client->initTool();
        $this->s3client = $client;
        return $client;
    }

    /**
     * @param bool $shadow
     * @param int $eventId
     * @param int $attributeId
     * @param string $pathSuffix
     * @return string
     */
    private function getPath($shadow, $eventId, $attributeId, $pathSuffix)
    {
        $path = $shadow ? ('shadow' . DS) : '';
        return $path . $eventId . DS . $attributeId . $pathSuffix;
    }

    /**
     * @param array $command
     * @return array
     * @throws Exception
     */
    private function executeAndParseJsonOutput(array $command)
    {
        $output = $this->execute($command);

        $json = json_decode($output, true);
        if ($json === null) {
            throw new Exception("Command output is not valid JSON: " . json_last_error_msg());
        }
        return $json;
    }

    /**
     * This method is much more complicated than just `exec`, but it also provide stderr output, so Exceptions
     * can be much more specific.
     *
     * @param array $command
     * @return string
     * @throws Exception
     */
    private function execute(array $command)
    {
        $descriptorspec = [
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"], // stderr
        ];

        $command = implode(' ', $command);
        $process = proc_open($command, $descriptorspec, $pipes);
        if (!$process) {
            throw new Exception("Command '$command' could be started.");
        }

        $stdout = stream_get_contents($pipes[1]);
        if ($stdout === false) {
            throw new Exception("Could not get STDOUT of command.");
        }
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);
        if ($returnCode !== 0) {
            throw new Exception("Command '$command' return error code $returnCode. STDERR: '$stderr', STDOUT: '$stdout'");
        }

        return $stdout;
    }
}
