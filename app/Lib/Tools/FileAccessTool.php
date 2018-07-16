<?php

class FileAccessTool {
	private $__fileErrorMsgPrefix = 'An error has occured while attempting to ';

	public function createTempFile($dir, $prefix = 'MISP') {
		$tempFile = tempnam($dir, $prefix);
		$this->__checkForFalse($tempFile, 'create a temporary file in path "' . $dir);
		return $tempFile;
	}

	public function readFromFile($file, $fileSize = -1) {
		$this->__checkForFalse($file, 'create file "' . $file);
		$fileHandle = fopen($file, 'rb');
		$this->__checkForFalse($fileHandle, 'access file "' . $file);
		if ($fileSize === -1) {
			$fileSize = filesize($file);
			$this->__checkForFalse($fileHandle, 'get filesize from file "' . $file);
		}
		$readResult = fread($fileHandle, $fileSize);
		$this->__checkForFalse($fileHandle, 'read from file "' . $file);
		fclose($fileHandle);
		return $readResult;
	}

	public function writeToFile($file, $content) {
		$this->__checkForFalse($file, 'create file "' . $file);
		$fileHandle = fopen($file, 'wb');
		$this->__checkForFalse($fileHandle, 'access file "' . $file);
		$writeResult = fwrite($fileHandle, $content);
		$this->__checkForFalse($writeResult, 'write to file "' . $file);
		fclose($fileHandle);
		return $file;
	}

	private function __checkForFalse($result, $errorMsgPart) {
		if ($result === false) {
			throw new MethodNotAllowedException($this->__fileErrorMsgPrefix . $errorMsgPart . '".');
		}
	}

	public function deleteFile($file) {
		unlink($file);
		return true;
	}
}
