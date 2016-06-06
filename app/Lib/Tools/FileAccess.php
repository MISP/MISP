<?php

class FileAccess {
	private static $__fileErrorMsgPrefix = 'An error has occured while attempting to ';

	public static function createTempFile($dir, $prefix = 'MISP') {
		$tempFile = tempnam($dir, $prefix);
		self::checkForFalse($tempFile, 'create a temporary file in path "' . $dir);
		return $tempFile;
	}

	public static function readFromFile($file, $fileSize = -1) {
		self::checkForFalse($file, 'create file "' . $file);
		$fileHandle = fopen($file, 'rb');
		self::checkForFalse($fileHandle, 'access file "' . $file);
		if ($fileSize === -1) {
			$fileSize = filesize($file);
			self::checkForFalse($fileHandle, 'get filesize from file "' . $file);
		}
		$readResult = fread($fileHandle, $fileSize);
		self::checkForFalse($fileHandle, 'read from file "' . $file);
		fclose($fileHandle);
		return $readResult;
	}

	public static function writeToFile($file, $content) {
		self::checkForFalse($file, 'create file "' . $file);
		$fileHandle = fopen($file, 'wb');
		self::checkForFalse($fileHandle, 'access file "' . $file);
		$writeResult = fwrite($fileHandle, $content);
		self::checkForFalse($writeResult, 'write to file "' . $file);
		fclose($fileHandle);
		return $file;
	}

	private static function checkForFalse($result, $errorMsgPart) {
		if ($result === false) {
			throw new Exception(self::$__fileErrorMsgPrefix . $errorMsgPart . '".');
		}
	}
}