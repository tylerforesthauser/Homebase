<?php
require_once "./util.php";
scriptDefaults();
$section = "PLEX";
$configFile = dirname(__FILE__) . "/rw/config.ini.php";
$result = "Please configure plex parameters.";

if (file_exists($configFile)) {
	$data = parse_ini_file($configFile,true);
	write_log("Got me a config: ".json_encode($data));
	$url = $data["$section"]["URL"] ?? false;
	$token = $data["$section"]["TOKEN"] ?? false;

	if ($url && $token) {
		$url .= $_POST['postData'];
		$header = [
			'X-Plex-Platform: Web Server',
			'X-Plex-Platform-Version: 1.0',
			'X-Plex-Provides: controller',
			'X-Plex-Client-Identifier: 923A3BBB-98AF-53CD-8916-D72BE92DA7E4',
			'X-Plex-Product: Homebase (for Plex)',
			'X-Plex-Version: 1.0',
			'X-Plex-Device: Web Server',
			'X-Plex-Device-Name: Homebase Web Server',
			'X-Plex-Token: ' . $token,
			'Accept: application/json',
		];
		$result = curlGet($url,$header);
		write_log("Result: " . json_encode($result));
	} else {
		write_log("No ". ($url ? " token" : " url").".","ERROR");
	}
}

echo $result;

// EOF
