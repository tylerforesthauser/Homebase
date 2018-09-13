<?php
require_once "./util.php";
scriptDefaults();
$section = "TAUTULLI";
$configFile = dirname(__FILE__) . "/rw/config.ini.php";
$result = "Please configure plex parameters.";

if (file_exists($configFile)) {
	$data = parse_ini_file($configFile,true);
	write_log("Got me a config: ".json_encode($data));
	$url = $data["$section"]["URL"] ?? false;
	$token = $data["$section"]["TOKEN"] ?? false;
	if ($url && $token) {
		$url .= "/api/v2?apikey=$token&" . http_build_query($_POST['postData']);
		$result = curlGet($url);
		write_log("Result: " . json_encode($result));
	} else {
		write_log("No ". ($url ? " token" : " url").".","ERROR");
	}
}

echo $result;
