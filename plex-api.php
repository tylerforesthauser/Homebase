<?php
require_once "./util.php";
require_once "./multiCurl.php";

scriptDefaults();
$section = "PLEX";
$configFile = dirname(__FILE__) . "/rw/config.ini.php";
$result = "Please configure plex parameters.";

if (file_exists($configFile)) {
	$data = parse_ini_file($configFile,true);
	write_log("Got me a config: ".json_encode($data));
	$url = $data["$section"]["URL"] ?? false;
	$token = $data["$section"]["TOKEN"] ?? false;
	$movieSectionId = $data["$section"]["MSID"] ?? false;
	$tvSectionId = $data["$section"]["TSID"] ?? false;

	if ($url && $token) {
		if (!$movieSectionId || !$tvSectionId) {
			$sectionUrl = "$url/library/sections?X-Plex-Token=$token";
			$sections = curlGet($sectionUrl,false,4,true,true)['MediaContainer']['Directory'];
			if ($sections) {
				$out = [];
				foreach($sections as $check) {
					$type = $check['type'];
					$id = $check['key'];
					write_log("ID for $type is $id");
					if ($type == 'movie') {
						$data["$section"]["MSID"] = $id;
						$movieSectionId = $id;
					}
					if ($type == 'show') {
						$data["$section"]["TSID"] = $id;
						$tvSectionId = $id;
					}
				}
				if (isset($data["$section"]["MSID"]) || isset($data["$section"]["TSID"])) {
					write_log("Setting section info.");
					write_ini_file($data,$configFile);
				}
			}
		}
		if (isset($_GET['popularRatings'])) {
			// Get sections list, determine movies and shows section ID's
			$mainUrl = "";
			$urls = [];

			if ($tvSectionId) {
				$tvRatings = ["TV-14","TV-G","TV-MA","TV-PG","TV-Y","TV-Y7","None"];
				foreach($tvRatings as $rating) {
					$urls["TV_$rating"][] = "$url/library/sections/$tvSectionId/all?contentRating=$rating&X-Plex-Token=$token";
				}
			}

			if ($movieSectionId) {
				$movieRatings = ["Approved", "E", "G", "NR", "Not Rated", "PG", "PG-13", "Passed","R", "TV-14", "TV-G", "TV-MA", "TV-PG", "Unrated", "None"];
				foreach($movieRatings as $rating) {
					$urls["MOVIE_$rating"][] = "$url/library/sections/$movieSectionId/all?contentRating=$rating&X-Plex-Token=$token";
				}
			}

			$counts = [];
			if (count($urls)) {
				write_log("Doing a multicurl!");
				$results = (new \digitalhigh\multiCurl($urls))->process();
				foreach($results as $rating => $sectionResult) {
					$rating = explode("_",$rating);
					$counts[$rating[0]][$rating[1]] = $sectionResult['size'];
				}
			}
			if (count($counts)) write_log("Got da counts, son: ".json_encode($counts));
			header("Content-Type: application/json");
			echo json_encode($counts);
			die();

		}

		// Handle OG POST Messages
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
		$result = curlGet($url, $header);

		write_log("Result: " . json_encode($result));
	} else {
		write_log("No ". ($url ? " token" : " url").".","ERROR");
	}
}

echo $result;

// EOF
