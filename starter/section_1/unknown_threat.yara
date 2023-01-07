rule darklord_detector {
        meta:
                Author = "@abhinavbom"
                Description = "This rule detects darklord malware."
        strings:
		$domain = "darkl0rd.com:7758"
		$org = "darkl0rd"
		$port = "7758"
		$path = "/root" nocase

        condition:
                all of them

}
