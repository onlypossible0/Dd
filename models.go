package main

import (
	"net/url"
	"strings"
)

// DetectSmartPaths analyzes the target URL and generates the most effective attack paths.
func DetectSmartPaths(rawURL string) *SmartPaths {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback
		return &SmartPaths{
			LoginGET:  rawURL,
			LoginPOST: rawURL,
		}
	}

	baseURL := u.Scheme + "://" + u.Host
	urlPath := strings.Trim(u.Path, "/")

	// -------------------------------------------
	// 1. Find the ACTION (last part of path)
	//    e.g. /ints/login  -> action = "login"
	//         /login       -> action = "login"
	// -------------------------------------------
	lastSlash := strings.LastIndex(urlPath, "/")
	var basePrefix, action string
	if lastSlash >= 0 {
		basePrefix = "/" + urlPath[:lastSlash]   // "/ints"
		action = urlPath[lastSlash+1:]           // "login"
	} else {
		basePrefix = ""
		action = urlPath                         // "login"
	}

	// -------------------------------------------
	// 2. Detect POST endpoint from action
	//    login / signin  -> signin
	//    signmein        -> signmein
	// -------------------------------------------
	actionLower := strings.ToLower(action)
	postAction := action // default same
	switch {
	case actionLower == "login" || actionLower == "signin":
		postAction = "signin"
	case actionLower == "signmein":
		postAction = "signmein"
	}

	// -------------------------------------------
	// 3. Build full URLs
	// -------------------------------------------
	paths := &SmartPaths{
		LoginGET:  rawURL,
		LoginPOST: rawURL,
		Dashboard: baseURL,
		Profile:   baseURL,
	}

	if basePrefix != "" {
		paths.LoginGET  = baseURL + basePrefix + "/" + action
		paths.LoginPOST = baseURL + basePrefix + "/" + postAction
	} else {
		paths.LoginGET  = baseURL + "/" + action
		paths.LoginPOST = baseURL + "/" + postAction
	}

	// -------------------------------------------
	// 4. Dashboard & Profile guesses
	// -------------------------------------------
	paths.Dashboard = baseURL + basePrefix + "/agent/"
	paths.Profile   = baseURL + basePrefix + "/agent/"

	// CSRF default (IMS SMS style)
	paths.CSRFEnabled = true
	paths.CSRFToken   = "etkk"

	return paths
}
