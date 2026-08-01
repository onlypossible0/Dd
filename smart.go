package main

import (
	"net/url"
	"strings"
)

// DetectSmartPaths analyzes the target URL and generates the most effective attack paths.
func DetectSmartPaths(rawURL string) *SmartPaths {
	u, _ := url.Parse(rawURL)
	baseURL := u.Scheme + "://" + u.Host
	urlPath := strings.Trim(u.Path, "/")

	paths := &SmartPaths{
		LoginGET:  rawURL,
		LoginPOST: rawURL,
		Dashboard: baseURL,
		Profile:   baseURL,
	}

	// Extract the "base prefix" — everything before the last path segment
	// e.g. "/sms/SignIn" → base prefix = "/sms", action = "SignIn"
	// e.g. "/login" → base prefix = "", action = "login"
	lastSlash := strings.LastIndex(urlPath, "/")
	var basePrefix, action string
	if lastSlash >= 0 {
		basePrefix = "/" + urlPath[:lastSlash]
		action = urlPath[lastSlash+1:]
	} else {
		basePrefix = ""
		action = urlPath
	}

	// Detect action type
	actionLower := strings.ToLower(action)

	// Determine POST endpoint based on known patterns
	postAction := action // default: same as GET
	switch {
	case actionLower == "signin":
		postAction = "signmein"
	case actionLower == "login":
		postAction = "signmein" // fallback for login pages
	case actionLower == "signmein":
		// Already POST endpoint, keep as is
	}

	// Build correct GET and POST URLs
	if basePrefix != "" {
		paths.LoginGET = baseURL + basePrefix + "/" + action
		paths.LoginPOST = baseURL + basePrefix + "/" + postAction
	} else {
		paths.LoginGET = baseURL + "/" + action
		paths.LoginPOST = baseURL + "/" + postAction
	}

	// Dashboard and Profile paths
	paths.Dashboard = baseURL + basePrefix + "/test/"
	paths.Profile = baseURL + basePrefix + "/test/Profile"

	return paths
}
