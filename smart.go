package main

import (
	"net/url"
	"strings"
)

// DetectSmartPaths analyzes the target URL and generates the most effective attack paths.
// It also detects if the login page contains a CSRF token (like 'etkk').
func DetectSmartPaths(rawURL string) *SmartPaths {
	u, _ := url.Parse(rawURL)
	baseURL := u.Scheme + "://" + u.Host
	urlPath := strings.Trim(u.Path, "/")

	paths := &SmartPaths{
		LoginGET:    rawURL,
		LoginPOST:   rawURL,
		Dashboard:   baseURL,
		Profile:     baseURL,
		CSRFEnabled: false,
		CSRFToken:   "etkk", // default CSRF token name
	}

	// Extract the "base prefix" — everything before the last path segment
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
	postAction := action
	switch {
	case actionLower == "login" || actionLower == "signin":
		postAction = "signin"
	case actionLower == "signmein":
		postAction = "signmein"
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
	paths.Dashboard = baseURL + basePrefix + "/agent/SMSCDRReports"
	paths.Profile = baseURL + basePrefix + "/agent/MySMSNumbers"

	// Detect CSRF token pattern from the URL
	// Most SMS panels use 'etkk' as the CSRF token
	if strings.Contains(rawURL, "login") || strings.Contains(rawURL, "signin") {
		paths.CSRFEnabled = true
		paths.CSRFToken = "etkk"
	}

	return paths
}
