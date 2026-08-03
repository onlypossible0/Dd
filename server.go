package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg       *Config
	proxyMgr  *ProxyManager
	hub       *WebSocketHub
	attacks   *AttackRegistry
	indexHTML []byte
}

func NewServer(cfg *Config, pm *ProxyManager, hub *WebSocketHub, ar *AttackRegistry) *Server {
	return &Server{cfg: cfg, proxyMgr: pm, hub: hub, attacks: ar}
}

func (s *Server) SetIndexHTML(html []byte) { s.indexHTML = html }

func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/attack/create", s.handleCreate)
	mux.HandleFunc("/api/attack/start", s.handleStart)
	mux.HandleFunc("/api/attack/stop", s.handleStop)
	mux.HandleFunc("/api/attack/status", s.handleStatus)
	mux.HandleFunc("/api/attack/list", s.handleList)
	mux.HandleFunc("/api/attack/delete", s.handleDelete)
	mux.HandleFunc("/api/attack/redeploy", s.handleRedeploy)
	mux.HandleFunc("/ws/console", s.handleWebSocket)
	return corsMiddleware(mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(s.indexHTML)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed", "success": false})
		return
	}
	var req CreateAttackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON", "success": false})
		return
	}
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "target URL required", "success": false})
		return
	}
	smartPaths := DetectSmartPaths(req.URL)
	attackID := generateID()
	attackInfo := &AttackInfo{
		ID:          attackID,
		URL:         req.URL,
		TargetPaths: smartPaths,
		CreatedAt:   time.Now(),
		Status:      "stopped",
	}
	s.attacks.Store(attackID, attackInfo)
	log.Printf("[api] Attack created: %s -> %s", attackID, req.URL)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"attack_id": attackID,
		"url":       req.URL,
		"paths":     smartPaths,
	})
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed", "success": false})
		return
	}
	var req struct {
		AttackID     string      `json:"attack_id"`
		Layers       LayerConfig `json:"layers,omitempty"`
		Duration     int         `json:"duration,omitempty"`
		ProxyEnabled bool        `json:"proxy_enabled"`
		SessionID    string      `json:"session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON", "success": false})
		return
	}
	if req.AttackID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "attack_id required", "success": false})
		return
	}
	info := s.attacks.Load(req.AttackID)
	if info == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "attack not found", "success": false})
		return
	}
	if info.Status == "active" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "attack already running", "success": false})
		return
	}
	targetURL, err := ParseTarget(info.URL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid stored URL: " + err.Error(), "success": false})
		return
	}
	layers := req.Layers
	if layers.L1 == 0 { layers.L1 = s.cfg.DefaultLayers.L1 }
	if layers.L2 == 0 { layers.L2 = s.cfg.DefaultLayers.L2 }
	if layers.L3 == 0 { layers.L3 = s.cfg.DefaultLayers.L3 }
	if layers.L4 == 0 { layers.L4 = s.cfg.DefaultLayers.L4 }
	if layers.L5 == 0 { layers.L5 = s.cfg.DefaultLayers.L5 }
	workers := LayerWorkers{L1: layers.L1, L2: layers.L2, L3: layers.L3, L4: layers.L4, L5: layers.L5}
	duration := time.Duration(req.Duration) * time.Second
	if duration <= 0 { duration = s.cfg.DefaultDuration }

	// Update SmartPaths with SessionID
	if info.TargetPaths == nil {
		info.TargetPaths = DetectSmartPaths(info.URL)
	}
	if req.SessionID != "" {
		info.TargetPaths.SessionID = req.SessionID
	}

	orch := NewOrchestrator(targetURL, workers, duration, s.proxyMgr, s.hub, s.cfg, req.ProxyEnabled, info.TargetPaths)
	info.Orchestrator = orch
	info.Status = "active"
	s.attacks.Store(req.AttackID, info)

	go func() {
		orch.Start()
		info := s.attacks.Load(req.AttackID)
		if info != nil {
			info.Status = "stopped"
			info.Orchestrator = nil
			s.attacks.Store(req.AttackID, info)
		}
		s.hub.BroadcastLog("info", "Attack finished: "+req.AttackID)
	}()

	log.Printf("[api] Attack started: %s -> %s (workers: %d, session: %s)", req.AttackID, targetURL.String(), workers.Total(), req.SessionID)
	writeJSON(w, http.StatusOK, AttackResponse{AttackID: req.AttackID, Success: true})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func (s *Server) handleRedeploy(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// ... (unchanged)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

type AttackRegistry struct {
	attacks map[string]*AttackInfo
	mu      sync.RWMutex
}

func NewAttackRegistry() *AttackRegistry { return &AttackRegistry{attacks: make(map[string]*AttackInfo)} }
func (ar *AttackRegistry) Store(id string, info *AttackInfo) { ar.mu.Lock(); ar.attacks[id] = info; ar.mu.Unlock() }
func (ar *AttackRegistry) Load(id string) *AttackInfo { ar.mu.RLock(); defer ar.mu.RUnlock(); return ar.attacks[id] }
func (ar *AttackRegistry) Delete(id string) { ar.mu.Lock(); delete(ar.attacks, id); ar.mu.Unlock() }
func (ar *AttackRegistry) List() []*AttackInfo {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	list := make([]*AttackInfo, 0, len(ar.attacks))
	for _, v := range ar.attacks { list = append(list, v) }
	return list
}
func (ar *AttackRegistry) StopAll() {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	for _, info := range ar.attacks {
		if info.Orchestrator != nil { info.Orchestrator.Stop() }
	}
}
