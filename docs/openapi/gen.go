// IronWall-WAF — OpenAPI Auto-Generation Middleware
// Generates live OpenAPI 3.1.0 spec from code annotations.
// Serves Swagger UI, ReDoc, and raw YAML/JSON.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package openapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ── OpenAPI 3.1 Types ─────────────────────────────────────────────────────────

type OpenAPI struct {
	OpenAPI    string              `json:"openapi"`
	Info       Info                `json:"info"`
	Servers    []Server            `json:"servers,omitempty"`
	Tags       []Tag               `json:"tags,omitempty"`
	Paths      map[string]PathItem `json:"paths"`
	Components Components          `json:"components,omitempty"`
}

type Info struct {
	Title       string  `json:"title"`
	Version     string  `json:"version"`
	Description string  `json:"description,omitempty"`
	Contact     Contact `json:"contact,omitempty"`
	License     License `json:"license,omitempty"`
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

type License struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

type Operation struct {
	Summary     string            `json:"summary,omitempty"`
	Description string            `json:"description,omitempty"`
	OperationID string            `json:"operationId,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Security    []SecurityReq     `json:"security,omitempty"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	RequestBody *RequestBody      `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
	Deprecated  bool              `json:"deprecated,omitempty"`
}

type SecurityReq map[string][]string

type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"` // path|query|header|cookie
	Required    bool    `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
	Example     interface{} `json:"example,omitempty"`
}

type RequestBody struct {
	Required    bool                        `json:"required,omitempty"`
	Description string                      `json:"description,omitempty"`
	Content     map[string]MediaTypeObject  `json:"content"`
}

type MediaTypeObject struct {
	Schema   *Schema              `json:"schema,omitempty"`
	Examples map[string]Example   `json:"examples,omitempty"`
}

type Example struct {
	Summary string      `json:"summary,omitempty"`
	Value   interface{} `json:"value,omitempty"`
}

type Response struct {
	Description string                     `json:"description"`
	Content     map[string]MediaTypeObject `json:"content,omitempty"`
}

type Schema struct {
	Type        string             `json:"type,omitempty"`
	Format      string             `json:"format,omitempty"`
	Description string             `json:"description,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Enum        []interface{}      `json:"enum,omitempty"`
	Example     interface{}        `json:"example,omitempty"`
	Nullable    bool               `json:"nullable,omitempty"`
	Default     interface{}        `json:"default,omitempty"`
	Minimum     *float64           `json:"minimum,omitempty"`
	Maximum     *float64           `json:"maximum,omitempty"`
}

type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Schemas         map[string]*Schema        `json:"schemas,omitempty"`
}

type SecurityScheme struct {
	Type        string `json:"type"`
	Scheme      string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// ── Registry ──────────────────────────────────────────────────────────────────

// Registry collects route documentation from across the codebase
type Registry struct {
	mu   sync.RWMutex
	ops  []registeredOp
	spec *OpenAPI
}

type registeredOp struct {
	Method    string
	Path      string
	Operation Operation
}

var Global = &Registry{}

// Register adds an operation to the registry
func (r *Registry) Register(method, path string, op Operation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, registeredOp{
		Method:    strings.ToLower(method),
		Path:      openAPIPath(path), // convert :param to {param}
		Operation: op,
	})
	r.spec = nil // invalidate cached spec
}

// BuildSpec assembles the full OpenAPI spec from all registered operations
func (r *Registry) BuildSpec() *OpenAPI {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.spec != nil { return r.spec }

	paths := make(map[string]PathItem)
	for _, op := range r.ops {
		item := paths[op.Path]
		switch op.Method {
		case "get":    item.Get    = &op.Operation
		case "post":   item.Post   = &op.Operation
		case "put":    item.Put    = &op.Operation
		case "patch":  item.Patch  = &op.Operation
		case "delete": item.Delete = &op.Operation
		}
		paths[op.Path] = item
	}

	r.spec = &OpenAPI{
		OpenAPI: "3.1.0",
		Info: Info{
			Title:   "IronWall-WAF API",
			Version: "1.0.0",
			Description: "IronWall-WAF REST API — auto-generated from route annotations\n\n" +
				"**Publisher:** OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com\n" +
				"**Contact:** contact@optimiumnexus.com\n\n" +
				"Generated at: " + time.Now().UTC().Format(time.RFC3339),
			Contact: Contact{
				Name:  "OPTIMIUM NEXUS LLC",
				URL:   "https://www.optimiumnexus.com",
				Email: "contact@optimiumnexus.com",
			},
			License: License{Name: "Proprietary", URL: "https://www.optimiumnexus.com/license"},
		},
		Servers: []Server{
			{URL: "/", Description: "Current server"},
			{URL: "https://YOUR_WAF_HOST:9443", Description: "Management API"},
			{URL: "http://YOUR_WAF_HOST:8090",  Description: "License Server"},
			{URL: "http://YOUR_WAF_HOST:8080",  Description: "Customer Portal"},
			{URL: "http://YOUR_WAF_HOST:8085",  Description: "Admin Center"},
		},
		Tags: []Tag{
			{Name: "Health",          Description: "Service health and readiness"},
			{Name: "License — Public",  Description: "Public license validation (no auth)"},
			{Name: "License — Admin",   Description: "License management (X-Admin-Key required)"},
			{Name: "GeoIP",            Description: "Geographic IP rules and lookup"},
			{Name: "Zero-Day Shield",  Description: "ML anomaly detection"},
			{Name: "DDoS Mitigation",  Description: "Volumetric attack protection"},
			{Name: "Forensics",        Description: "PCAP capture and evidence packaging"},
			{Name: "Portal — Auth",    Description: "Customer portal authentication"},
			{Name: "Portal — Licenses", Description: "Self-service license management"},
			{Name: "Portal — Billing", Description: "Subscription and invoicing"},
			{Name: "Admin — Tenants",  Description: "Multi-tenant administration"},
			{Name: "Admin — Audit",    Description: "Immutable audit log"},
		},
		Paths: paths,
		Components: Components{
			SecuritySchemes: map[string]SecurityScheme{
				"AdminKey": {
					Type: "apiKey", In: "header", Name: "X-Admin-Key",
					Description: "Admin API key for license and management endpoints",
				},
				"BearerToken": {
					Type: "http", Scheme: "bearer", BearerFormat: "JWT",
					Description: "JWT token from /auth/login (8h validity)",
				},
				"PortalAPIKey": {
					Type: "apiKey", In: "header", Name: "X-API-Key",
					Description: "Customer portal API key",
				},
			},
			Schemas: buildSchemas(),
		},
	}
	return r.spec
}

// ── Gin Route Annotator ───────────────────────────────────────────────────────

// Annotator wraps a Gin router group to auto-register operations
type Annotator struct {
	group    *gin.RouterGroup
	registry *Registry
	tags     []string
	security []SecurityReq
}

func NewAnnotator(group *gin.RouterGroup, tags []string, security ...SecurityReq) *Annotator {
	return &Annotator{
		group: group, registry: Global,
		tags: tags, security: security,
	}
}

func (a *Annotator) GET(path, summary, description string, handler ...gin.HandlerFunc) gin.IRoutes {
	a.register("GET", path, summary, description, nil)
	return a.group.GET(path, handler...)
}

func (a *Annotator) POST(path, summary, description string, body *RequestBody, handler ...gin.HandlerFunc) gin.IRoutes {
	a.register("POST", path, summary, description, body)
	return a.group.POST(path, handler...)
}

func (a *Annotator) DELETE(path, summary, description string, handler ...gin.HandlerFunc) gin.IRoutes {
	a.register("DELETE", path, summary, description, nil)
	return a.group.DELETE(path, handler...)
}

func (a *Annotator) PUT(path, summary, description string, body *RequestBody, handler ...gin.HandlerFunc) gin.IRoutes {
	a.register("PUT", path, summary, description, body)
	return a.group.PUT(path, handler...)
}

func (a *Annotator) register(method, path, summary, description string, body *RequestBody) {
	op := Operation{
		Summary:     summary,
		Description: description,
		Tags:        a.tags,
		Security:    a.security,
		Responses: map[string]Response{
			"200": {Description: "Success", Content: map[string]MediaTypeObject{
				"application/json": {Schema: &Schema{Type: "object"}},
			}},
			"401": {Description: "Unauthorized — missing or invalid credentials"},
			"403": {Description: "Forbidden — insufficient permissions"},
			"422": {Description: "Validation error"},
			"500": {Description: "Internal server error"},
		},
	}
	if body != nil { op.RequestBody = body }

	// Extract path parameters
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, ":") {
			param := seg[1:]
			op.Parameters = append(op.Parameters, Parameter{
				Name: param, In: "path", Required: true,
				Schema: &Schema{Type: "string"},
			})
		}
	}

	a.registry.Register(method, path, op)
}

// ── Serving ───────────────────────────────────────────────────────────────────

// Mount registers the documentation endpoints on a Gin router
func Mount(r *gin.Engine) {
	// Load external spec if it exists (from docs/openapi/ironwall-api.yaml)
	externalSpec, _ := os.ReadFile("docs/openapi/ironwall-api.yaml")

	// Raw spec endpoints
	r.GET("/docs/openapi.json", func(c *gin.Context) {
		spec := Global.BuildSpec()
		c.Header("Access-Control-Allow-Origin", "*")
		c.JSON(http.StatusOK, spec)
	})

	r.GET("/docs/openapi.yaml", func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Content-Type", "application/yaml")
		if len(externalSpec) > 0 {
			c.Data(http.StatusOK, "application/yaml", externalSpec)
			return
		}
		// Auto-generate YAML from registered spec
		spec := Global.BuildSpec()
		data, _ := json.Marshal(spec)
		c.Data(http.StatusOK, "application/yaml", data)
	})

	// Swagger UI
	r.GET("/docs", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, swaggerUIHTML("/docs/openapi.json"))
	})

	// ReDoc
	r.GET("/docs/redoc", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, redocHTML("/docs/openapi.json"))
	})

	// Custom docs viewer (our own)
	r.StaticFile("/docs/custom", "docs/openapi/index.html")
	r.StaticFile("/docs/spec",   "docs/openapi/ironwall-api.yaml")

	fmt.Println("[openapi] Documentation served at:")
	fmt.Println("  Swagger UI  → /docs")
	fmt.Println("  ReDoc       → /docs/redoc")
	fmt.Println("  Custom      → /docs/custom")
	fmt.Println("  OpenAPI JSON → /docs/openapi.json")
	fmt.Println("  OpenAPI YAML → /docs/openapi.yaml")
}

// ── Swagger UI HTML ───────────────────────────────────────────────────────────

func swaggerUIHTML(specURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>IronWall-WAF API — Swagger UI</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css"/>
  <style>
    body { background: #07090f; margin: 0; }
    .topbar { background: #0e1118 !important; border-bottom: 1px solid #1a2435; }
    .topbar-wrapper a { color: #00d4ff !important; font-family: 'IBM Plex Mono', monospace; }
    .topbar .download-url-wrapper { display: none; }
    .swagger-ui .info .title { color: #00d4ff; }
    .swagger-ui .info { background: #0e1118; padding: 20px; border-radius: 8px; }
  </style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-standalone-preset.min.js"></script>
<script>
window.onload = function() {
  SwaggerUIBundle({
    url: "%s",
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "StandaloneLayout",
    syntaxHighlight: { activate: true, theme: "monokai" },
    defaultModelsExpandDepth: 2,
    defaultModelExpandDepth: 2,
    docExpansion: "list",
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    persistAuthorization: true,
    tryItOutEnabled: true,
    requestInterceptor: (request) => {
      request.headers['X-IronWall-Docs'] = '1';
      return request;
    },
  });
};
</script>
</body>
</html>`, specURL)
}

// ── ReDoc HTML ────────────────────────────────────────────────────────────────

func redocHTML(specURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>IronWall-WAF API — ReDoc</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet"/>
  <style>
    body { margin: 0; font-family: 'IBM Plex Sans', sans-serif; }
    redoc-footer { display: none; }
  </style>
</head>
<body>
  <redoc spec-url="%s"
    theme='{
      "colors": {
        "primary": { "main": "#00d4ff" },
        "http": {
          "get":    "#00e676",
          "post":   "#00d4ff",
          "put":    "#ff9100",
          "delete": "#ff1744",
          "patch":  "#d500f9"
        },
        "tonalOffset": 0.2
      },
      "sidebar": {
        "backgroundColor": "#0c1019",
        "textColor": "#c8d8e8",
        "width": "260px"
      },
      "typography": {
        "fontSize": "14px",
        "fontFamily": "IBM Plex Sans, sans-serif",
        "headings": { "fontFamily": "IBM Plex Sans, sans-serif" },
        "code": { "fontFamily": "IBM Plex Mono, monospace", "fontSize": "13px" }
      },
      "rightPanel": {
        "backgroundColor": "#0e1118"
      }
    }'
    hide-download-button
    expand-responses="200,201"
    no-auto-auth
  ></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.3/bundles/redoc.standalone.js"></script>
</body>
</html>`, specURL)
}

// ── Schema Builders ───────────────────────────────────────────────────────────

func buildSchemas() map[string]*Schema {
	str  := func(desc string) *Schema { return &Schema{Type:"string",  Description:desc} }
	num  := func(desc string) *Schema { return &Schema{Type:"integer", Description:desc} }
	bool_:= func(desc string) *Schema { return &Schema{Type:"boolean", Description:desc} }
	arr  := func(items *Schema, desc string) *Schema { return &Schema{Type:"array", Items:items, Description:desc} }
	ref  := func(name string) *Schema { return &Schema{Ref:"#/components/schemas/"+name} }

	return map[string]*Schema{
		"Error": {
			Type: "object",
			Properties: map[string]*Schema{
				"error":   str("Human-readable error message"),
				"code":    str("Machine-readable error code"),
				"details": {Type:"object"},
			},
		},
		"LicenseTier": {
			Type: "string",
			Enum: []interface{}{"COMMUNITY","PROFESSIONAL","ENTERPRISE","ULTIMATE","TRIAL","DEVELOPER"},
		},
		"ValidationResult": {
			Type: "object",
			Properties: map[string]*Schema{
				"valid":             bool_("Whether the license is valid"),
				"tier":              ref("LicenseTier"),
				"licensee":          str("Company or person name"),
				"email":             {Type:"string", Format:"email"},
				"key":               {Type:"string", Example:"IW-ENT-A3F2-B9K1-M7X4-Z2P8"},
				"is_lifetime":       bool_(""),
				"days_remaining":    {Type:"integer", Description:"-1 = lifetime, 0 = expired"},
				"expires_at":        {Type:"string", Format:"date-time", Nullable:true},
				"features":          arr(str("feature name"), "Features granted by this license"),
				"extra_features":    arr(str(""), "Additional features beyond tier defaults"),
				"disabled_features": arr(str(""), "Features explicitly disabled"),
				"errors":            arr(str(""), "Validation errors"),
				"warnings":          arr(str(""), "Validation warnings"),
				"feature_available": {Type:"boolean", Nullable:true, Description:"Set only when feature param provided"},
			},
		},
		"LicenseLimits": {
			Type: "object",
			Properties: map[string]*Schema{
				"max_sites":            {Type:"integer", Description:"-1 = unlimited"},
				"max_requests_per_sec": {Type:"integer"},
				"max_nodes":            {Type:"integer"},
				"max_users":            {Type:"integer"},
				"max_custom_rules":     {Type:"integer"},
				"support_level":        {Type:"string", Enum:[]interface{}{"community","email","priority","dedicated"}},
				"update_channel":       {Type:"string", Enum:[]interface{}{"stable","lts","edge"}},
			},
		},
		"IssueLicenseRequest": {
			Type:     "object",
			Required: []string{"tier","licensee","email"},
			Properties: map[string]*Schema{
				"tier":             ref("LicenseTier"),
				"licensee":         {Type:"string", Example:"Acme Corporation"},
				"email":            {Type:"string", Format:"email"},
				"domain":           str("Optional domain binding"),
				"hardware_id":      str("Optional hardware fingerprint"),
				"valid_for_days":   {Type:"integer", Default:365, Description:"0 = lifetime license"},
				"extra_features":   arr(str(""), "Features to add beyond tier"),
				"disabled_features": arr(str(""), "Features to remove from tier"),
				"notes":            str("Internal notes"),
			},
		},
		"Tenant": {
			Type: "object",
			Properties: map[string]*Schema{
				"id":            {Type:"string", Format:"uuid"},
				"name":          str("Tenant display name"),
				"slug":          str("URL-safe identifier"),
				"plan":          {Type:"string", Enum:[]interface{}{"trial","pro","enterprise","ultimate"}},
				"status":        {Type:"string", Enum:[]interface{}{"active","suspended","deleted"}},
				"region":        str("Deployment region"),
				"max_users":     {Type:"integer", Description:"-1 = unlimited"},
				"max_sites":     num("-1 = unlimited"),
				"contact_email": {Type:"string", Format:"email"},
				"created_at":    {Type:"string", Format:"date-time"},
			},
		},
		"AnomalyScore": {
			Type: "object",
			Properties: map[string]*Schema{
				"score":              {Type:"number", Description:"0.0–1.0 (1.0 = most anomalous)"},
				"level":             {Type:"string", Enum:[]interface{}{"normal","suspect","anomaly","zero_day"}},
				"is_zero_day":       bool_(""),
				"confidence":        {Type:"number"},
				"baseline_deviation": {Type:"number"},
				"explanation":       str("Human-readable explanation of the score"),
			},
		},
		"DDoSEvent": {
			Type: "object",
			Properties: map[string]*Schema{
				"attack_type": {Type:"string", Enum:[]interface{}{"volumetric","http_flood","slow_loris","amplification","syn_flood","rudy"}},
				"source_ip":   str(""),
				"rps":         {Type:"number"},
				"action":      {Type:"string", Enum:[]interface{}{"allow","challenge","throttle","block","tarpit","null_route"}},
				"detected_at": {Type:"string", Format:"date-time"},
			},
		},
	}
}

// ── Utilities ─────────────────────────────────────────────────────────────────

// openAPIPath converts Gin-style :param to OpenAPI {param}
func openAPIPath(ginPath string) string {
	parts := strings.Split(ginPath, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

// JSONBody creates a RequestBody for a JSON payload
func JSONBody(schema *Schema, description string, required bool) *RequestBody {
	return &RequestBody{
		Required:    required,
		Description: description,
		Content: map[string]MediaTypeObject{
			"application/json": {Schema: schema},
		},
	}
}

// OKResponse builds a standard 200 response
func OKResponse(schema *Schema) map[string]Response {
	return map[string]Response{
		"200": {Description: "Success", Content: map[string]MediaTypeObject{
			"application/json": {Schema: schema},
		}},
		"401": {Description: "Unauthorized"},
		"403": {Description: "Forbidden"},
	}
}
