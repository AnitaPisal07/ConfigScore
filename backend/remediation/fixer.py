from typing import List, Dict, Any

FIX_TEMPLATES = {
    "header-content-security-policy": {
        "title": "Content-Security-Policy (CSP)",
        "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:;\" always;",
        "apache": "Header set Content-Security-Policy \"default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:;\"",
        "express": "// npm install helmet\nconst helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy());",
        "python": "# FastAPI / Starlette\nfrom starlette.middleware.base import BaseHTTPMiddleware\n\nclass SecurityHeadersMiddleware(BaseHTTPMiddleware):\n    async def dispatch(self, request, call_next):\n        response = await call_next(request)\n        response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self' https:;\"\n        return response\n\napp.add_middleware(SecurityHeadersMiddleware)",
        "nextjs": "// next.config.js\nmodule.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self' https:;\" }\n        ]\n      }\n    ];\n  }\n};"
    },
    "header-strict-transport-security": {
        "title": "Strict-Transport-Security (HSTS)",
        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
        "express": "const helmet = require('helmet');\napp.use(helmet.hsts({\n  maxAge: 31536000,\n  includeSubDomains: true,\n  preload: true\n}));",
        "python": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'",
        "nextjs": "{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }"
    },
    "header-x-frame-options": {
        "title": "X-Frame-Options (Clickjacking Protection)",
        "nginx": "add_header X-Frame-Options \"DENY\" always;\n# Or for same-origin framing:\n# add_header X-Frame-Options \"SAMEORIGIN\" always;",
        "apache": "Header set X-Frame-Options \"DENY\"",
        "express": "const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
        "python": "response.headers['X-Frame-Options'] = 'DENY'",
        "nextjs": "{ key: 'X-Frame-Options', value: 'DENY' }"
    },
    "header-x-content-type-options": {
        "title": "X-Content-Type-Options (MIME Sniffing)",
        "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
        "apache": "Header set X-Content-Type-Options \"nosniff\"",
        "express": "const helmet = require('helmet');\napp.use(helmet.noSniff());",
        "python": "response.headers['X-Content-Type-Options'] = 'nosniff'",
        "nextjs": "{ key: 'X-Content-Type-Options', value: 'nosniff' }"
    },
    "header-referrer-policy": {
        "title": "Referrer-Policy",
        "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "apache": "Header set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "express": "const helmet = require('helmet');\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        "python": "response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
        "nextjs": "{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }"
    },
    "header-permissions-policy": {
        "title": "Permissions-Policy",
        "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
        "apache": "Header set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"",
        "express": "app.use((req, res, next) => {\n  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');\n  next();\n});",
        "python": "response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'",
        "nextjs": "{ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' }"
    },
    "server-version-leak": {
        "title": "Hide Server Version Leak",
        "nginx": "# In http block of nginx.conf:\nserver_tokens off;",
        "apache": "# In httpd.conf or apache2.conf:\nServerTokens Prod\nServerSignature Off",
        "express": "app.disable('x-powered-by');",
        "python": "# In Uvicorn / FastAPI\nuvicorn.run(\"main:app\", server_header=False)",
        "nextjs": "// next.config.js\nmodule.exports = {\n  poweredByHeader: false,\n};"
    },
    "x-powered-by-leak": {
        "title": "Strip X-Powered-By Header",
        "nginx": "proxy_hide_header X-Powered-By;",
        "apache": "Header unset X-Powered-By",
        "express": "app.disable('x-powered-by');",
        "python": "# Ensure no custom X-Powered-By headers are injected in responses",
        "nextjs": "module.exports = { poweredByHeader: false };"
    }
}

def generate_remediations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    remediations = []
    
    for f in findings:
        if f.get("status") in ["FAIL", "WARNING"]:
            fid = f.get("id", "")
            if fid in FIX_TEMPLATES:
                template = FIX_TEMPLATES[fid]
                remediations.append({
                    "finding_id": fid,
                    "title": template["title"],
                    "severity": f.get("severity"),
                    "recommendation": f.get("recommendation"),
                    "snippets": {
                        "nginx": template["nginx"],
                        "apache": template["apache"],
                        "express": template["express"],
                        "python": template["python"],
                        "nextjs": template["nextjs"]
                    }
                })

    return remediations
