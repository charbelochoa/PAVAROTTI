package trafico

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

var (
	mimeUnavailable = caso.HTTPFinding{Rule: "mime-ausente", Label: "Tipo de contenido ausente o inválido", Header: "Content-Type"}
	nosniffMissing  = caso.HTTPFinding{Rule: "nosniff-ausente", Label: "HTML sin X-Content-Type-Options: nosniff", Header: "X-Content-Type-Options"}
	frameMissing    = caso.HTTPFinding{Rule: "marcos-sin-politica", Label: "HTML sin protección de marcos declarada", Header: "X-Frame-Options y Content-Security-Policy"}
	referrerUnsafe  = caso.HTTPFinding{Rule: "referencia-unsafe-url", Label: "Referrer-Policy permite la URL completa", Header: "Referrer-Policy"}
	hstsMissing     = caso.HTTPFinding{Rule: "hsts-ausente", Label: "HTTPS sin cabecera HSTS", Header: "Strict-Transport-Security"}
	hstsInvalid     = caso.HTTPFinding{Rule: "hsts-invalida", Label: "HTTPS con política HSTS inválida", Header: "Strict-Transport-Security"}
	hstsInactive    = caso.HTTPFinding{Rule: "hsts-inactiva", Label: "HTTPS con HSTS desactivada", Header: "Strict-Transport-Security"}
	redirectHTTP    = caso.HTTPFinding{Rule: "redireccion-http", Label: "Redirección de HTTPS a HTTP", Header: "Location"}
	cookieSecure    = caso.HTTPFinding{Rule: "cookie-sin-secure", Label: "Cookies HTTPS sin atributo Secure", Header: "Set-Cookie"}
	cookieSameSite  = caso.HTTPFinding{Rule: "cookie-none-sin-secure", Label: "Cookies SameSite=None sin atributo Secure", Header: "Set-Cookie"}
	passiveRules    = []caso.HTTPFinding{mimeUnavailable, nosniffMissing, frameMissing, referrerUnsafe, hstsMissing, hstsInvalid,
		hstsInactive, redirectHTTP, cookieSecure, cookieSameSite}
)

func PassiveRules() []caso.HTTPFinding { return slices.Clone(passiveRules) }

func passiveFindings(origin, method, media string, status int, headers http.Header, observed time.Time) []caso.HTTPFinding {
	if headers == nil || status < 200 || status > 599 {
		return nil
	}
	var findings []caso.HTTPFinding
	add := func(rule caso.HTTPFinding, observation string) {
		rule.Observation = observation
		findings = append(findings, rule)
	}
	mayContainBody := status < 300 && status != 204 && status != 205 && method != http.MethodHead
	if mayContainBody && media == "" {
		add(mimeUnavailable, "Respuesta de éxito con cuerpo permitido y sin un tipo MIME válido.")
	}
	if mayContainBody && (media == "text/html" || media == "application/xhtml+xml") {
		if !strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff") {
			add(nosniffMissing, "El tipo MIME es HTML y falta el valor nosniff.")
		}
		if !framePolicyDeclared(headers) {
			add(frameMissing, "Faltan DENY o SAMEORIGIN en X-Frame-Options y una directiva frame-ancestors con valores en CSP aplicada.")
		}
		if referrerPolicy(headers.Values("Referrer-Policy")) == "unsafe-url" {
			add(referrerUnsafe, "La última política reconocida es unsafe-url.")
		}
	}
	https := strings.HasPrefix(origin, "https://")
	if https {
		values := headers.Values("Strict-Transport-Security")
		if len(values) == 0 {
			add(hstsMissing, "La respuesta HTTPS carece de Strict-Transport-Security.")
		} else if active, valid := hstsMaxAge(values[0]); !valid {
			add(hstsInvalid, "La primera cabecera HSTS requiere un único max-age numérico.")
		} else if !active {
			add(hstsInactive, "La cabecera anuncia max-age=0.")
		}
		if isRedirect(status) && strings.HasPrefix(caso.Origin(strings.TrimSpace(headers.Get("Location"))), "http://") {
			add(redirectHTTP, "La respuesta dirige a un origen con esquema HTTP.")
		}
	}
	withoutSecure, noneWithoutSecure, total := reviewCookies(headers.Values("Set-Cookie"), observed)
	if https && withoutSecure > 0 {
		add(cookieSecure, fmt.Sprintf("Falta Secure en %d de %d cookies analizadas.", withoutSecure, total))
	}
	if noneWithoutSecure > 0 {
		add(cookieSameSite, fmt.Sprintf("Se observaron %d cookies con SameSite=None y sin Secure.", noneWithoutSecure))
	}
	return findings
}

func framePolicyDeclared(headers http.Header) bool {
	xfo := strings.TrimSpace(headers.Get("X-Frame-Options"))
	if strings.EqualFold(xfo, "DENY") || strings.EqualFold(xfo, "SAMEORIGIN") {
		return true
	}
	for _, field := range headers.Values("Content-Security-Policy") {
		for policy := range strings.SplitSeq(field, ",") {
			for directive := range strings.SplitSeq(policy, ";") {
				name, values, _ := strings.Cut(strings.TrimSpace(strings.ReplaceAll(directive, "\t", " ")), " ")
				if strings.EqualFold(name, "frame-ancestors") {
					if strings.TrimSpace(values) != "" {
						return true
					}
					break
				}
			}
		}
	}
	return false
}

func referrerPolicy(values []string) string {
	policy := ""
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			token = strings.TrimSpace(token)
			switch token {
			case "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin",
				"strict-origin", "strict-origin-when-cross-origin", "unsafe-url":
				policy = token
			}
		}
	}
	return policy
}

func hstsMaxAge(header string) (active, valid bool) {
	for directive := range strings.SplitSeq(header, ";") {
		name, value, found := strings.Cut(directive, "=")
		if !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		if valid || !found {
			return false, false
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if value == "" || strings.ContainsFunc(value, func(r rune) bool { return r < '0' || r > '9' }) {
			return false, false
		}
		valid, active = true, strings.TrimLeft(value, "0") != ""
	}
	return active, valid
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func reviewCookies(values []string, observed time.Time) (withoutSecure, noneWithoutSecure, total int) {
	for _, value := range values {
		if len(value) > 4096 {
			continue
		}
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.MaxAge < 0 || (cookie.MaxAge == 0 && !observed.IsZero() &&
			!cookie.Expires.IsZero() && !cookie.Expires.After(observed)) {
			continue
		}
		total++
		if !cookie.Secure {
			withoutSecure++
			if cookie.SameSite == http.SameSiteNoneMode {
				noneWithoutSecure++
			}
		}
	}
	return withoutSecure, noneWithoutSecure, total
}
