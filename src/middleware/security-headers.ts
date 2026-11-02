/**
 * ConFuse Auth Middleware - Security Headers
 *
 * Defence-in-depth on top of helmet(): belt-and-braces headers set on every
 * response so the service stays safe even as routes change shape.
 */

import { type Request, type Response, type NextFunction } from 'express';

export function securityHeadersMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
        // Pin HTTPS for a year: once a browser has seen this service it must
        // never talk to it over plain HTTP again.
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        // Clickjacking: nothing served here is meant to be framed.
        res.setHeader('X-Frame-Options', 'DENY');

        // Legacy XSS auditor hint (modern browsers ignore it; harmless).
        res.setHeader('X-XSS-Protection', '1; mode=block');

        // Stop browsers from reinterpreting payloads as a different, possibly
        // executable content type via MIME sniffing.
        res.setHeader('X-Content-Type-Options', 'nosniff');

        // Leak only the origin on cross-origin navigations.
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Basic CSP: this service serves JSON APIs, so every resource type is
        // restricted to 'self'. 'unsafe-inline' for styles covers inline style
        // attributes; no inline scripts are ever needed.
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'");

        next();
    };
}