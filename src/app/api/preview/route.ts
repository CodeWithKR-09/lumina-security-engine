import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const rawUrl = req.nextUrl.searchParams.get("url");

    if (!rawUrl) {
      return new NextResponse("Missing 'url' parameter", { status: 400 });
    }

    let targetUrl = rawUrl.trim();
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = `https://${targetUrl}`;
    }

    try {
      new URL(targetUrl);
    } catch {
      return new NextResponse("Invalid URL format", { status: 400 });
    }

    // Convert YouTube watch links to embed links if applicable
    const ytMatch = targetUrl.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/i);
    if (ytMatch) {
      const embedUrl = `https://www.youtube.com/embed/${ytMatch[1]}`;
      return NextResponse.redirect(embedUrl);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
    }).finally(() => clearTimeout(timeoutId));

    if (!response.ok) {
      const errorHtml = `
        <!DOCTYPE html>
        <html>
        <head><style>body{font-family:sans-serif;padding:2rem;text-align:center;background:#09090b;color:#f43f5e;}</style></head>
        <body>
          <h3>Target Webpage Unavailable (HTTP ${response.status})</h3>
          <p style="color:#a1a1aa;font-size:0.875rem;">${response.statusText || 'Unable to load target destination'}</p>
        </body>
        </html>
      `;
      return new NextResponse(errorHtml, {
        status: response.status,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    let html = await response.text();

    // 1. Strip Content-Security-Policy meta tags so styles and assets resolve
    html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '');

    // 2. Strip frame-busting scripts (e.g. if(top != self) top.location = self.location)
    html = html.replace(/\b(?:window\.)?top\.location\b/g, '/* blocked */ window.__sandbox_loc');

    // 3. Inject <base href="..."> into <head> so all relative images, scripts, and CSS load from the target domain
    const baseTag = `<base href="${targetUrl}" target="_blank">`;
    if (/<head[^>]*>/i.test(html)) {
      html = html.replace(/<head[^>]*>/i, `$&${baseTag}`);
    } else {
      html = `${baseTag}${html}`;
    }

    // 4. Return the HTML without X-Frame-Options or frame-ancestors CSP
    return new NextResponse(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Sandbox-Proxied": "true",
      },
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : "Error connecting to target host";
    const errorHtml = `
      <!DOCTYPE html>
      <html>
      <head><style>body{font-family:sans-serif;padding:2rem;text-align:center;background:#09090b;color:#f43f5e;}</style></head>
      <body>
        <h3>Webpage Not Found / Server Unreachable</h3>
        <p style="color:#a1a1aa;font-size:0.875rem;">${msg}</p>
      </body>
      </html>
    `;
    return new NextResponse(errorHtml, {
      status: 502,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
}
