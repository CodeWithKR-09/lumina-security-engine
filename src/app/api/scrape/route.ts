import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  let targetUrl = "";

  try {
    const rawUrl = req.nextUrl.searchParams.get("url");

    if (!rawUrl) {
      return NextResponse.json(
        { available: false, error: "Missing 'url' parameter" },
        { status: 400 }
      );
    }

    targetUrl = rawUrl.trim();
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = `https://${targetUrl}`;
    }

    try {
      new URL(targetUrl);
    } catch {
      return NextResponse.json(
        { available: false, isNotFound: true, reason: "Invalid URL syntax", error: "Invalid URL format", targetUrl },
        { status: 400 }
      );
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    let response: Response;
    try {
      response = await fetch(targetUrl, {
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Sec-Fetch-Dest": "document",
          "Sec-Fetch-Mode": "navigate",
          "Sec-Fetch-Site": "none",
          "Sec-Fetch-User": "?1",
        },
      });
    } finally {
      clearTimeout(timeoutId);
    }

    // Handle 404 or other non-200 responses
    if (!response.ok) {
      const is404 = response.status === 404;
      const is410 = response.status === 410;
      const isNotFound = is404 || is410;
      const reason = is404
        ? "Target webpage returned HTTP 404 Not Found"
        : is410
        ? "Target webpage has been removed (HTTP 410 Gone)"
        : `Target server responded with HTTP ${response.status} ${response.statusText}`;

      return NextResponse.json(
        {
          available: false,
          isNotFound,
          statusCode: response.status,
          reason,
          error: reason,
          targetUrl,
        },
        { status: response.status }
      );
    }

    const html = await response.text();

    return new NextResponse(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache",
        "X-Target-Available": "true",
        "X-Resolved-Url": response.url || targetUrl,
      },
    });
  } catch (error: unknown) {
    let reason = "Target server unreachable";
    let isNotFound = false;

    if (error instanceof Error) {
      const cause = (error as unknown as { cause?: { code?: string } }).cause;
      const code = cause?.code || "";

      if (code === "ENOTFOUND" || code === "EAI_AGAIN" || error.message.includes("ENOTFOUND") || error.message.includes("fetch failed")) {
        reason = "Domain does not exist or DNS lookup failed (Webpage not found)";
        isNotFound = true;
      } else if (code === "ECONNREFUSED" || error.message.includes("ECONNREFUSED")) {
        reason = "Target server connection was refused (Host offline)";
        isNotFound = true;
      } else if (error.name === "AbortError") {
        reason = "Connection timed out connecting to target host";
      } else {
        reason = error.message || "Failed to reach target server";
      }
    }

    return NextResponse.json(
      {
        available: false,
        isNotFound,
        statusCode: 0,
        reason,
        error: reason,
        targetUrl,
      },
      { status: 502 }
    );
  }
}
