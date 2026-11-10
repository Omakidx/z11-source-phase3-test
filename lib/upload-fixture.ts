import { createHash } from "node:crypto";

import { html } from "./phase17-http";

/**
 * Upload fixture for Z11 Phase 17 functional journeys. Stateless: it stores
 * nothing and needs no session.
 *
 *   GET  /upload       a file input (`#upload-file`), `#upload-submit`, and a
 *                      status line (`#upload-result`) that shows the hash
 *   POST /api/upload   multipart field `file`; answers `{ sha256, bytes }`
 *
 * The file's name and content are never echoed or kept, only its SHA-256.
 */

export const MAX_UPLOAD_BYTES = 64 * 1024;

const PAGE_SCRIPT = `
const form = document.getElementById("upload-form");
const result = document.getElementById("upload-result");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  result.textContent = "";
  try {
    const response = await fetch("/api/upload", { method: "POST", body: new FormData(form) });
    const body = await response.json();
    result.textContent = response.ok ? "Uploaded sha256 " + body.sha256 : "Upload failed";
  } catch {
    result.textContent = "Upload failed";
  }
});`;

function uploadPage() {
  return html(
    `<h1>Upload</h1>` +
      `<form id="upload-form">` +
      `<label for="upload-file">File</label>` +
      `<input id="upload-file" name="file" type="file">` +
      `<button id="upload-submit" type="submit">Upload</button></form>` +
      `<p id="upload-result" role="status"></p>` +
      `<script>${PAGE_SCRIPT}</script>`,
    200,
    "Z11 fixture upload",
  );
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

/** Handles an upload request; returns `undefined` for paths it does not own. */
export async function handleUploadFixtureRequest(
  request: Request,
): Promise<Response | undefined> {
  const path = new URL(request.url).pathname;
  if (path !== "/upload" && path !== "/api/upload") return undefined;
  if (path === "/upload")
    return request.method === "GET"
      ? uploadPage()
      : new Response("Method not allowed", { status: 405 });
  if (request.method !== "POST")
    return new Response("Method not allowed", { status: 405 });
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_UPLOAD_BYTES + 4_096)
    return json({ error: "payload_too_large" }, 413);
  let file: unknown;
  try {
    file = (await request.formData()).get("file");
  } catch {
    return json({ error: "invalid_upload" }, 400);
  }
  if (!(file instanceof File)) return json({ error: "missing_file" }, 400);
  if (file.size > MAX_UPLOAD_BYTES)
    return json({ error: "payload_too_large" }, 413);
  const bytes = Buffer.from(await file.arrayBuffer());
  return json({
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length,
  });
}
