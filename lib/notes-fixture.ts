import { createHmac, randomBytes } from "node:crypto";

import {
  type FixtureEnvironment,
  SESSION_SECONDS,
  account,
  cookieAttributes,
  html,
  readForm,
  redirect,
  safeEqual,
  sessionValid,
} from "./phase17-http";

/**
 * Notes fixture for Z11 Phase 17 functional journeys. A framework-free
 * handler shared by the Next.js routes and the journey runner tests.
 *
 *   GET  /notes       the signed-in session's notes, newest first, with a create
 *                     form and per-note update and delete forms
 *   POST /api/notes   `action` = create | update | delete; redirects to /notes
 *
 * Notes live only in a signed cookie, so they prove create, update and delete
 * within one browser session, not durable server-side cleanup. Both routes need
 * the existing fixture login session; without it they redirect to /login, and
 * without the test account they answer 404. Note text is HTML-escaped.
 */

export const NOTES_COOKIE = "fixture_notes";
export const MAX_NOTES = 10;
export const MAX_NOTE_LENGTH = 100;

type Note = { id: string; text: string };

function notesSignature(payload: string, password: string) {
  return createHmac("sha256", `fixture-notes:${password}`)
    .update(payload)
    .digest("base64url");
}

function readNotes(request: Request, password: string): Note[] {
  const part = request.headers
    .get("cookie")
    ?.split(/;\s*/u)
    .find((item) => item.startsWith(`${NOTES_COOKIE}=`));
  if (!part) return [];
  const [payload, signature] = part.slice(NOTES_COOKIE.length + 1).split(".");
  if (!payload || !signature) return [];
  if (!safeEqual(signature, notesSignature(payload, password))) return [];
  try {
    const parsed: unknown = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    );
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (item): item is Note =>
          !!item &&
          typeof item.id === "string" &&
          typeof item.text === "string",
      )
      .slice(0, MAX_NOTES);
  } catch {
    return [];
  }
}

function writeNotes(notes: Note[], password: string, request: Request) {
  const payload = Buffer.from(JSON.stringify(notes), "utf8").toString(
    "base64url",
  );
  return `${NOTES_COOKIE}=${payload}.${notesSignature(payload, password)}; Max-Age=${SESSION_SECONDS}; ${cookieAttributes(request)}`;
}

export function escapeHtml(text: string) {
  return text
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

function notesPage(notes: Note[]) {
  const items = notes
    .map(
      (note) =>
        `<li class="note" data-note-id="${escapeHtml(note.id)}">` +
        `<span class="note-text">${escapeHtml(note.text)}</span>` +
        `<form method="post" action="/api/notes">` +
        `<input type="hidden" name="action" value="update">` +
        `<input type="hidden" name="id" value="${escapeHtml(note.id)}">` +
        `<input class="note-edit" name="text" type="text" maxlength="${MAX_NOTE_LENGTH}" aria-label="New text">` +
        `<button class="note-update" type="submit">Update</button></form>` +
        `<form method="post" action="/api/notes">` +
        `<input type="hidden" name="action" value="delete">` +
        `<input type="hidden" name="id" value="${escapeHtml(note.id)}">` +
        `<button class="note-delete" type="submit">Delete</button></form></li>`,
    )
    .join("");
  return html(
    `<h1>Notes</h1>` +
      `<form method="post" action="/api/notes">` +
      `<input type="hidden" name="action" value="create">` +
      `<label for="note-text">New note</label>` +
      `<input id="note-text" name="text" type="text" maxlength="${MAX_NOTE_LENGTH}">` +
      `<button id="note-create" type="submit">Create</button></form>` +
      `<ul id="notes">${items}</ul>`,
    200,
    "Z11 fixture notes",
  );
}

/**
 * Handles a notes request; returns `undefined` for paths it does not own so a
 * host can fall through to its other routes.
 */
export async function handleNotesFixtureRequest(
  request: Request,
  environment: FixtureEnvironment,
  nowMs: number = Date.now(),
): Promise<Response | undefined> {
  const url = new URL(request.url);
  if (url.pathname !== "/notes" && url.pathname !== "/api/notes")
    return undefined;
  const found = account(environment);
  if (!found) return new Response("Not found", { status: 404 });
  if (!sessionValid(request, found, nowMs)) return redirect("/login");

  if (url.pathname === "/notes") {
    if (request.method !== "GET")
      return new Response("Method not allowed", { status: 405 });
    return notesPage(readNotes(request, found.password));
  }

  if (request.method !== "POST")
    return new Response("Method not allowed", { status: 405 });
  const form = await readForm(request);
  if (!form) return new Response("Payload too large", { status: 413 });
  const notes = readNotes(request, found.password);
  const text = (form.get("text") ?? "").trim().slice(0, MAX_NOTE_LENGTH);
  const id = form.get("id") ?? "";
  const action = form.get("action");
  let next = notes;
  if (action === "create" && text)
    next = [{ id: randomBytes(6).toString("hex"), text }, ...notes].slice(
      0,
      MAX_NOTES,
    );
  else if (action === "update" && text)
    next = notes.map((note) => (note.id === id ? { ...note, text } : note));
  else if (action === "delete") next = notes.filter((note) => note.id !== id);
  else if (action !== "create" && action !== "update")
    return new Response("Bad request", { status: 400 });
  return redirect("/notes", writeNotes(next, found.password, request));
}
