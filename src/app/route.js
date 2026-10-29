import { readFile } from "node:fs/promises";
import path from "node:path";

// Generate the existing standalone interface at build time so deployed requests
// do not depend on access to the repository's source files.
export const dynamic = "force-static";

export async function GET() {
  const html = await readFile(path.join(process.cwd(), "index.html"), "utf8");

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
