/* Hekate web vault entry.
 *
 * Mode dispatch: the SPA is mounted at two URL prefixes by the server,
 * so we pick the route shell from `location.pathname`:
 *
 *   /send/#/<id>/<key>  → recipient mode (anonymous Send decryption)
 *   /web/#/...          → owner mode    (login → vault, sends, orgs, …)
 *
 * Owner-mode internal navigation uses hash routing (no history fallback
 * needed on the static-asset host). Recipient mode is a single screen;
 * the URL fragment is data, not a route.
 */
import { render } from "solid-js/web";
import { Recipient } from "./routes/recipient/Recipient";
import { Owner } from "./routes/owner/Owner";

const root = document.getElementById("app");
if (!root) {
  throw new Error("#app not found");
}
// Solid's `render` mounts alongside existing children rather than
// replacing them. Clear the SSR/no-JS "Loading…" placeholder so it
// doesn't linger as a flex sibling once the SPA tree mounts.
root.replaceChildren();

const path = window.location.pathname;
if (path.startsWith("/send")) {
  render(() => <Recipient />, root);
} else {
  // Owner mode is the default landing — works whether the SPA is
  // hosted at /web/ in production or at / under `vite dev`.
  render(() => <Owner />, root);
}
