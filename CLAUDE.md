# Prac360: working notes for Claude

## What this is
Prac360 is a practice management system for **South African private healthcare practices** (GP, dental, allied health, oncology, hospital rounds). It covers the diary, the patient file, consultations (with an AI Scribe and the Prac360 Assist helper), sick notes and referral letters with e-signature, billing and medical aid claims (EDI, eRA), payments and accounts, stock and dispensing, and practice setup with POPIA, security and roles.

Users are practice staff: reception, nurses, doctors, billing clerks, practice managers and owners, plus Prac360 support and admin staff. Many are not technical, so the app must be plain, calm and safe: clear words, few clicks, no surprises. It is a demo with synthetic data only. Never put real patient information in it.

## How it is built
- Almost everything is one file: `index.html` (about 25,000 lines). It has no build step. Features are added as small `(function () { ... })();` modules, each under a `/* ===== name.js ===== */` banner near the end of the file. Look at the latest one (currently `ui-v096.js`) for the pattern.
- `server.js` (Node, no packages) serves the app and keeps the shared data in `data/` (git-ignored). `seed-data.json` is the starting demo data.
- Without the server (GitHub Pages) the app still runs; each browser then keeps its own data.
- Live site: https://michaelduplessis32-app.github.io/prac360-demo (served from `main`).
- Demo logins are in `README.md`. `dr.naidoo@jacaranda.example` is the sample practice owner.

## Standing rules from the owner (follow on every change)
1. **Publish every change.** When the owner asks for a change, finish it to the end: commit and push to `main` so it is live on the GitHub Pages link. Do not leave work on a side branch.
2. **Every change is a new version.** Bump the version by adding a release to `A.RELEASES` in a new module (for example `ui-v093.js`, placed before `req-map.js`). The app version is the highest release number. Add a plain-language entry per change in **What's new** (type new, improved or fixed; area; title; text; link; guide).
3. **Keep the Training Academy and help current.** Update, in the same module: the Training Academy lesson that teaches the topic (`A.COURSES`), a quiz question where it helps, the help article (`KB`), the guided tour (`A.GUIDES`) and the function list (`A.FUNCTIONS`). Fix any older help text that the change makes wrong (search the file for the old wording).
4. **Build for the people who use it.** Plain everyday words, short labels, one obvious next step, no jargon. Keep it consistent with the existing look, in every theme and in dark mode, and usable on a phone. Respect roles and permissions (`A.can`, `ACT_PERMS`). Nothing risky without a confirm. Do not break the audit trail, POPIA consent or the signing rules.
5. **Test before publishing.** Run a syntax check of the inline scripts, start `node server.js` (use `PORT=8766`), sign in with a demo login in a browser (Playwright is installed) and walk through the change. Look at a screenshot.
6. Commit messages end with the attribution lines the session gives.
