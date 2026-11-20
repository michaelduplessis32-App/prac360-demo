# Prac360 server

The Prac360 app plus **one shared copy of its data**, so everyone with the link and a login uses the same system from any browser, phone or network. Logins, practices, users, login requests and patient records are shared, and changes appear on other screens within about a second.

> **Demo / trial use.** Use synthetic or test data only, not real patient information. The production system will add real email delivery, per-record saving and a full POPIA review.

## How it is protected (version 2)
- **Passwords and two-step codes are checked on the server.** A browser only gets data after a successful sign-in.
- **Nobody receives other people's password data.** Password hashes, two-step secrets, recovery codes and reset codes stay on the server.
- **Practice data only goes to people with access to that practice.** For example, a Jacaranda user never receives Smile Dental's patients.
- **Every change is checked.** People who are not signed in can only register a practice or send a login request. Only Prac360 administrators can give Prac360 staff access. Only an account's owner, their practice owner or manager, or Prac360 staff can change its password.
- **Sign-in attempts are limited.** Too many wrong passwords block that email and that internet address for 15 minutes.
- **Signing out removes practice data from that browser.** Sign-in lasts 12 hours at most.
- **HTTPS is used on hosts that provide it** (FORCE_HTTPS=1).
- **The data is backed up every day.** Copies go to `data/backups/`, and the last 14 days are kept.
- **"Forgot password" asks people to contact their practice administrator.** An online demo cannot send real email, so it does not show reset codes on screen.

### Demo accounts are public
The demo logins below use a published password, and two of them are Prac360 super administrators. Anyone who knows them can change anything. For a team trial:
1. Sign in as `admin@prac360.example` and create **personal logins** for your staff (Admin tool → Users, or approve their **Login requests**).
2. Then **change the passwords** of the demo accounts, or set them to inactive, so only your people can get in.

| Who | Email | Password |
|---|---|---|
| Prac360 super administrator (two-step code shown on screen) | admin@prac360.example | Demo-Clinic-2026! |
| Demo tester (sees everything) | demo@prac360.example | Demo-Clinic-2026! |
| Sample practice owner | dr.naidoo@jacaranda.example | Demo-Clinic-2026! |

## Option A: on the internet with Render (recommended)
Render gives you a public **https://** address and keeps the data on a disk. It costs about **US$7 a month** (Starter) plus **US$0.25 a month** for the 1 GB disk. The free plan cannot keep data, so it is not suitable.

1. Go to **https://render.com** and **sign up with GitHub** (the account that owns `prac360-demo`).
2. Click **New → Blueprint**, choose the **prac360-demo** repository, then click **Apply**. The settings come from `render.yaml`: Frankfurt region, Starter plan, 1 GB disk, HTTPS on.
3. Add a payment card when Render asks.
4. Wait until the service shows **Live** (about 2 minutes). Your address is shown at the top, for example `https://prac360.onrender.com`. Send that link to your users.
5. Updates: every time the repository changes, Render redeploys automatically. Your data on the disk is kept.

## Option B: on your own computer or server
1. Install **Node.js 18 or newer** (LTS from https://nodejs.org).
2. Unzip this folder, for example to `C:\Prac360`.
3. Double-click **start.bat** (Windows) or run `./start.sh` (Mac/Linux). The window shows the address, for example `http://192.168.1.20:8360`.
4. **For the office network only:** open that address on the other computers. Allow Node.js (port 8360) through the firewall if Windows asks.
5. **For access from anywhere:** use a free **Cloudflare Tunnel** (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) to give this computer a public https address. Then set `FORCE_HTTPS=1` before starting. The computer must stay on.

## Data and backups
- All data is in **`data/prac360-data.json`** (on Render: on the disk at `/var/data`). Daily copies are in `data/backups/`.
- To start fresh, stop the server, delete `prac360-data.json` and start again. The demo set-up from `seed-data.json` is loaded.
- Settings (environment variables):

  | Variable | What it does |
  |---|---|
  | `PORT` | Port to listen on |
  | `DATA_DIR` | Where the data is kept |
  | `FORCE_HTTPS=1` | Send everyone to https |
  | `SESSION_HOURS` | Maximum sign-in time, default 12 |

## Good to know
- If two people change **the same practice at the same moment**, the last save of that practice wins. Platform records (users, logins, requests) are merged item by item.
- Opening Prac360 from the GitHub Pages link or as a single file works **without** this server. Each browser then keeps its own separate data.

## Try it without the server
The same app runs on its own at https://michaelduplessis32-app.github.io/prac360-demo/ — each browser then keeps its own separate data.
