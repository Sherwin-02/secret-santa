# Secret Santa

A Secret Santa website with an organiser panel, family exclusions, private PIN-locked reveals and anonymous chat between each Santa and their match.

- **Players** open the site, type their name, add their email and mobile, and choose a 4-digit PIN. Then they tap to reveal who they're buying for.
- **Anonymous chat:** each person can message their match as "Your Secret Santa" and reply to their own Santa without knowing who that is.
- **Organiser** (`/#admin`): set the budget, exchange date and notes, add people grouped by family, and draw names. You can see who has joined and who has opened their match, but **never who got whom**. The draw runs on the server.

Live site: https://sherwin-02.github.io/secret-santa/
Organiser panel: https://sherwin-02.github.io/secret-santa/#admin

## Status
The database is set up (Supabase project `secret-santa`, Sydney) and connected in `index.html`. All that's left is turning on GitHub Pages and setting the admin password (steps 3–4 below).

## One-time setup (about 10 minutes)

### 1. Create the free database
1. Go to https://supabase.com, sign up, and create a **New project**. Any name works. Pick the Sydney region and save the database password somewhere.
2. When it's ready, open **SQL Editor → New query**.
3. Paste in the whole of [`supabase.sql`](supabase.sql) and press **Run**. You should see "Success".

### 2. Connect the website to the database
1. In Supabase, open **Project Settings → API** (or **API Keys**).
2. Copy the **Project URL** and the **anon public** key (or the **publishable** key).
3. In this repo, edit `index.html` and fill in the two lines near the top:
   ```js
   const SUPABASE_URL = 'https://xxxx.supabase.co';
   const SUPABASE_KEY = 'eyJ...';   // anon / publishable key
   ```
   This key is meant to be public. The database only allows the Secret Santa functions, and each one checks a PIN or the admin password.

### 3. Turn on GitHub Pages
Repo **Settings → Pages → Deploy from a branch → main → /(root) → Save**.

### 4. Set up the organiser panel
Open `…/secret-santa/#admin` straight away and create the admin password. The first person to open this page sets the password, so do it before you share the link.

## Running the event
1. In `#admin`: fill in the event details, add each family with its members, and tap **Save participant list**.
2. Tap **Draw names**.
3. Copy the invite from the admin panel and send it to everyone.
4. Each person joins, reveals their match and can chat anonymously.

**If someone forgets their PIN, or someone else joined with their name:** tap **Reset sign-up** next to them in the admin panel. They can then join again, and their match stays the same.

**To change the list after the draw:** tap **Undo the draw**. This deletes all matches and messages. Then edit the list and draw again.

## Security notes
- PINs and the admin password are stored hashed. A PIN locks for 15 minutes after 5 wrong tries, and the admin login locks for 10 minutes after 8 wrong tries.
- The draw happens inside the database. The admin panel and the API never return pairs.
- Anyone with access to the Supabase dashboard can look in the raw tables, so keep that account to yourself.
