# Preparing direct backups to Google Drive, Dropbox and OneDrive

> **Not built yet.** `vault-server` cannot back up straight to these services
> today. This page is how to register the app each one requires, so that the
> feature can be built and tried. **You can already back up to all three:** point a
> folder target at the folder their desktop app syncs
> ([user guide, Backups](user-guide.md#9-backups)).

Checked on 2026-11-25. These websites change often: if a button is named
differently, the step is still the same idea. Items marked **unconfirmed** could
not be established from the provider's documentation.

## What the registration is

Each service lets a program into your files only if the program is registered
with them. You register your own, so no one else's account or app stands between
your server and your backups. Each registration gives an **ID** (Google also gives
a **secret**). Nothing here needs payment details, except possibly Microsoft.

In every case the server will ask for the **narrowest access offered**: only files
it created itself, or only its own folder. It can never read your other files.
The backups are sealed with your recovery key before upload, so the service sees
only unreadable files.

**Keep the IDs and the secret private.** Do not put them in the repository, an
issue or a chat. Keep them in your own vault; you will type them into your server.

## Do them in this order

| Service | Effort | Notes |
|---|---|---|
| Dropbox | Low | One ID, no secret. Start here. |
| Google Drive | Medium | ID and secret; the app must be *published* or access ends weekly |
| OneDrive | Higher | Needs a Microsoft Azure account with a subscription |

## Dropbox

1. Sign in at the [Dropbox App Console](https://www.dropbox.com/developers/apps)
   and choose **Create app**.
2. Choose **Scoped access**, then **App folder**. Give it a name such as
   `vault-server-backups-yourname` (names must be unique).
3. On the **Permissions** tab tick `files.metadata.read`, `files.content.write`
   and `files.content.read`, then **Submit**.
4. On the **Settings** tab, under *OAuth 2*, allow **public clients** (this
   turns on PKCE, so no secret is needed). Leave the redirect URIs empty: Dropbox
   then shows a code you copy to your server.
5. Note the **App key**. That is the only value needed. Not the *App secret*.

Leave the app in **Development** status. **Unconfirmed:** how many people may link
an app in that status; it is meant for the case here, where only you do.

## Google Drive

1. Open the [Google Cloud console](https://console.cloud.google.com/), sign in
   and **create a project**, for example `vault-server-backups`.
2. Enable the **Google Drive API** for it (APIs & Services, then Library).
3. Set up the consent screen (**Google Auth Platform**): app name, your email,
   user type **External**. If a **Personal** user type is offered, it is the
   better choice: it is limited to your own account, with no test users or
   verification. It cannot be changed later.
4. With **External**: press **Publish app** so the status is *In production*.
   **This matters:** while the status is *Testing*, access to Drive expires
   **7 days** after you approve it, and backups would stop every week.
5. Under data access add only the scope
   `https://www.googleapis.com/auth/drive.file` (files the app itself creates).
6. Create a client (**Clients**, or *Credentials, Create credentials, OAuth client
   ID*) of type **TVs and Limited Input devices**. The server then shows a short
   code that you enter on another device.
7. Note the **Client ID** and **Client secret**.

**Unconfirmed:** whether Google asks an app that uses only `drive.file` to be
verified. Verification is required for *sensitive* and *restricted* scopes, and
Google's Drive documentation presents `drive.file` as neither. If you are shown
an "unverified app" warning for your own app, you may continue past it.

## OneDrive

Microsoft's instructions require **an Azure account with an active subscription**
and a directory (the *Default Directory* is fine). **Unconfirmed:** whether a
personal Microsoft account can register an app without one. If the portal asks for
payment details you would rather not give, skip OneDrive and use a folder target.

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/) open **App
   registrations**, then **New registration**.
2. Name it, for example `vault-server-backups`. For supported account types
   choose **Personal accounts only** if your OneDrive is a personal one.
3. Open **Authentication** and set **Allow public client flows** to **Yes**.
4. Under **API permissions** add the Microsoft Graph *delegated* permissions
   `Files.ReadWrite.AppFolder` and `offline_access`.
5. Note the **Application (client) ID**. No secret is needed.

**Unconfirmed:** that the app-folder permission behaves the same for every kind of
personal account. It will be tried when the feature is built.

## What happens next

When you have registered one or more, say which. The feature to build is, for each:

```
vault-server backup add dropbox | gdrive | onedrive
```

It will ask for the ID (and Google's secret), show a code and a web address to
approve on your phone or computer, and from then on upload each sealed snapshot,
read it back to check it, and delete old ones by the same rules as folder targets.
The access it receives is stored on the server like its other keys, readable only
by the server's own user. You can withdraw it at any time on the service's
connected-apps page.

## Where this comes from

- [Google: OAuth for TV and limited-input devices](https://developers.google.com/identity/protocols/oauth2/limited-input-device)
- [Google: publishing status and test users](https://support.google.com/cloud/answer/15549945)
- [Dropbox: OAuth guide](https://docs.dropboxapi.com/dropbox-api/docs/oauth)
- [Microsoft: device code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Microsoft: register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
