# Discord setup for alarm-monitor

The daemon talks to users over Discord DMs the same way it does over Facebook
Messenger: authorize with the shared secret, subscribe to alerts, and send
Polish natural-language alarm commands.

Discord is accessed with a small Gateway + REST client (httpx + websockets), not
the full discord.py library.

## Developer Portal

1. Create an application at https://discord.com/developers/applications
2. Open the **Bot** tab, create a bot, and copy the token into `DISCORD_TOKEN`
3. Invite the bot to a private server you control (OAuth2 URL Generator → scope
   `bot` → permissions: View Channels + Send Messages is enough)
4. You and the bot must share that server before Discord allows DMs — you can
   ignore the server afterward and only DM the bot

No privileged gateway intents are required. The bot connects with the Direct
Messages intent only; DM content is delivered without Message Content Intent.

## Runtime

Set in the service env file (alongside optional `FACEBOOK_TOKEN`):

```
DISCORD_TOKEN=...
SECRET=...
```

At least one of `FACEBOOK_TOKEN` / `DISCORD_TOKEN` is required. If only one is
set, the other is skipped with a warning and the daemon keeps running.

User ids in `cfg.json` are stored as `discord:<snowflake>` (and `fb:<id>` for
Messenger). Authorize by DMing the bot `zaloguj <SECRET>`, then `informuj` to
subscribe to proactive alerts.

If one platform fails, the other keeps running and the failed one is retried
every 5 minutes. If every configured platform is down, the process exits so
systemd can restart it.
