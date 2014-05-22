# Bouncer
## A Revel framework module for authentication

### Configuring

After adding this module to your Revel webapp, you will need to add the following entries to your app.config. Of course, you can control the configurations by adding the appropriate settings in [dev] vs [prod] sections. For example, you can use a test Facebook app for [dev] and have production settings for your live systems.

**auth.providersallowed**

Add the allowed Providers your app can use by listing them in a comma-separated string. Currently supported are:
- Facebook
- Google
- LinkedIn
- Twitter

**auth._provider_.authconfig**

For each provider allowed, you must configure an AuthConfig set. This is done by providing to Bouncer the necessary data in a JSON string. Replace _provider_ with one of the Providers supported.

- Facebook:
auth.facebook.authconfig = { "CallbackUrl": "[your callback URL]", "ConsumerKey": "[your client id]", "ConsumerSecret": "[your client secret]", "RequestTokenUrl": "[]", "AuthorizeUrl": "https://www.facebook.com/dialog/oauth", "AccessTokenUrl": "https://graph.facebook.com/oauth/access_token", "Permissions": "email public_profile"}


Please note the following observations on settings:
- Some providers have case-sensitive URLs. So, for example, "https://www.linkedin.com/uas/oauth2/accessToken" is not equivalent to "https://www.linkedin.com/uas/oauth2/accesstoken"; the latter one will 404 (at the time of writing).

### Troubleshooting
