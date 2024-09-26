# Jenkins Service Users Plugin

This Jenkins plugin adds a very simple menu to create service users for use with e.g. the [Authorize Project](https://plugins.jenkins.io/authorize-project/) plugin.

### Usage

Go to Manage Jenkins and then Service Users. You can add/remove service users on that page.

Note: whether these service users can actually be impersonated (e.g. via Authorize Project plugin) depends on the configured security realm. Some security realms do allow impersonating users that are only present in Jenkins' own database, others don't.

### Development

Starting a development Jenkins instance with this plugin: `mvn hpi:run`

Building the plugin: `mvn package`
