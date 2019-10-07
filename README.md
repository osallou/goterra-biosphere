# goterra-biosphere

this app manages user and project creation when a user logs with AAI auth on goterra. It creates resources on defined endpoints and update endpoint defaults.

To submit jobs for biosphere:

* User need to be created on endpoint
* NS (project) needs to be created on endpoint if 1 project per ns, else user needs to be member of global/shared project
* User needs to have a keypair with his public key named *biosphere* (can be internal). If run contains input *ssh_pub_key* then key will be injected in VM sh authorized_keys.
* User credentials *should* be saved in *secrets* REST API (/deploy/ns/{id}/endpoint/{endpoint}/secret) or sent with job params in sensitive inputs fields

With biosphere API, creating a user on an endpoint will store his credentials in secrets automatically.
Creating project will also store project default (project id etc..) and create an internal keypair named biosphere (not user ssh pub key).
