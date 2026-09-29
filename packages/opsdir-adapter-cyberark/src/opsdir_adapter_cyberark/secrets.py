"""CyberArk secrets: cyberark://<app-id>/<safe>/<object> references resolved at run time with the Credential
Provider's command-line SDK, as the application the vault authorizes."""


def password_command(rest):
    app_id, safe, obj = rest.split("/", 2)
    return (f"clipasswordsdk GetPassword -p AppDescs.AppID='{app_id}' -p Query='Safe={safe};Object={obj}' "
            "-o Password")
