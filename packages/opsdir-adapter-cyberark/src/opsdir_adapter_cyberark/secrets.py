"""CyberArk secrets: cyberark://<app-id>/<safe>/<object> references resolved at run time with the Credential
Provider's command-line SDK, as the application the vault authorizes."""
from opsdir.core.shell import command


def password_command(rest):
    """The shell command printing a cyberark:// password, the application id and the query one argument each
    whatever the reference holds."""
    app_id, safe, obj = rest.split("/", 2)
    return command("clipasswordsdk", "GetPassword", "-p", f"AppDescs.AppID={app_id}", "-p",
                   f"Query=Safe={safe};Object={obj}", "-o", "Password")
