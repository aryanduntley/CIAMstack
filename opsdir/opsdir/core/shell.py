"""Shell command lines as the renderers and resolvers write them: built from their words, each word quoted where it
needs to be, so a shell reads the line back as exactly those words whatever characters a word holds (a secret
reference's text, a path, an ARN) and expands nothing in them. Pure."""
import shlex


def command(*words):
    """A shell command line from its words (strings, or numbers written as text): `sh -c` runs the program in the
    first word with each other word as exactly one argument, quotes, `$`, backticks and separators taken literally."""
    return shlex.join(map(str, words))
