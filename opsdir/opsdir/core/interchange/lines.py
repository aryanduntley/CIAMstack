"""Text as physical lines, each with its own line terminator, for the codecs that capture line-based files."""
import re


def physical_lines(text):
    """The text's lines, each keeping its terminator (\\n or \\r\\n; the last may have none): "".join gives the text."""
    return tuple(re.findall(r"[^\n]*\n|[^\n]+", text))


def body_and_end(line):
    """(the line without its terminator, the terminator)."""
    end = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    return line[:len(line) - len(end)], end


def line_col(text, index):
    """1-based (line, column) of a character index in the text."""
    return text.count("\n", 0, index) + 1, index - (text.rfind("\n", 0, index) + 1) + 1


def first_gap(text, spans):
    """Index of the first character no span covers (spans: (start, end) in order), or None when they tile the text."""
    ends = (0, *(end for _, end in spans))
    starts = (*(start for start, _ in spans), len(text))
    return next((end for end, start in zip(ends, starts) if start != end), None)
