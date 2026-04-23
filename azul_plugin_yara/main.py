"""Uses yara-x and a configurable ruleset to publish signature hits as AZUL features."""

import base64
import io
import logging
import os
import re
from hashlib import md5
from pathlib import Path
from typing import Any, Optional

import yara_x
from azul_runner import (
    FV,
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
    settings,
)

YARA_EXTENSIONS = [".yar", ".yara"]


class AzulPluginYara(BinaryPlugin):
    """Uses yara-x and a configurable ruleset to publish signature hits as AZUL features."""

    VERSION = "2026.04.24"
    CONTACT = "ASD's ACSC"
    SETTINGS = add_settings(
        filter_max_content_size="0",  # operate on any sized file
        filter_data_types={"content": []},  # scan all content
        yara_rules_path=(str | None, None),
        yara_namespace_blacklist=(list[str] | str, []),
        # Only load files that match any of the provided regex. (regex is just on the file name and not the extension.)
        # Still will only load .yar or .yara files.
        yara_only_load_files_named=(list[str] | str, []),
        size_before_disk=(int, 2**24),
        # Max number of yara includes to follow before giving up on looking for rules.
        max_yara_include_depth=(int, 5),
    )

    FEATURES = [
        Feature("yararule", "Rule the string matched on from YARA", type=FeatureType.String),
        Feature(
            "yararule_match",
            "Binary string signature match extracted by the labelling yara rule",
            type=FeatureType.Binary,
        ),
        Feature(
            "yararule_match_name",
            "Variable name of matched string in the labelling yara rule",
            type=FeatureType.String,
        ),
        Feature(
            "yararule_description",
            "Description of the yara rule that hit",
            type=FeatureType.String,
        ),
        Feature("yararule_tag", "Tag associated to this rule", type=FeatureType.String),
        # optional metadata fields included in some rulesets
        Feature(
            "yararule_attribution",
            "Yara rule metadata attribution tags",
            type=FeatureType.String,
        ),
        Feature(
            "yararule_implant",
            "Yara rule metadata implant references",
            type=FeatureType.String,
        ),
        Feature(
            "yararule_exploit",
            "Yara rule metadata tagged exploits",
            type=FeatureType.String,
        ),
        Feature(
            "yararule_technique",
            "Yara rule metadata technique groupings",
            type=FeatureType.String,
        ),
        Feature(
            "yararule_reference",
            "External reference the yara rule was derived from",
            type=FeatureType.String,
        ),
    ]
    _cached_rules = None

    def __init__(self, config: settings.Settings | dict = None) -> None:
        """Check correct config and load/cache rules."""
        super().__init__(config)
        if not self.cfg.yara_rules_path or not self.cfg.name_suffix or not self.cfg.version_suffix:
            raise Exception("Plugin requires 'yara_rules_path', 'name_suffix' and 'version_suffix' config to be set")

        if not self.cfg.security_override:
            raise Exception("Plugin requires 'security_override' to be defined")

        # handle config override with env string
        blacklist = self.cfg.yara_namespace_blacklist
        if isinstance(blacklist, str):
            blacklist = blacklist.split(",")

        # Handle a list of regex to only load certain file types
        yara_file_to_load_regex = self.cfg.yara_only_load_files_named
        if isinstance(yara_file_to_load_regex, list) and len(yara_file_to_load_regex) > 0:
            yara_file_to_load_regex = [re.compile(expression) for expression in yara_file_to_load_regex]
        elif isinstance(yara_file_to_load_regex, str):
            yara_file_to_load_regex = [re.compile(yara_file_to_load_regex)]
        else:
            yara_file_to_load_regex = None

        self.namespace_to_rule_path: dict[str, str] = list_rules(
            self.cfg.yara_rules_path, blacklist, yara_file_to_load_regex
        )
        if not self.namespace_to_rule_path:
            raise Exception("No yara rules found in %s path" % self.cfg.yara_rules_path)

        self.logger.info(f"Loaded {len(self.namespace_to_rule_path)} files containing yara rules.")
        if len(self.namespace_to_rule_path) < 20:
            for namespace, path in self.namespace_to_rule_path.items():
                self.logger.info(f"Loaded rules from the file namespace: '{namespace}', path: '{path}'")
        # Create a yara_x compiler
        compiler = construct_yara_x_compiler(self.namespace_to_rule_path, self.logger)
        self._cached_rules = compiler.build()

    def execute(self, job: Job):
        """Run the configured rules across the supplied entity's data, returning as features."""
        # Some external rulesets rely on filename being defined or will raise errors
        # note - 'filetype' not implemented
        fname = fpath = ext = ftype = ""
        if job.event.entity.features:
            filenames = [x for x in job.event.entity.features if x.name == "filename"]
            for f in filenames:
                fname = f.value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                if fname and fname != f.value:
                    fpath = f.value[: -len(fname)]
                if "." in fname:
                    ext = fname.rsplit(".", 1)[-1]

        scanner = yara_x.Scanner(self._cached_rules)
        scanner.set_global("filename", fname)
        scanner.set_global("filepath", fpath)
        scanner.set_global("extension", ext)
        scanner.set_global("filetype", ftype)
        # if binary over certain size, write to disk first
        if job.event.entity.size > self.cfg.size_before_disk:
            matches = scanner.scan_file(job.get_data().get_filepath())  # type: yara_x.ScanResults
        else:
            matches = scanner.scan(job.get_data().read())  # type: yara_x.ScanResults
        if not matches:
            return State.Label.COMPLETED

        # Get yararule features.
        names = set()  # Use a set to avoid possible duplicate (rule, var) results if it hits more than once
        match_tuples = []
        seen_rules_md5s = []
        # Read file from disk as multiple seek/read operations will be required
        fpath = job.get_data().get_filepath()
        for match in matches.matching_rules:
            rule = match.namespace + "." + match.identifier
            self.add_feature_values("yararule", rule)

            # Find the raw rule and save it as a file
            rule_file_path = self.namespace_to_rule_path[match.namespace]
            self.yara_include_depth = 0
            raw_rule = self.fetch_original_rule(rule_file_path, match.identifier, self.logger)
            if len(raw_rule) > 0:
                new_rule = md5(raw_rule).hexdigest()  # noqa: S324
                if new_rule not in seen_rules_md5s:
                    seen_rules_md5s.append(new_rule)
                    raw_rule_with_header = (
                        f"// plugin: {self.NAME}{self.cfg.name_suffix}, namespace_identifier: {rule}\n".encode()
                        + raw_rule
                    )
                    self.add_data(label=DataLabel.YARA_RULE_HIT, tags={}, data=raw_rule_with_header)

            for match_data in match.patterns:
                var = match_data.identifier
                for match_instance in match_data.matches:
                    # Read match from the job file as yara_x does not return the match string
                    offset = match_instance.offset
                    length = match_instance.length
                    value = read_bytes(fpath, offset, length)
                    if len(var) > 3:
                        names.add(FV(var, label=rule))
                    match_tuples.append((rule, offset, var, value))

            meta_dict = dict(match.metadata)
            if "attribution" in meta_dict:
                self.add_feature_values(
                    "yararule_attribution", [s.strip() for s in meta_dict["attribution"].split(",") if s.strip()]
                )
            if "implant" in meta_dict:
                self.add_feature_values(
                    "yararule_implant", [s.strip() for s in meta_dict["implant"].split(",") if s.strip()]
                )
            if "technique" in meta_dict:
                self.add_feature_values(
                    "yararule_technique", [a.strip() for a in meta_dict["technique"].split(",") if a.strip()]
                )
            if "exploit" in meta_dict:
                self.add_feature_values(
                    "yararule_exploit", [a.strip() for a in meta_dict["exploit"].split(",") if a.strip()]
                )
            if "reference" in meta_dict:
                self.add_feature_values("yararule_reference", FV(meta_dict["reference"], label=rule))
            if "description" in meta_dict:
                self.add_feature_values("yararule_description", FV(meta_dict["description"], label=rule))

            for tag in match.tags:
                self.add_feature_values("yararule_tag", tag)

        self.add_feature_values("yararule_match_name", names)
        self.add_feature_values(
            "yararule_match",
            [FV(val, label=rule, offset=offset, size=len(val)) for rule, offset, _, val in match_tuples],
        )

        if match_tuples:
            info = {
                "matches_key": ["rule", "offset", "var", "value"],
                "matches": [],
            }
            # Values must be JSONable - encode raw match bytes to base64
            info["matches"] = [[r, o, n, base64.b64encode(v).decode("ascii")] for (r, o, n, v) in match_tuples]
            self.add_info(info)

        # TODO complete with errors if no original rule found
        # return State(State.Label.COMPLETED_WITH_ERRORS, message=e.args[0])

    def _make_path_absolute(self, parent_rule_path: str, path_str: str) -> Path:
        """Create an absolute path from a relative or absolute path from a yara include."""
        path = Path(path_str)
        # Handle absolute path
        if path.is_absolute():
            return path.resolve()

        # Handle relative path
        parent_path = Path(parent_rule_path).parent
        # resolve relative to parent path
        path = (parent_path / path).resolve()
        return path

    def fetch_original_rule(self, rule_path: str, rule_identifier: str, logger: logging.Logger) -> bytes:
        """A basic yara rule parser that can load the original rule from disk."""
        if not os.path.exists(rule_path):
            logger.warning(f"Could not load rule path '{rule_path}' for rule {rule_identifier} and it should exist.")
            return b""

        # Regex rules for finding start and end of yara rule.
        rule_pattern = rb"rule\s" + rule_identifier.encode()
        open_curly_brace_pattern = rb"(?<!\\)(?:\\\\)*\{"
        closed_curly_brace_pattern = rb"(?<!\\)(?:\\\\)*\}"
        regex_open_curly_brace = re.compile(open_curly_brace_pattern)
        regex_closed_curly_brace = re.compile(closed_curly_brace_pattern)
        regex_start_of_rule = re.compile(rule_pattern)

        external_inclusion_path = rb"^\s*include\s*\"(.*)\"\s*$"
        regex_external_inclusion = re.compile(external_inclusion_path)

        included_yara_rule_paths: list[Path] = []
        # output full raw rule.
        output = io.BytesIO()
        start_of_rule = False
        at_least_one_brace_found = False
        with open(rule_path, "rb") as f:
            open_curly_brace = 0
            while line := f.readline():
                if include_match := regex_external_inclusion.search(line):
                    included_yara_rule_paths.append(
                        self._make_path_absolute(rule_path, include_match.group(1).decode())
                    )
                if start_of_rule or regex_start_of_rule.search(line):
                    start_of_rule = True
                    output.write(line)
                    # Count braces
                    open_curly_brace += len(regex_open_curly_brace.findall(line))
                    if open_curly_brace > 0:
                        at_least_one_brace_found = True
                    open_curly_brace -= len(regex_closed_curly_brace.findall(line))
                    if open_curly_brace == 0 and at_least_one_brace_found:
                        break

        # If no rule was found check if the rule is somewhere in the included paths.
        if not start_of_rule:
            # Ensure recursive yara includes don't end in an infinite loop
            self.yara_include_depth += 1
            if self.yara_include_depth >= self.cfg.max_yara_include_depth:
                return b""
            # Search included yara files.
            for included_path in included_yara_rule_paths:
                inner_output = self.fetch_original_rule(str(included_path), rule_identifier, logger)
                if len(inner_output) > 0:
                    return inner_output

            logger.warning(f"Could not find the rule '{rule_identifier}' while searching the file '{rule_path}'")
            return b""

        output.seek(0)
        return output.read()


def construct_yara_x_compiler(list_rules: dict[str, str], logger: logging.Logger) -> yara_x.Compiler:
    """Constructs a yara_x compiler from the provided yara rules dict. Replaces includes for yara_x compatibility.

    Args:
        list_rules (dict[str, str]): Dict containing namespace and rule path
        logger (Loggger): Logger for logging the progress of the compilation of the yara command.

    Returns:
        yara_x.Compiler: yara_x compiler
    """
    compiler = yara_x.Compiler(relaxed_re_syntax=True)
    compiler.define_global("filename", "")
    compiler.define_global("filepath", "")
    compiler.define_global("extension", "")
    compiler.define_global("filetype", "")

    for ns, val in list_rules.items():
        with open(file=val, mode="r") as file:
            compiler.new_namespace(ns)
            # Setup variables for replace_include
            file_dirname = os.path.dirname(val)
            temp_lines: list[str] = []
            f_lines = file.readlines()
            processed_files: set[str] = set()

            for _, f_line in enumerate(f_lines):
                if f_line.startswith("include"):
                    # Check and replace includes
                    lines, processed_files = replace_include(f_line, file_dirname, processed_files, logger)
                    temp_lines.extend(lines)
                else:
                    temp_lines.append(f_line)
            compiler.add_source("\n".join(temp_lines))
    return compiler


def list_rules(
    root: str, blacklist: list[str] | None = None, yara_file_to_load_regex: list[re.Pattern[Any]] | None = None
) -> dict[str, str]:
    """Fetch a dictionary of rule filenames by recursively walking the root.

    :param root: Root of rule directory to scan/load.
    :param blacklist: List of namespaces to filter rules.
    :param yara_file_to_load_regex: Regex expressions file names must match to be loaded.
    :return: dict of namespace->rulepath matches
    """
    if blacklist is None:
        blacklist = []
    rootpath = os.path.abspath(root)
    if not rootpath.endswith(os.path.sep):
        rootpath = rootpath + os.path.sep

    paths: dict[str, str] = {}
    for path, _, names in os.walk(rootpath):
        relative_path = path[len(rootpath) :]
        namespace_base = ".".join(relative_path.split(os.path.sep))

        for filename in names:
            name, ext = os.path.splitext(filename)
            if ext not in YARA_EXTENSIONS:
                continue

            # Only load files that match the provided regex.
            if yara_file_to_load_regex:
                match_found = False
                for expression in yara_file_to_load_regex:
                    if expression.match(filename):
                        match_found = True
                        break
                if not match_found:
                    continue

            namespace = f"{namespace_base}.{name}" if namespace_base else name

            if any(namespace.startswith(x) for x in blacklist):
                print("Ignoring blacklisted namespace %s" % namespace)
                continue
            paths[namespace] = os.path.join(path, filename)
    return paths


def read_bytes(filepath: str, offset: int, length: int) -> Optional[bytes]:
    """Reads a specified number of bytes from a file starting at a given offset.

    Args:
        filepath (str): The path to the file.
        offset (int): The position in the file to start reading from.
        length (int): The number of bytes to read.

    Returns:
        Optional[bytes]: The bytes read from the file, or None if an error occurs.
    """
    try:
        with open(filepath, "rb") as file:
            file.seek(offset)
            data = file.read(length)
            return data
    except Exception as e:
        raise Exception(f"An error occurred while reading bytes {e}") from e


def replace_include(include, dirname, processed_files: set[str], cur_logger: logging.Logger):
    """Processes a yara file containing 'include' statements, replace includes with contents of the file.

    Args:
        include (str): The 'include' statement containing the path to the file to be included.
        dirname (str): The directory name where the current file is located.
        processed_files (set[str]): A set of file paths that have already been processed to avoid redundancy.
        cur_logger (logging.Logger): Logger for info and errors.

    Returns:
        tuple: A tuple containing:
            - list: Lines of the processed file, including any recursively included files.
            - set[str]: Updated set of processed file paths.
    """
    include_path = re.match(r"include [\'\"](.{4,})[\'\"]", include)
    if not include_path:
        return [], processed_files
    include_path = include_path.group(1)
    full_include_path = os.path.normpath(os.path.join(dirname, include_path))
    if not os.path.exists(full_include_path):
        cur_logger.info(f"File doesn't exist: {full_include_path}")
        return [], processed_files

    temp_lines = ["\n"]  # Start with a new line to separate rules
    if full_include_path not in processed_files:
        processed_files.add(full_include_path)
        with open(full_include_path, "r") as include_f:
            lines = include_f.readlines()

        for line in lines:
            if line.startswith("include"):
                new_dirname = os.path.dirname(full_include_path)
                lines, processed_files = replace_include(line, new_dirname, processed_files, cur_logger)
                temp_lines.extend(lines)
            else:
                temp_lines.append(line)

    return temp_lines, processed_files


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginYara)


if __name__ == "__main__":
    main()
