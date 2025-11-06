import os

from azul_runner import FV, APIFeatureValue, Event, JobResult, State, test_template

from azul_plugin_yara.main import AzulPluginYara

rel_rules_dir = "./rules"
rel_import_rules_dir = "./rules_with_imports"


class TestYara(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginYara
    PLUGIN_TO_TEST_CONFIG = {
        "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
        "version_suffix": "0",
        "name_suffix": "0",
        "security_override": "OFFICIAL",
    }

    def setUp(self) -> None:
        """Setup tests and allow overriding rules directory."""
        return super().setUp()

    def test_incoming_features(self):
        # expect no hits
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            feats_in=[APIFeatureValue(name="unrelated", type="filepath", value="/blah/test.exe")],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

        # Expect no hits
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            feats_in=[APIFeatureValue(name="filename", type="filepath", value="stroganoff.txt")],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

        # Expect many hits
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            feats_in=[APIFeatureValue(name="filename", type="filepath", value="/blah/test.exe")],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        features={
                            "yararule": [
                                FV("exploits.check_filename.test_extension"),
                                FV("exploits.check_filename.test_filename"),
                                FV("exploits.check_filename.test_filepath"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_yara(self):
        self.assertRaisesRegex(
            Exception,
            "Plugin requires 'yara_rules_path', 'name_suffix' and 'version_suffix' config to be set",
            self.do_execution,
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            config={},
        )
        self.assertRaisesRegex(
            Exception,
            "No yara rules found in ./data path",
            self.do_execution,
            config={
                "yara_rules_path": "./data",
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
        )
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )
        # check cached rules
        p = self.PLUGIN_TO_TEST(
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            }
        )
        self.assertIsNotNone(p._cached_rules)

        # Expect no hits; the test rules don't match on mirage
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def test_yara_match_result(self):
        result = self.do_execution(
            # This content should hit on the CVE-2015-0313 Angler EK rule in rules
            data_in=[("content", b'example -> "exploit_primarodial_finish(" <-')],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b3c96d09b681a18b41b9eb99c8ccfc97acc432a2721f6dd9676183658a59f375",
                        features={
                            "yararule": [FV("exploits.CVE313_unclass.Exploit_CVE_2015_0313")],
                            "yararule_description": [
                                FV(
                                    "Looks for presence of code that could indicate ANGLER EK use of this flash vuln",
                                    label="exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                )
                            ],
                            "yararule_exploit": [FV("CVE-2015-0313")],
                            "yararule_match": [
                                FV(
                                    b"exploit_primarodial_finish(",
                                    label="exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                    offset=12,
                                    size=27,
                                )
                            ],
                        },
                        info={
                            "matches_key": ["rule", "offset", "var", "value"],
                            "matches": [
                                [
                                    "exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                    12,
                                    "$",
                                    "ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go",
                                ]
                            ],
                        },
                    )
                ],
            ),
        )

    def test_yara_match_result_disk(self):
        """Test yara works when reading files from disk."""
        result = self.do_execution(
            # This content should hit on the CVE-2015-0313 Angler EK rule in rules
            data_in=[("content", b'example -> "exploit_primarodial_finish(" <-')],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "security_override": "OFFICIAL",
                "size_before_disk": 1,
            },
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b3c96d09b681a18b41b9eb99c8ccfc97acc432a2721f6dd9676183658a59f375",
                        features={
                            "yararule": [FV("exploits.CVE313_unclass.Exploit_CVE_2015_0313")],
                            "yararule_description": [
                                FV(
                                    "Looks for presence of code that could indicate ANGLER EK use of this flash vuln",
                                    label="exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                )
                            ],
                            "yararule_exploit": [FV("CVE-2015-0313")],
                            "yararule_match": [
                                FV(
                                    b"exploit_primarodial_finish(",
                                    label="exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                    offset=12,
                                    size=27,
                                )
                            ],
                        },
                        info={
                            "matches_key": ["rule", "offset", "var", "value"],
                            "matches": [
                                [
                                    "exploits.CVE313_unclass.Exploit_CVE_2015_0313",
                                    12,
                                    "$",
                                    "ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go",
                                ]
                            ],
                        },
                    )
                ],
            ),
        )

    def test_yara_blacklist(self):
        """Blacklist should filter the only rule."""
        path = os.path.join(os.path.dirname(__file__), rel_rules_dir)
        self.assertRaisesRegex(
            Exception,
            "No yara rules found in %s path" % path,
            self.do_execution,
            config={
                "yara_rules_path": path,
                "version_suffix": "0",
                "name_suffix": "0",
                "yara_namespace_blacklist": "exploits",
                "security_override": "OFFICIAL",
            },
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
        )

    def test_yara_blacklist_unmatched(self):
        """Blacklist doesn't match the rule."""
        result = self.do_execution(
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_rules_dir),
                "version_suffix": "0",
                "name_suffix": "0",
                "yara_namespace_blacklist": "exploits.wont_match",
                "security_override": "OFFICIAL",
            },
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def template_importing_rules_directory(self, regex: str | list[str], extra_matches=[]):
        """Test the case where rules are all imported from a single file."""
        # Expect many hits
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        "Malicious Windows 32EXE, malware family mint.",
                    ),
                )
            ],
            feats_in=[APIFeatureValue(name="filename", type="filepath", value="/blah/test.exe")],
            config={
                "yara_rules_path": os.path.join(os.path.dirname(__file__), rel_import_rules_dir),
                "version_suffix": "0",
                "yara_only_load_files_named": regex,
                "name_suffix": "0",
                "security_override": "OFFICIAL",
            },
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        features={
                            "yararule": [
                                FV("exploits.includes.test_extension"),
                                FV("exploits.includes.test_filename"),
                                FV("exploits.includes.test_filepath"),
                            ]
                            + extra_matches,
                        },
                    )
                ],
            ),
        )

    def test_import_rules_list_regex(self):
        """Test list of regex."""
        self.template_importing_rules_directory(["include.*"])

    def test_import_rules_multi_list_regex(self):
        """Test list of regex."""
        self.template_importing_rules_directory(
            ["include.*", "check.*"],
            [
                FV("exploits.check_filename.test_extension"),
                FV("exploits.check_filename.test_filename"),
                FV("exploits.check_filename.test_filepath"),
            ],
        )

    def test_import_rules_string_regex(self):
        """Test string regex."""
        self.template_importing_rules_directory("include.*")

    def test_import_rules_regex_wide(self):
        """Test too wide regex."""
        self.template_importing_rules_directory(
            [".*"],
            [
                FV("exploits.check_filename.test_extension"),
                FV("exploits.check_filename.test_filename"),
                FV("exploits.check_filename.test_filepath"),
            ],
        )

    def test_import_rules_no_regex(self):
        """Test too wide regex."""
        self.template_importing_rules_directory(
            [],
            [
                FV("exploits.check_filename.test_extension"),
                FV("exploits.check_filename.test_filename"),
                FV("exploits.check_filename.test_filepath"),
            ],
        )
