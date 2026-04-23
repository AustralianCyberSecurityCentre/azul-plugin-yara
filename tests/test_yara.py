import os

from azul_runner import FV, APIFeatureValue, Event, JobResult, State, test_template
from azul_runner.models import EventData

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
                        sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        data=[
                            EventData(
                                hash="24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36",
                                label="yara_rule_hit",
                            ),
                        ],
                        features={
                            "yararule": [
                                FV("exploits.check_filename.test_extension"),
                                FV("exploits.check_filename.test_filename"),
                                FV("exploits.check_filename.test_filepath"),
                            ]
                        },
                    )
                ],
                data={
                    "24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                },
            ),
            inspect_data=True,
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
                        sha256="b3c96d09b681a18b41b9eb99c8ccfc97acc432a2721f6dd9676183658a59f375",
                        data=[
                            EventData(
                                hash="9803d73413f689a9cacb55928dcce07e09b770b5e188447fe8e67f1d5bc86fa0",
                                label="yara_rule_hit",
                            )
                        ],
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
                                    "ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go",
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
                data={
                    "9803d73413f689a9cacb55928dcce07e09b770b5e188447fe8e67f1d5bc86fa0": b'// plugin: Yara-00, namespace_identifier: exploits.CVE313_unclass.Exploit_CVE_2015_0313\nrule Exploit_CVE_2015_0313 {\n    meta:\n        rule_group = "Exploit"  \n\n        //required\n        classification = "UNCLASSIFIED"\n        description = "Looks for presence of code that could indicate ANGLER EK use of this flash vuln"\n        exploit = "CVE-2015-0313"\n        info = "SWF"\n        organisation = "Defence"\n        poc = "azul@asd.gov.au" \n        rule_version = "1"\n        yara_version = "1.6"\n\n        //optional\n        weight = 51\n\n    strings:\n        $ = "take_over_32("\n        $ = "get_x86_shellcode("\n        $ = "exploit_primordial_start("\n        $ = "exploit_primarodial_finish("\n        $ = "this.shellcodes.GetX86Shellcode("\n        $ = "Shellcodes("\n        $ = "attacking_buffer"\n        $ = "take_over_buffer"\n        $ = "make_spray_by_buffers_no_holes"\n        $ = "fake_object_address"\n    condition:\n\tany of them\n}\n'
                },
            ),
            inspect_data=True,
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
                        sha256="b3c96d09b681a18b41b9eb99c8ccfc97acc432a2721f6dd9676183658a59f375",
                        data=[
                            EventData(
                                hash="9803d73413f689a9cacb55928dcce07e09b770b5e188447fe8e67f1d5bc86fa0",
                                label="yara_rule_hit",
                            )
                        ],
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
                                    "ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go",
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
                data={
                    "9803d73413f689a9cacb55928dcce07e09b770b5e188447fe8e67f1d5bc86fa0": b'// plugin: Yara-00, namespace_identifier: exploits.CVE313_unclass.Exploit_CVE_2015_0313\nrule Exploit_CVE_2015_0313 {\n    meta:\n        rule_group = "Exploit"  \n\n        //required\n        classification = "UNCLASSIFIED"\n        description = "Looks for presence of code that could indicate ANGLER EK use of this flash vuln"\n        exploit = "CVE-2015-0313"\n        info = "SWF"\n        organisation = "Defence"\n        poc = "azul@asd.gov.au" \n        rule_version = "1"\n        yara_version = "1.6"\n\n        //optional\n        weight = 51\n\n    strings:\n        $ = "take_over_32("\n        $ = "get_x86_shellcode("\n        $ = "exploit_primordial_start("\n        $ = "exploit_primarodial_finish("\n        $ = "this.shellcodes.GetX86Shellcode("\n        $ = "Shellcodes("\n        $ = "attacking_buffer"\n        $ = "take_over_buffer"\n        $ = "make_spray_by_buffers_no_holes"\n        $ = "fake_object_address"\n    condition:\n\tany of them\n}\n'
                },
            ),
            inspect_data=True,
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

    def template_importing_rules_directory(
        self, regex: str | list[str], expected_result_override: JobResult | None = None
    ):
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
        expected_result = JobResult(
            state=State(State.Label.COMPLETED),
            events=[
                Event(
                    sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                    data=[
                        EventData(
                            hash="f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417",
                            label="yara_rule_hit",
                        ),
                        EventData(
                            hash="b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88",
                            label="yara_rule_hit",
                        ),
                        EventData(
                            hash="6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186",
                            label="yara_rule_hit",
                        ),
                    ],
                    features={
                        "yararule": [
                            FV("exploits.includes.test_extension"),
                            FV("exploits.includes.test_filename"),
                            FV("exploits.includes.test_filepath"),
                        ]
                    },
                )
            ],
            data={
                "f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                "b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                "6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
            },
        )

        if expected_result_override:
            expected_result = expected_result_override

        self.assertJobResult(
            result,
            expected_result,
            inspect_data=True,
        )

    def test_import_rules_list_regex(self):
        """Test list of regex."""
        self.template_importing_rules_directory(["include.*"])

    def test_import_rules_multi_list_regex(self):
        """Test list of regex."""
        self.template_importing_rules_directory(
            ["include.*", "check.*"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        data=[
                            EventData(
                                hash="24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186",
                                label="yara_rule_hit",
                            ),
                        ],
                        features={
                            "yararule": [
                                FV("exploits.check_filename.test_extension"),
                                FV("exploits.check_filename.test_filename"),
                                FV("exploits.check_filename.test_filepath"),
                                FV("exploits.includes.test_extension"),
                                FV("exploits.includes.test_filename"),
                                FV("exploits.includes.test_filepath"),
                            ]
                        },
                    )
                ],
                data={
                    "24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                    "f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                },
            ),
        )

    def test_import_rules_string_regex(self):
        """Test string regex."""
        self.template_importing_rules_directory("include.*")

    def test_import_rules_regex_wide(self):
        """Test too wide regex."""
        self.template_importing_rules_directory(
            [".*"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        data=[
                            EventData(
                                hash="24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186",
                                label="yara_rule_hit",
                            ),
                        ],
                        features={
                            "yararule": [
                                FV("exploits.check_filename.test_extension"),
                                FV("exploits.check_filename.test_filename"),
                                FV("exploits.check_filename.test_filepath"),
                                FV("exploits.includes.test_extension"),
                                FV("exploits.includes.test_filename"),
                                FV("exploits.includes.test_filepath"),
                            ]
                        },
                    )
                ],
                data={
                    "24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                    "f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                },
            ),
        )

    def test_import_rules_no_regex(self):
        """Test too wide regex."""
        self.template_importing_rules_directory(
            [],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        data=[
                            EventData(
                                hash="24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186",
                                label="yara_rule_hit",
                            ),
                        ],
                        features={
                            "yararule": [
                                FV("exploits.check_filename.test_extension"),
                                FV("exploits.check_filename.test_filename"),
                                FV("exploits.check_filename.test_filepath"),
                                FV("exploits.includes.test_extension"),
                                FV("exploits.includes.test_filename"),
                                FV("exploits.includes.test_filepath"),
                            ]
                        },
                    )
                ],
                data={
                    "24ee3c6317bd15c42b504fbbd2c3109b2c8e1e1839e0b3ff2c53b9d5c54d0a4c": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "8d7b5d6962a4757d515e9902fca4e91b56b7b80290f577b2696a33985ec7efdb": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6e1cdbbabaeff13954b87e30065bcc3da12f4ab7b38a798539e1c6d5466e3a36": b'// plugin: Yara-00, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                    "f37fadf6057d817256344225d2744dc8487616f6761e839e0ecd4bb16d5c5417": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "b98528ea5fbf29f9cb784a02a900f2c00ad0353f6ab5f95b993dcb4f762b6e88": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "6391287b9565b6fdfcbd160508070912bf1f3064d286e4f95a1cf3ed7881a186": b'// plugin: Yara-00, namespace_identifier: exploits.includes.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                },
            ),
        )
