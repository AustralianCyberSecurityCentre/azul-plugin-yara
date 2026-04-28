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
                                hash="bdb3c93c261f1ac33b5a3f6f61dfd450b4f00a65125fca3720ff06168d425f28",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="96b56d16a97c86b539fa890ad943bc1020df16dac2644dc6296ab2e094794c71",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="7c5f5934f7ba38c37e80ac0605173b896d9f3d7f97945b967d30f06395d6208b",
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
                    "bdb3c93c261f1ac33b5a3f6f61dfd450b4f00a65125fca3720ff06168d425f28": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "96b56d16a97c86b539fa890ad943bc1020df16dac2644dc6296ab2e094794c71": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "7c5f5934f7ba38c37e80ac0605173b896d9f3d7f97945b967d30f06395d6208b": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
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
                                hash="125bb8da4c1b6651bbc35a75b207a48d598b6fe338b6a0026afb1d83e97d0d6d",
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
                    "125bb8da4c1b6651bbc35a75b207a48d598b6fe338b6a0026afb1d83e97d0d6d": b'// plugin: Yara-0, namespace_identifier: exploits.CVE313_unclass.Exploit_CVE_2015_0313\nrule Exploit_CVE_2015_0313 {\n    meta:\n        rule_group = "Exploit"  \n\n        //required\n        classification = "UNCLASSIFIED"\n        description = "Looks for presence of code that could indicate ANGLER EK use of this flash vuln"\n        exploit = "CVE-2015-0313"\n        info = "SWF"\n        organisation = "Defence"\n        poc = "azul@asd.gov.au" \n        rule_version = "1"\n        yara_version = "1.6"\n\n        //optional\n        weight = 51\n\n    strings:\n        $ = "take_over_32("\n        $ = "get_x86_shellcode("\n        $ = "exploit_primordial_start("\n        $ = "exploit_primarodial_finish("\n        $ = "this.shellcodes.GetX86Shellcode("\n        $ = "Shellcodes("\n        $ = "attacking_buffer"\n        $ = "take_over_buffer"\n        $ = "make_spray_by_buffers_no_holes"\n        $ = "fake_object_address"\n    condition:\n\tany of them\n}\n'
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
                                hash="125bb8da4c1b6651bbc35a75b207a48d598b6fe338b6a0026afb1d83e97d0d6d",
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
                    "125bb8da4c1b6651bbc35a75b207a48d598b6fe338b6a0026afb1d83e97d0d6d": b'// plugin: Yara-0, namespace_identifier: exploits.CVE313_unclass.Exploit_CVE_2015_0313\nrule Exploit_CVE_2015_0313 {\n    meta:\n        rule_group = "Exploit"  \n\n        //required\n        classification = "UNCLASSIFIED"\n        description = "Looks for presence of code that could indicate ANGLER EK use of this flash vuln"\n        exploit = "CVE-2015-0313"\n        info = "SWF"\n        organisation = "Defence"\n        poc = "azul@asd.gov.au" \n        rule_version = "1"\n        yara_version = "1.6"\n\n        //optional\n        weight = 51\n\n    strings:\n        $ = "take_over_32("\n        $ = "get_x86_shellcode("\n        $ = "exploit_primordial_start("\n        $ = "exploit_primarodial_finish("\n        $ = "this.shellcodes.GetX86Shellcode("\n        $ = "Shellcodes("\n        $ = "attacking_buffer"\n        $ = "take_over_buffer"\n        $ = "make_spray_by_buffers_no_holes"\n        $ = "fake_object_address"\n    condition:\n\tany of them\n}\n'
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

    def template_importing_rules_directory(self, regex: str | list[str], is_expected_result_alt: bool = False):
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
                            hash="2a171168ba538346aedca03c7871a195358d5d043eac7f6bfbab5bc520243c44",
                            label="yara_rule_hit",
                        ),
                        EventData(
                            hash="47b07e41347363068c32451d938af21f1dd4ac2113ba5e1d8b97eba81c488be9",
                            label="yara_rule_hit",
                        ),
                        EventData(
                            hash="493580d9da173345d8a93d1780eb463a1315c57fe4d642e72e5576c460a2d7d0",
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
                "2a171168ba538346aedca03c7871a195358d5d043eac7f6bfbab5bc520243c44": b'// plugin: Yara-0, namespace_identifier: exploits.includes.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                "47b07e41347363068c32451d938af21f1dd4ac2113ba5e1d8b97eba81c488be9": b'// plugin: Yara-0, namespace_identifier: exploits.includes.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                "493580d9da173345d8a93d1780eb463a1315c57fe4d642e72e5576c460a2d7d0": b'// plugin: Yara-0, namespace_identifier: exploits.includes.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
            },
        )
        if is_expected_result_alt:
            expected_result = JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="78f18b9256b3dc9f268fce4b4d20f32329687da45b60fc96ac685ccb221b22aa",
                        data=[
                            EventData(
                                hash="bdb3c93c261f1ac33b5a3f6f61dfd450b4f00a65125fca3720ff06168d425f28",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="96b56d16a97c86b539fa890ad943bc1020df16dac2644dc6296ab2e094794c71",
                                label="yara_rule_hit",
                            ),
                            EventData(
                                hash="7c5f5934f7ba38c37e80ac0605173b896d9f3d7f97945b967d30f06395d6208b",
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
                    "bdb3c93c261f1ac33b5a3f6f61dfd450b4f00a65125fca3720ff06168d425f28": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_filename\nrule test_filename\n{\ncondition:\n    filename startswith "test.exe"\n}\n',
                    "96b56d16a97c86b539fa890ad943bc1020df16dac2644dc6296ab2e094794c71": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_filepath\nrule test_filepath\n{\ncondition:\n    filepath startswith "/blah/"\n}\n',
                    "7c5f5934f7ba38c37e80ac0605173b896d9f3d7f97945b967d30f06395d6208b": b'// plugin: Yara-0, namespace_identifier: exploits.check_filename.test_extension\nrule test_extension\n{\ncondition:\n    extension startswith "exe"\n}\n',
                },
            )
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
        self.template_importing_rules_directory(["include.*", "check.*"], is_expected_result_alt=True)

    def test_import_rules_string_regex(self):
        """Test string regex."""
        self.template_importing_rules_directory("include.*")

    def test_import_rules_regex_wide(self):
        """Test too wide regex."""
        self.template_importing_rules_directory([".*"], is_expected_result_alt=True)

    def test_import_rules_no_regex(self):
        """Test too wide regex."""
        self.template_importing_rules_directory([], is_expected_result_alt=True)
