"""Fast offline checks for the lab harness, not core migration tests."""
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import fixture
import lab

class LabSafetyTests(unittest.TestCase):
    def test_optimized_python_is_rejected_before_docker_access(self):
        result=subprocess.run([sys.executable,'-O',lab.__file__,'status'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('optimization must be disabled',result.stderr)

    def test_fixture_has_real_mime_attachments_and_repeatable_bytes(self):
        body,flags,_=fixture.generate(2,0)
        message=BytesParser(policy=policy.default).parsebytes(body)
        attachments=list(message.iter_attachments())
        self.assertEqual(len(attachments),3)
        self.assertEqual({a.get_content_type() for a in attachments},{'application/pdf','text/csv','image/png'})
        self.assertTrue(attachments[0].get_payload(decode=True).startswith(b'%PDF-1.4'))
        self.assertIn('日本語',str(message['Subject']))
        self.assertIn('\\Seen',flags)
        self.assertNotIn('\\Seen',fixture.generate(2,1)[1])
        self.assertEqual(body,fixture.generate(2,0)[0])

    def test_only_test_endpoints_credentials_and_state_paths_are_accepted(self):
        with tempfile.TemporaryDirectory() as td, patch.object(fixture,'LAB',Path(td)):
            root=Path(td)
            for role in ['source','destination']:
                (root/f'{role}.password').write_text(fixture.password(role))
            path=root/'migration.toml'
            text=fixture.render_config([(f,f) for f in fixture.FOLDERS])
            path.write_text(text)
            fixture.validate_config(path)
            for wrong in [text.replace('host = "source"','host = "outside-lab.invalid"'),
                          text.replace('state_dir = "./state/migration"','state_dir = "/etc"'),
                          text.replace('security = "tls"','security = "plaintext"')]:
                path.write_text(wrong)
                with self.assertRaises(AssertionError): fixture.validate_config(path)
            path.write_text(text)
            (root/'source.password').write_text('not-a-test-credential')
            with self.assertRaises(AssertionError): fixture.validate_config(path)

    def test_reset_preparation_refuses_symlinks_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); outside=root/'outside'; outside.mkdir()
            sentinel=outside/'sentinel'; sentinel.write_text('keep')
            runtime=root/'runtime'; runtime.symlink_to(outside,target_is_directory=True)
            with patch.object(lab,'RUNTIME',runtime), self.assertRaises(SystemExit): lab.prepare()
            self.assertEqual(list(outside.iterdir()),[sentinel])
            self.assertEqual(sentinel.read_text(),'keep')

    def test_compose_gate_rejects_public_ports_and_external_resources(self):
        def base():
            return {'services':{n:{'networks':{'lab':{}}} for n in ['source','destination','client']},
                    'networks':{'lab':{'internal':True}},'volumes':{'source-mail':{},'destination-mail':{}}}
        good=base()
        with patch.object(lab,'compose',return_value=subprocess.CompletedProcess([],0,json.dumps(good))): lab.isolation_check()
        for field in ['ports','network','volume']:
            bad=base()
            if field=='ports': bad['services']['source']['ports']=[{'published':'993','target':993}]
            if field=='network': bad['networks']['lab']['internal']=False
            if field=='volume': bad['volumes']['source-mail']['external']=True
            with patch.object(lab,'compose',return_value=subprocess.CompletedProcess([],0,json.dumps(bad))), self.assertRaises(AssertionError): lab.isolation_check()

if __name__=='__main__': unittest.main()
