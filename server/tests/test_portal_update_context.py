"""Build-context regression; no Docker daemon or installed image mutation."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]

def test_supervisor_copy_is_present_in_selected_build_context():
    spec=importlib.util.spec_from_file_location('portal_update',ROOT/'deploy/prepare-portal-update.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    digest='sha256:'+'a'*64
    builds=[]
    def run(*args):
        if args[:3]==('docker','image','inspect'):return digest
        if args[:2]==('docker','build'):
            context=Path(args[-1]); builds.append(context)
            source=context/'server/upstream/app/endpoint.py'
            assert source.read_bytes()==(ROOT/'server/upstream/app/endpoint.py').read_bytes()
            assert list((context/'server/upstream/app').iterdir())==[source]
            assert not list(context.rglob('.env'))
            Path(args[args.index('--iidfile')+1]).write_text(digest)
        return ''
    with patch.object(module,'run',side_effect=run):
        result=module.prepare('synthetic-base','synthetic-candidate')
    assert builds and result['image']==digest and not result['running_containers_changed']
