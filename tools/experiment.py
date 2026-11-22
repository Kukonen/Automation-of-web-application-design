"""Evaluate the two actual schema proposals against the same acceptance contract."""
from pathlib import Path
import json
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import CMS


def evaluate(name):
    proposal = ROOT / 'harness' / 'experiment' / (name + '.json')
    value = json.loads(proposal.read_text(encoding='utf-8'))
    fields = value.get('fields', {})
    checks = {
        'root_contract': set(value) == {'label', 'fields'},
        'field_names': set(fields) == {'location', 'event_date'},
        'location_type': fields.get('location', {}).get('type') == 'text',
        'location_limit': fields.get('location', {}).get('max_length') == 200,
        'required': all(fields.get(k, {}).get('required') is True for k in ['location', 'event_date']),
        'date_type': fields.get('event_date', {}).get('type') == 'date',
    }
    with tempfile.TemporaryDirectory() as folder:
        target = Path(folder)
        shutil.copytree(ROOT / 'schemas', target / 'schemas')
        shutil.copyfile(proposal, target / 'schemas' / 'notice.json')
        instance = CMS.__new__(CMS)
        try:
            instance.__init__(target)
            accepted, error = True, None
        except (ValueError, KeyError) as failure:
            accepted, error = False, str(failure)
        finally:
            if hasattr(instance, 'conn'):
                instance.close()
    return {'checks': checks, 'passed_criteria': sum(checks.values()),
            'total_criteria': len(checks), 'core_accepted': accepted, 'error': error}


if __name__ == '__main__':
    result = {'free': evaluate('free'), 'spec': evaluate('spec'),
              'design': 'Sequential A then B; same agent; B saw A; n=1 per prompt; no timing inference.'}
    path = ROOT / 'evidence' / 'experiment.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
