"""Replay the finite synthetic workflow scenarios without a database."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.workflow_demo import workflow_examples


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=workflow_examples()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(synthetic=True,scenarios=len(result['scenarios']),database_modified=False)))
    return 0


if __name__=='__main__':raise SystemExit(main())
