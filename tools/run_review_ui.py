"""Run only the isolated review preview; no pipeline or collector is started."""
import argparse
import sys
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--demo',action='store_true');choice.add_argument('--config',type=Path)
    parser.add_argument('--publication');parser.add_argument('--session-file',type=Path);parser.add_argument('--access-token-file',type=Path)
    parser.add_argument('--host',choices=('127.0.0.1','localhost','::1'),default='127.0.0.1');parser.add_argument('--port',type=int,default=5020)
    args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('Use a port from 1024 to 65535.')
    from p24_foundation.review_ui import create_app,live_provider_factory
    if args.demo:app=create_app()
    else:
        if not all((args.publication,args.session_file,args.access_token_file)):parser.error('Live review needs --publication, --session-file and --access-token-file.')
        try:publication=str(uuid.UUID(args.publication))
        except ValueError:parser.error('Invalid publication reference.')
        app=create_app(live_provider_factory(args.config,args.session_file,args.access_token_file),initial_publication=publication,mode='live')
    app.run(host=args.host,port=args.port,debug=False,use_reloader=False)


if __name__=='__main__':main()
