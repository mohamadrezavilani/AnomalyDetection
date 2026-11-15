"""Window-local source fencing, with the conservative legacy fallback."""
from .snapshot import digest,require

CONTRACT='viewer-window-epochs-1'


def stamp(q,meta,window):
    epoch=meta.get('window_epoch_contract')
    if epoch:
        require(epoch['contract']==CONTRACT,'UNSUPPORTED_WINDOW_EPOCH_CONTRACT')
        rows=q('SELECT revision FROM public.viewer_window_epochs WHERE start_ns=%s',(window['start_ns'],),cap=1)
        revision=rows[0]['revision'] if rows else 0
        return digest([CONTRACT,window,revision,epoch['maintenance_epoch'],meta['catalog_fingerprint']])
    return digest([window,meta['generation'],meta['semantic_generation'],meta.get('catalog_fingerprint')])
