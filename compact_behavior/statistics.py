"""Input-packet statistics, separate from merged durable behavior counts."""
from collections import Counter


class PacketStatistics:
    def __init__(self):
        self.values = dict(observed_public_api_requests=0, input_available=0,
                           output_available=0, input_eligible=0, output_eligible=0)
        self.quality = Counter()
        self.apis = Counter()

    def observe(self, body):
        if body is None:
            return
        self.values['observed_public_api_requests'] += 1
        self.quality.update(body['quality'])
        self.apis[body['api'] or '<conflict>'] += 1
        for direction in ('input', 'output'):
            self.values[direction+'_available'] += body['features'][direction] is not None
            self.values[direction+'_eligible'] += body['features'][direction+'_eligible']

    def result(self):
        return dict(self.values, quality=dict(self.quality), apis=dict(self.apis))
