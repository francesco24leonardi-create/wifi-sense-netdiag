"""Local site survey: measured samples at explicitly user-declared grid positions."""
from collections import deque
import math
import statistics
import time


class Survey:
    def __init__(self):
        self.samples = deque(maxlen=1000)
        self.points = []
        self.context = None

    def observe(self, sample, link, interface):
        context = (interface, link.get('bssid'), link.get('band'))
        if context != self.context:
            self.samples.clear()
            self.context = context
        value = sample.get('rssi_dbm')
        if link.get('eligible') and isinstance(value, (float, int)) and math.isfinite(value):
            self.samples.append((sample['timestamp'], value, sample.get('rtt_ms')))

    def capture(self, x, y, label, now=None):
        now = time.monotonic() if now is None else now
        if (isinstance(x, bool) or isinstance(y, bool) or not isinstance(x, (int, float))
                or not isinstance(y, (int, float)) or not math.isfinite(x) or not math.isfinite(y)
                or not 0 <= x <= 100 or not 0 <= y <= 100):
            raise ValueError('Coordinate locali in metri richieste, tra 0 e 100.')
        if len(self.points) >= 200:
            raise ValueError('Massimo 200 punti per rilievo; esportare e iniziare un nuovo rilievo.')
        rows = [s for s in self.samples if 0 <= now-s[0] <= 3]
        if len(rows) < 20 or now-rows[-1][0] > .5 or rows[-1][0]-rows[0][0] < 2:
            raise ValueError('Servono almeno 2 secondi di RSSI recente sul link 2,4 GHz; restare fermi nel punto scelto.')
        pings = [r[2] for r in rows if isinstance(r[2], (int, float)) and math.isfinite(r[2])]
        point = dict(id=len(self.points)+1, x_m=x, y_m=y, label=str(label or '')[:80],
            position_source='user_declared_floor_grid', position_accuracy_m=None,
            observed_at=time.time(), rssi_dbm=statistics.median(r[1] for r in rows),
            rssi_min=min(r[1] for r in rows), rssi_max=max(r[1] for r in rows),
            rtt_ms=statistics.median(pings) if pings else None, samples=len(rows),
            interface=self.context[0], bssid=self.context[1], band=self.context[2])
        self.points.append(point)
        return point

    def snapshot(self):
        return dict(points=list(self.points), note='Punti della pianta indicati dall’utente, non posizione GPS verificata. Nessuna interpolazione nelle aree non misurate.')
