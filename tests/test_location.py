"""Provider observations are test fixtures; never loaded by the application."""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from location import LocationFix, LocationManager, InvalidFix, parse_gpsd_tpv, parse_windows_position, parse_geoclue_location

def fix(timestamp=1000):
    return LocationFix(40, 10, 15, timestamp, 'test provider', 'WIFI', 'test fixture')

class LocationTests(unittest.TestCase):
    def test_missing_invalid_accuracy_and_coordinates_rejected(self):
        for lat,accuracy in ((91,10),(True,10),(40,None),(40,0),(40,float('nan'))):
            with self.assertRaises(InvalidFix):
                LocationFix(lat,10,accuracy,1000,'test','UNKNOWN','test')

    def test_future_and_expired_measurements_rejected(self):
        manager=LocationManager(clock=lambda:1000,monotonic=lambda:10)
        for timestamp in (1001,939):
            with self.assertRaises(InvalidFix): manager._accept(fix(timestamp))
        self.assertIsNone(manager.origin())

    def test_fix_expires_even_after_wall_clock_adjustment(self):
        clocks=[1000,10]
        manager=LocationManager(clock=lambda:clocks[0],monotonic=lambda:clocks[1])
        manager._accept(fix())
        self.assertEqual(manager.origin()['accuracy_m'],15)
        clocks[1]=71
        self.assertIsNone(manager.origin())
        self.assertEqual(manager.snapshot()['status'],'stale')
        clocks[:]=[999,11]
        self.assertIsNone(manager.origin())

    def test_windows_manual_default_not_a_measurement(self):
        coordinate=SimpleNamespace(position_source=5, point=SimpleNamespace(position=SimpleNamespace(latitude=40,longitude=10)),
                                   accuracy=50,timestamp=datetime.fromtimestamp(1000,timezone.utc))
        with self.assertRaises(InvalidFix): parse_windows_position(SimpleNamespace(coordinate=coordinate))
        coordinate.position_source=2
        result=parse_windows_position(SimpleNamespace(coordinate=coordinate))
        self.assertEqual(result.position_source,'WIFI')
        self.assertEqual(result.accuracy_m,50)
        self.assertEqual(result.timestamp,1000)

    def test_gpsd_requires_fix_time_and_uncertainty(self):
        report=dict(class_='TPV')
        report={'class':'TPV','mode':3,'time':'2026-11-14T10:00:00Z','lat':40,'lon':10,'eph':4}
        self.assertEqual(parse_gpsd_tpv(report).accuracy_m,4)
        for key in ('eph','time'):
            invalid=dict(report);invalid.pop(key)
            with self.assertRaises(InvalidFix): parse_gpsd_tpv(invalid)

    def test_geoclue_does_not_invent_physical_source(self):
        result=parse_geoclue_location({'Timestamp':(1000,500000),'Latitude':40,'Longitude':10,'Accuracy':20})
        self.assertEqual(result.timestamp,1000.5)
        self.assertEqual(result.position_source,'UNKNOWN')

    def test_stop_cancels_provider_and_forgets_position(self):
        class Provider:
            closed=False
            async def start(self): pass
            async def read_fix(self): return fix()
            async def close(self): self.closed=True
        async def run():
            provider=Provider()
            manager=LocationManager(system_enabled=True,provider_factory=lambda _:provider,clock=lambda:1000)
            await manager.start('system')
            for _ in range(20):
                if manager.origin(): break
                await asyncio.sleep(.01)
            self.assertIsNotNone(manager.origin())
            await manager.stop()
            self.assertTrue(provider.closed)
            self.assertIsNone(manager.origin())
            self.assertIsNone(manager.snapshot()['source'])
        asyncio.run(run())

    def test_denied_provider_never_falls_back(self):
        class Denied:
            async def start(self): raise PermissionError('denied')
            async def close(self): pass
        async def run():
            manager=LocationManager(system_enabled=True,provider_factory=lambda _:Denied())
            await manager.start('system')
            await asyncio.sleep(.02)
            self.assertEqual(manager.snapshot()['status'],'unavailable')
            self.assertIsNone(manager.origin())
            await manager.stop()
        asyncio.run(run())

if __name__=='__main__': unittest.main()
