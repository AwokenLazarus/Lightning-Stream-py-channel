"""SQLite WAL ledger: persist, reload, one row per channel."""
import os
import tempfile
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelParams
from xbt402.ledger import ChannelState, Ledger
from xbt402.tx import p2wpkh_spk


def params():
    return ChannelParams(
        payer_pub=ecc.pubkey(0x1111).hex(), payee_pub=ecc.pubkey(0x2222).hex(), expiry=2000,
        payer_spk=p2wpkh_spk(ecc.pubkey(0x1111)).hex(), payee_spk=p2wpkh_spk(ecc.pubkey(0x2222)).hex(),
        close_fee=600, funding_txid="ab" * 32, funding_vout=0, capacity=100_000)


class LedgerTest(unittest.TestCase):
    def test_roundtrip(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "led.json")
        led = Ledger(path)
        st = ChannelState(params(), best_cum=1500, best_sig="aa", seq=3, spent_msat=1500000)
        led.channels[st.params.channel_id] = st
        led.save()
        led2 = Ledger(path)
        self.assertEqual(len(led2.channels), 1)
        got = led2.channels[st.params.channel_id]
        self.assertEqual(got.best_cum, 1500)
        self.assertEqual(got.spent_msat, 1500000)
        self.assertEqual(got.params.capacity, 100_000)
        self.assertTrue(led2.path.endswith(".sqlite"))


if __name__ == "__main__":
    unittest.main()
