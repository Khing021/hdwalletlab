import { cryptoUtils, hexToBytes, bytesToHex } from './src/utils/crypto.js';

const keys = [
  {
    id: 1,
    priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    pub: "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40",
    addr: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
  }
];

const txData = {
  utxos: [
    {
      txid: "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
      vout: 0,
      value: 5000000000,
      addr: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
      priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  ],
  outputs: [
    { id: 1, addr: "", value: 0 }
  ]
};

try {
    const inputs = txData.utxos;
    const outputs = txData.outputs.filter(o => o.addr && o.value > 0);

    const version = "02000000";
    const locktime = "00000000";
    const hashType = "01000000";
    
    let outputsHex = "";
    outputs.forEach(out => {
      const valHex = cryptoUtils.toLittleEndian(out.value || 0, 8);
      const spk = getScriptPubKey(out.addr); // wait getScriptPubKey is missing here
      //...
    });
} catch(e) {
    console.error(e);
}
