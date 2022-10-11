import axios from 'axios';

const APIURL = process.env.APIURL || 'http://localhost:3001';
export const TESTNET_APIURL = 'https://blockstream.info/liquidtestnet/api';

export async function faucet(address: string): Promise<any> {
  try {
    const resp = await axios.post(`${APIURL}/faucet`, { address });
    if (resp.status !== 200) {
      throw new Error('Invalid address');
    }
    const { txId } = resp.data;

    sleep(1000);
    let rr = { data: [] };
    const filter = (): any => rr.data.filter((x: any) => x.txid === txId);
    while (!rr.data.length || !filter().length) {
      sleep(1000);
      rr = await axios.get(`${APIURL}/address/${address}/utxo`);
    }

    return filter()[0];
  } catch (e) {
    const err = (e as any)
    const errMsg = err.response && err.response.data ? err.response.data : err.request.data
    console.error(errMsg);
    throw new Error(errMsg);
  }
}

export async function mint(address: string, quantity: number): Promise<any> {
  try {
    const resp = await axios.post(`${APIURL}/mint`, { address, quantity });
    if (resp.status !== 200) {
      throw new Error('Invalid request');
    }
    const { txId, asset } = resp.data;
    sleep(1000);
    let rr = { data: [] };
    const filter = (): any => rr.data.filter((x: any) => x.txid === txId);
    while (!rr.data.length || !filter().length) {
      sleep(1000);
      rr = await axios.get(`${APIURL}/address/${address}/utxo`);
    }

    return { asset, txid: filter()[0].txid, index: filter()[0].vout };
  } catch (e) {
    const err = (e as any)
    const errMsg = err.response && err.response.data ? err.response.data : err.request.data
    console.error(errMsg);
    throw new Error(errMsg);
  }
}

export async function fetchTx(txId: string): Promise<string> {
  try {
    const resp = await axios.get(`${APIURL}/tx/${txId}/hex`);
    return resp.data;
  } catch(e) {
    const err = (e as any)
    const errMsg = err.response && err.response.data ? err.response.data : err.request.data
    console.error(errMsg);
    throw new Error(errMsg);
  }
}

export async function fetchUtxo(txId: string): Promise<any> {
  try {
    const txHex = await fetchTx(txId);
    const resp = await axios.get(`${APIURL}/tx/${txId}`);
    return { txHex, ...resp.data };
  } catch(e) {
    const err = (e as any)
    const errMsg = err.response && err.response.data ? err.response.data : err.request.data
    console.error(errMsg);
    throw new Error(errMsg);
  }
}

export async function broadcast(
  txHex: string,
  verbose = true,
  api: string = APIURL,
): Promise<string> {
  try {
    const resp = await axios.get(`${api}/broadcast?tx=${txHex}`);
    return resp.data;
  } catch (e) {
    const err = (e as any)
    const errMsg = err.response && err.response.data ? err.response.data : err.request.data
    if (verbose) console.error(errMsg);
    throw new Error(errMsg);
  }
}

function sleep(ms: number): Promise<any> {
  return new Promise((res: any): any => setTimeout(res, ms));
}
