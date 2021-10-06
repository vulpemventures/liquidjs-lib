export interface Network {
    messagePrefix: string;
    bech32: string;
    blech32: string;
    bip32: Bip32;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
    assetHash: string;
    confidentialPrefix: number;
}
interface Bip32 {
    public: number;
    private: number;
}
export declare const liquid: Network;
export declare const regtest: Network;
export declare const testnet: Network;
export {};
