export declare const digestLength: number;
export declare const blockSize: number;
export declare class Hash {
    digestLength: number;
    blockSize: number;
    finished: boolean;
    state: Int32Array;
    private temp;
    private buffer;
    private bufferLength;
    private bytesHashed;
    constructor();
    reset(): this;
    clean(): void;
    update(data: Uint8Array, dataLength?: number): this;
    finish(out: Uint8Array): this;
    digest(): Uint8Array;
    _saveState(out: Uint32Array): void;
    _restoreState(from: Uint32Array, bytesHashed: number): void;
}
export declare function hash(data: Uint8Array): Uint8Array;
export declare function sha256Midstate(data: Buffer): Buffer;
